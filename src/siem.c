#include "common.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static void siem_alert(spf_state_t* state, const spf_event_t* e);
static const char* event_names[] = {
    "CONN_OPEN",
    "CONN_CLOSE", 
    "AUTH_FAIL",
    "BLOCKED",
    "RATE_LIMITED",
    "HEALTH_DOWN",
    "HEALTH_UP",
    "GEOBLOCK",
    "THREAT_MATCH",
    "ANOMALY",
    "DDOS"
};

void siem_init(spf_state_t* state) {
    memset(&state->events, 0, sizeof(state->events));
    pthread_mutex_init(&state->events.lock, NULL);
    spf_log(SPF_LOG_INFO, "siem: initialized");
}

void siem_push(spf_state_t* state, spf_event_type_t type, const char* ip, 
               uint16_t port, uint32_t rule_id, const char* details) {
    spf_event_t event_copy;
    bool should_alert = false;
    
    pthread_mutex_lock(&state->events.lock);
    
    spf_event_t* e = &state->events.events[state->events.head];
    memset(e, 0, sizeof(spf_event_t));
    
    e->type = type;
    e->timestamp = spf_time_sec();
    if (ip) {
        strncpy(e->src_ip, ip, SPF_IP_MAX_LEN - 1);
        e->src_ip[SPF_IP_MAX_LEN - 1] = '\0';
    }
    e->src_port = port;
    e->rule_id = rule_id;
    if (details) {
        strncpy(e->details, details, sizeof(e->details) - 1);
        e->details[sizeof(e->details) - 1] = '\0';
    }
    
    state->events.head = (state->events.head + 1) % SPF_MAX_EVENTS;
    if (state->events.count < SPF_MAX_EVENTS) {
        state->events.count++;
    } else {
        state->events.tail = (state->events.tail + 1) % SPF_MAX_EVENTS;
    }
    
    // Copy event before unlock for alert
    if (type >= SPF_EVENT_BLOCKED) {
        memcpy(&event_copy, e, sizeof(event_copy));
        should_alert = true;
    }
    
    pthread_mutex_unlock(&state->events.lock);
    
    if (should_alert) {
        siem_alert(state, &event_copy);
    }
}

void siem_get_recent(spf_state_t* state, spf_event_t* out, uint32_t count, uint32_t* actual) {
    pthread_mutex_lock(&state->events.lock);
    
    uint32_t n = count < state->events.count ? count : state->events.count;
    *actual = n;
    
    for (uint32_t i = 0; i < n; i++) {
        uint32_t idx = (state->events.head - 1 - i + SPF_MAX_EVENTS) % SPF_MAX_EVENTS;
        memcpy(&out[i], &state->events.events[idx], sizeof(spf_event_t));
    }
    
    pthread_mutex_unlock(&state->events.lock);
}

int siem_format_json(const spf_event_t* e, char* buf, size_t len) {
    return snprintf(buf, len,
        "{\"ts\":%lu,\"type\":\"%s\",\"src_ip\":\"%s\",\"src_port\":%u,"
        "\"rule_id\":%u,\"details\":\"%s\"}",
        e->timestamp,
        e->type < sizeof(event_names)/sizeof(event_names[0]) ? event_names[e->type] : "UNKNOWN",
        e->src_ip,
        e->src_port,
        e->rule_id,
        e->details);
}

int siem_format_syslog(const spf_event_t* e, char* buf, size_t len) {
    time_t t = e->timestamp;
    struct tm tm_buf;
    struct tm* tm = localtime_r(&t, &tm_buf);
    char ts[32];
    
    if (tm) {
        strftime(ts, sizeof(ts), "%b %d %H:%M:%S", tm);
    } else {
        snprintf(ts, sizeof(ts), "(time error)");
    }
    
    return snprintf(buf, len,
        "<%d>%s spf[%d]: %s src=%s:%u rule=%u %s",
        (13 << 3) | 6,
        ts,
        getpid(),
        e->type < sizeof(event_names)/sizeof(event_names[0]) ? event_names[e->type] : "UNKNOWN",
        e->src_ip,
        e->src_port,
        e->rule_id,
        e->details);
}

static void siem_alert(spf_state_t* state, const spf_event_t* e) {
    if (state->config.security.webhook_url[0] == '\0') return;
    
    char json[512];
    siem_format_json(e, json, sizeof(json));
    
    spf_log(SPF_LOG_SECURITY, "alert: %s", json);
}

int siem_export_logs(spf_state_t* state, int fd, uint32_t count) {
    spf_event_t events[100];
    uint32_t actual;
    
    if (count > 100) count = 100;
    siem_get_recent(state, events, count, &actual);
    
    char line[512];
    for (uint32_t i = 0; i < actual; i++) {
        int len = siem_format_json(&events[i], line, sizeof(line) - 1);
        line[len++] = '\n';
        ssize_t wrote = write(fd, line, len);
        if (wrote != (ssize_t)len) {
            return -1;
        }
    }
    
    return actual;
}

bool siem_detect_scan(spf_state_t* state, const char* ip) {
    spf_tracker_t* t = NULL;
    
    pthread_mutex_lock(&state->lock);
    for (int i = 0; i < SPF_MAX_IP_TRACKERS; i++) {
        if (strcmp(state->trackers[i].ip, ip) == 0) {
            t = &state->trackers[i];
            break;
        }
    }
    pthread_mutex_unlock(&state->lock);
    
    if (!t) return false;
    
    uint64_t now = spf_time_sec();
    if (now - t->first_ts < SPF_SCAN_WINDOW_SEC && t->count > SPF_SCAN_THRESHOLD) {
        return true;
    }
    return false;
}

bool siem_detect_brute(spf_state_t* state, const char* ip, uint32_t threshold) {
    (void)threshold;
    return siem_detect_scan(state, ip);
}

void siem_cleanup(spf_state_t* state) {
    pthread_mutex_destroy(&state->events.lock);
}
