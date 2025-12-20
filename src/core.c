#include "common.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef SPF_PLATFORM_ESP32
    #include <Arduino.h>
    #define SPF_TIME_MS() millis()
#else
    #include <sys/time.h>
#endif

uint64_t spf_time_ms(void) {
#ifdef SPF_PLATFORM_ESP32
    return millis();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

uint64_t spf_time_sec(void) {
    return spf_time_ms() / 1000;
}

void spf_random_bytes(uint8_t* buf, size_t len) {
#ifdef SPF_PLATFORM_ESP32
    for (size_t i = 0; i < len; i++) buf[i] = random() & 0xFF;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, len);
        close(fd);
    } else {
        for (size_t i = 0; i < len; i++) buf[i] = rand() & 0xFF;
    }
#endif
}

uint32_t spf_hash_ip(const char* ip) {
    uint32_t h = 5381;
    while (*ip) h = ((h << 5) + h) + (uint8_t)*ip++;
    return h;
}

static const char* g_log_prefix[] = {"DBG", "INF", "WRN", "ERR", "SEC"};

void spf_log(spf_log_level_t level, const char* fmt, ...) {
    if (level < 0 || level > SPF_LOG_SECURITY) level = SPF_LOG_INFO;
    
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm* t = localtime_r(&now, &tm_buf);
    char ts[32];
    if (t) {
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    } else {
        snprintf(ts, sizeof(ts), "(time error)");
    }
    
    fprintf(stderr, "[%s] [%s] ", ts, g_log_prefix[level]);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void spf_init(spf_state_t* state) {
    memset(state, 0, sizeof(spf_state_t));
    state->running = true;
    state->next_conn_id = 1;
    state->start_time = spf_time_sec();
    state->authenticated = false;
    
    pthread_mutex_init(&state->lock, NULL);
    pthread_mutex_init(&state->stats_lock, NULL);
    pthread_mutex_init(&state->events.lock, NULL);
    pthread_rwlock_init(&state->blocklist.lock, NULL);
    
    strncpy(state->config.admin.bind_addr, "127.0.0.1", SPF_IP_MAX_LEN);
    state->config.admin.port = SPF_CTRL_PORT_DEFAULT;
    state->config.metrics.port = SPF_METRICS_PORT_DEFAULT;
    state->config.log_level = SPF_LOG_INFO;
    
    spf_log(SPF_LOG_INFO, "spf v%s init done", SPF_VERSION);
}

void spf_shutdown(spf_state_t* state) {
    state->running = false;
    
    pthread_mutex_destroy(&state->lock);
    pthread_mutex_destroy(&state->stats_lock);
    pthread_mutex_destroy(&state->events.lock);
    pthread_rwlock_destroy(&state->blocklist.lock);
    
    if (state->blocklist.ips) {
        free(state->blocklist.ips);
        state->blocklist.ips = NULL;
    }
    
    spf_log(SPF_LOG_INFO, "shutdown complete");
}

int spf_add_rule(spf_state_t* state, const spf_rule_t* rule) {
    pthread_mutex_lock(&state->lock);
    
    if (state->rule_count >= SPF_MAX_RULES) {
        pthread_mutex_unlock(&state->lock);
        return -1;
    }
    
    int idx = -1;
    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (!state->rules[i].active) {
            idx = i;
            break;
        }
        if (state->rules[i].id == rule->id) {
            idx = i;
            state->rule_count--;
            break;
        }
    }
    
    if (idx < 0) {
        pthread_mutex_unlock(&state->lock);
        return -1;
    }
    
    memcpy(&state->rules[idx], rule, sizeof(spf_rule_t));
    pthread_mutex_init(&state->rules[idx].lock, NULL);
    
    for (int i = 0; i < state->rules[idx].backend_count; i++) {
        pthread_mutex_init(&state->rules[idx].backends[i].lock, NULL);
    }
    
    state->rules[idx].active = true;
    state->rule_count++;
    
    pthread_mutex_unlock(&state->lock);
    spf_log(SPF_LOG_INFO, "rule %u added: port %u -> %u backends", 
            rule->id, rule->listen_port, rule->backend_count);
    return 0;
}

int spf_del_rule(spf_state_t* state, uint32_t rule_id) {
    pthread_mutex_lock(&state->lock);
    
    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (state->rules[i].active && state->rules[i].id == rule_id) {
            state->rules[i].active = false;
            state->rules[i].enabled = false;
            state->rule_count--;
            pthread_mutex_unlock(&state->lock);
            spf_log(SPF_LOG_INFO, "rule %u deleted", rule_id);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&state->lock);
    return -1;
}

spf_rule_t* spf_get_rule(spf_state_t* state, uint32_t rule_id) {
    pthread_mutex_lock(&state->lock);
    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (state->rules[i].active && state->rules[i].id == rule_id) {
            pthread_mutex_unlock(&state->lock);
            return &state->rules[i];
        }
    }
    pthread_mutex_unlock(&state->lock);
    return NULL;
}

static spf_tracker_t* find_tracker(spf_state_t* state, const char* ip, int* empty_slot) {
    *empty_slot = -1;
    for (int i = 0; i < SPF_MAX_IP_TRACKERS; i++) {
        if (state->trackers[i].ip[0] == '\0') {
            if (*empty_slot < 0) *empty_slot = i;
            continue;
        }
        if (strcmp(state->trackers[i].ip, ip) == 0) {
            return &state->trackers[i];
        }
    }
    return NULL;
}

bool spf_is_blocked(spf_state_t* state, const char* ip) {
    pthread_mutex_lock(&state->lock);
    
    if (spf_blocklist_contains(&state->blocklist, ip)) {
        pthread_mutex_unlock(&state->lock);
        return true;
    }
    
    uint64_t now = spf_time_sec();
    int slot;
    spf_tracker_t* t = find_tracker(state, ip, &slot);
    
    if (!t) {
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    
    if (t->blocked) {
        if (t->block_until > now) {
            pthread_mutex_unlock(&state->lock);
            return true;
        }
        t->blocked = false;
        t->count = 0;
    }
    
    pthread_mutex_unlock(&state->lock);
    return false;
}

bool spf_register_attempt(spf_state_t* state, const char* ip) {
    pthread_mutex_lock(&state->lock);
    
    uint64_t now = spf_time_sec();
    int empty_slot;
    spf_tracker_t* t = find_tracker(state, ip, &empty_slot);
    
    if (!t) {
        if (empty_slot < 0) {
            pthread_mutex_unlock(&state->lock);
            return true;
        }
        t = &state->trackers[empty_slot];
        strncpy(t->ip, ip, SPF_IP_MAX_LEN - 1);
        t->count = 1;
        t->first_ts = now;
        t->last_ts = now;
        t->strikes = 0;
        t->blocked = false;
        pthread_mutex_unlock(&state->lock);
        return true;
    }
    
    t->last_ts = now;
    t->conns_total++;
    
    if (now - t->first_ts > SPF_SCAN_WINDOW_SEC) {
        t->count = 1;
        t->first_ts = now;
        pthread_mutex_unlock(&state->lock);
        return true;
    }
    
    t->count++;
    
    if (t->count > SPF_SCAN_THRESHOLD) {
        t->strikes++;
        
        uint64_t dur;
        if (t->strikes == 1) dur = SPF_BLOCK_FIRST_SEC;
        else if (t->strikes == 2) dur = SPF_BLOCK_SECOND_SEC;
        else dur = SPF_BLOCK_PERMA_SEC;
        
        t->block_until = now + dur;
        t->blocked = true;
        t->count = 0;
        
        state->blocked_count++;
        spf_event_push(state, SPF_EVENT_BLOCKED, ip, 0, 0, "rate limit exceeded");
        
        pthread_mutex_unlock(&state->lock);
        spf_log(SPF_LOG_SECURITY, "blocked %s for %lus (strike %u)", ip, dur, t->strikes);
        return false;
    }
    
    pthread_mutex_unlock(&state->lock);
    return true;
}

void spf_block_ip(spf_state_t* state, const char* ip, uint64_t duration_sec) {
    pthread_mutex_lock(&state->lock);
    
    uint64_t now = spf_time_sec();
    int empty_slot;
    spf_tracker_t* t = find_tracker(state, ip, &empty_slot);
    
    if (!t && empty_slot >= 0) {
        t = &state->trackers[empty_slot];
        strncpy(t->ip, ip, SPF_IP_MAX_LEN - 1);
        t->first_ts = now;
    }
    
    if (t) {
        t->blocked = true;
        t->block_until = duration_sec ? now + duration_sec : UINT64_MAX;
        state->blocked_count++;
        spf_event_push(state, SPF_EVENT_BLOCKED, ip, 0, 0, "manual block");
    }
    
    pthread_mutex_unlock(&state->lock);
    spf_log(SPF_LOG_SECURITY, "manually blocked %s", ip);
}

void spf_unblock_ip(spf_state_t* state, const char* ip) {
    pthread_mutex_lock(&state->lock);
    
    int slot;
    spf_tracker_t* t = find_tracker(state, ip, &slot);
    
    if (t) {
        t->blocked = false;
        t->block_until = 0;
        t->strikes = 0;
        t->count = 0;
    }
    
    pthread_mutex_unlock(&state->lock);
    spf_log(SPF_LOG_INFO, "unblocked %s", ip);
}

void spf_bucket_init(spf_bucket_t* tb, uint64_t rate, double burst) {
    tb->rate = rate;
    tb->capacity = (uint64_t)(rate * burst);
    tb->tokens = (double)tb->capacity;
    tb->last_refill = spf_time_ms();
}

uint64_t spf_bucket_consume(spf_bucket_t* tb, uint64_t want) {
    uint64_t now = spf_time_ms();
    
    // Handle time wraparound
    if (now >= tb->last_refill) {
        double dt = (now - tb->last_refill) / 1000.0;
        tb->tokens += tb->rate * dt;
        if (tb->tokens > (double)tb->capacity) {
            tb->tokens = (double)tb->capacity;
        }
        tb->last_refill = now;
    } else {
        // Time wrapped around, reset
        tb->last_refill = now;
    }
    
    if (tb->tokens >= (double)want) {
        tb->tokens -= (double)want;
        return want;
    }
    
    uint64_t allowed = (uint64_t)tb->tokens;
    tb->tokens = 0.0;
    return allowed;
}

void spf_event_push(spf_state_t* state, spf_event_type_t type, const char* ip, 
                    uint16_t port, uint32_t rule_id, const char* details) {
    bool should_alert = false;
    char webhook_url[256] = {0};
    spf_event_t event_copy;
    
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
    
    // Copy for webhook before unlock
    if (state->config.security.webhook_url[0] && type >= SPF_EVENT_BLOCKED) {
        should_alert = true;
        strncpy(webhook_url, state->config.security.webhook_url, sizeof(webhook_url) - 1);
        memcpy(&event_copy, e, sizeof(event_copy));
    }
    
    pthread_mutex_unlock(&state->events.lock);
    
    if (should_alert) {
        spf_webhook_alert(webhook_url, &event_copy);
    }
}

void spf_event_get_recent(spf_state_t* state, spf_event_t* out, uint32_t count, uint32_t* actual) {
    pthread_mutex_lock(&state->events.lock);
    
    uint32_t n = count < state->events.count ? count : state->events.count;
    *actual = n;
    
    for (uint32_t i = 0; i < n; i++) {
        uint32_t idx = (state->events.head - 1 - i + SPF_MAX_EVENTS) % SPF_MAX_EVENTS;
        memcpy(&out[i], &state->events.events[idx], sizeof(spf_event_t));
    }
    
    pthread_mutex_unlock(&state->events.lock);
}

bool spf_verify_token(spf_state_t* state, const char* token) {
    if (state->config.admin.token[0] == '\0') return true;
    
    size_t len = strlen(state->config.admin.token);
    size_t tlen = strlen(token);
    
    if (len != tlen) return false;
    
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= state->config.admin.token[i] ^ token[i];
    }
    return diff == 0;
}

void spf_generate_token(char* buf, size_t len) {
    if (len < 2) {
        if (len == 1) buf[0] = '\0';
        return;
    }
    
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint8_t rnd[128];
    size_t token_len = len - 1;
    if (token_len > 127) token_len = 127;
    
    spf_random_bytes(rnd, token_len);
    
    for (size_t i = 0; i < token_len; i++) {
        buf[i] = charset[rnd[i] % (sizeof(charset) - 1)];
    }
    buf[token_len] = '\0';
}

int spf_lb_select_backend(spf_rule_t* rule, const char* client_ip) {
    pthread_mutex_lock(&rule->lock);
    
    if (rule->backend_count == 0) {
        pthread_mutex_unlock(&rule->lock);
        return -1;
    }
    
    int selected = -1;
    
    switch (rule->lb_algo) {
        case SPF_LB_ROUNDROBIN: {
            for (int tries = 0; tries < rule->backend_count; tries++) {
                int idx = rule->rr_index % rule->backend_count;
                rule->rr_index++;
                if (rule->backends[idx].state == SPF_BACKEND_UP) {
                    selected = idx;
                    break;
                }
            }
            break;
        }
        
        case SPF_LB_LEASTCONN: {
            uint32_t min_conns = UINT32_MAX;
            for (int i = 0; i < rule->backend_count; i++) {
                if (rule->backends[i].state == SPF_BACKEND_UP &&
                    rule->backends[i].active_conns < min_conns) {
                    min_conns = rule->backends[i].active_conns;
                    selected = i;
                }
            }
            break;
        }
        
        case SPF_LB_IPHASH: {
            uint32_t h = spf_hash_ip(client_ip);
            int start = h % rule->backend_count;
            for (int i = 0; i < rule->backend_count; i++) {
                int idx = (start + i) % rule->backend_count;
                if (rule->backends[idx].state == SPF_BACKEND_UP) {
                    selected = idx;
                    break;
                }
            }
            break;
        }
        
        case SPF_LB_WEIGHTED: {
            uint32_t total = 0;
            for (int i = 0; i < rule->backend_count; i++) {
                if (rule->backends[i].state == SPF_BACKEND_UP) {
                    total += rule->backends[i].weight;
                }
            }
            if (total > 0) {
                uint8_t rnd[4];
                spf_random_bytes(rnd, 4);
                uint32_t r = (*(uint32_t*)rnd) % total;
                uint32_t acc = 0;
                for (int i = 0; i < rule->backend_count; i++) {
                    if (rule->backends[i].state == SPF_BACKEND_UP) {
                        acc += rule->backends[i].weight;
                        if (r < acc) {
                            selected = i;
                            break;
                        }
                    }
                }
            }
            break;
        }
        
        case SPF_LB_RANDOM: {
            int up_count = 0;
            int up_idx[SPF_MAX_BACKENDS];
            for (int i = 0; i < rule->backend_count; i++) {
                if (rule->backends[i].state == SPF_BACKEND_UP) {
                    up_idx[up_count++] = i;
                }
            }
            if (up_count > 0) {
                uint8_t rnd;
                spf_random_bytes(&rnd, 1);
                selected = up_idx[rnd % up_count];
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&rule->lock);
    return selected;
}

void spf_lb_conn_start(spf_rule_t* rule, uint8_t backend_idx) {
    if (backend_idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[backend_idx].lock);
    rule->backends[backend_idx].active_conns++;
    rule->backends[backend_idx].total_conns++;
    pthread_mutex_unlock(&rule->backends[backend_idx].lock);
}

void spf_lb_conn_end(spf_rule_t* rule, uint8_t backend_idx) {
    if (backend_idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[backend_idx].lock);
    if (rule->backends[backend_idx].active_conns > 0) {
        rule->backends[backend_idx].active_conns--;
    }
    pthread_mutex_unlock(&rule->backends[backend_idx].lock);
}

bool spf_blocklist_contains(spf_blocklist_t* bl, const char* ip) {
    if (!bl->ips || bl->count == 0) return false;
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return false;
    
    uint32_t ip_val = ntohl(addr.s_addr);
    
    pthread_rwlock_rdlock(&bl->lock);
    
    if (bl->count == 0) {
        pthread_rwlock_unlock(&bl->lock);
        return false;
    }
    
    int lo = 0, hi = (int)bl->count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (bl->ips[mid] == ip_val) {
            pthread_rwlock_unlock(&bl->lock);
            return true;
        }
        if (bl->ips[mid] < ip_val) lo = mid + 1;
        else hi = mid - 1;
    }
    
    pthread_rwlock_unlock(&bl->lock);
    return false;
}

int spf_webhook_alert(const char* url, const spf_event_t* event) {
    (void)url;
    (void)event;
    return 0;
}

bool spf_geoip_is_blocked(spf_state_t* state, const char* ip) {
    (void)state;
    (void)ip;
    return false;
}

int spf_geoip_init(const char* db_path) {
    (void)db_path;
    return 0;
}

void spf_geoip_cleanup(void) {
}

int spf_blocklist_load(spf_blocklist_t* bl, const char* url) {
    (void)bl;
    (void)url;
    return 0;
}
