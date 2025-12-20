#include "common.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#define HEALTH_CHECK_TIMEOUT_SEC 2
#define HEALTH_FAIL_THRESHOLD 3

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int health_tcp_check(const char* host, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    set_nonblocking(fd);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    
    int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    
    // Check FD_SETSIZE limit
    if (fd >= FD_SETSIZE) {
        close(fd);
        return -1;
    }
    
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    ret = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
        close(fd);
        return -1;
    }
    
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    close(fd);
    
    return err == 0 ? 0 : -1;
}

void health_check_backend(spf_state_t* state, spf_rule_t* rule, uint8_t idx) {
    if (idx >= rule->backend_count) return;
    
    spf_backend_t* b = &rule->backends[idx];
    
    if (b->state == SPF_BACKEND_DRAIN) return;
    
    int ok = health_tcp_check(b->host, b->port, SPF_HEALTH_TIMEOUT_MS);
    
    pthread_mutex_lock(&b->lock);
    b->last_health_check = spf_time_sec();
    
    if (ok == 0) {
        if (b->state == SPF_BACKEND_DOWN) {
            b->state = SPF_BACKEND_UP;
            b->health_fails = 0;
            pthread_mutex_unlock(&b->lock);
            
            spf_event_push(state, SPF_EVENT_HEALTH_UP, b->host, b->port, rule->id, "recovered");
            spf_log(SPF_LOG_INFO, "health: %s:%u UP", b->host, b->port);
            return;
        }
        b->health_fails = 0;
    } else {
        b->health_fails++;
        uint8_t fails = b->health_fails;
        if (fails >= HEALTH_FAIL_THRESHOLD && b->state == SPF_BACKEND_UP) {
            b->state = SPF_BACKEND_DOWN;
            pthread_mutex_unlock(&b->lock);
            
            spf_event_push(state, SPF_EVENT_HEALTH_DOWN, b->host, b->port, rule->id, "failed");
            spf_log(SPF_LOG_WARN, "health: %s:%u DOWN (fails=%u)", b->host, b->port, fails);
            return;
        }
    }
    
    pthread_mutex_unlock(&b->lock);
}

void* health_worker(void* arg) {
    spf_rule_t* rule = (spf_rule_t*)arg;
    
    spf_state_t* state = NULL;
    extern spf_state_t g_state;
    state = &g_state;
    
    spf_log(SPF_LOG_INFO, "health: worker started for rule %u", rule->id);
    
    while (state->running && rule->active) {
        for (int i = 0; i < rule->backend_count; i++) {
            health_check_backend(state, rule, i);
        }
        
        for (int i = 0; i < SPF_HEALTH_INTERVAL_MS / 100 && state->running; i++) {
            usleep(100000);
        }
    }
    
    spf_log(SPF_LOG_INFO, "health: worker stopped for rule %u", rule->id);
    return NULL;
}

int health_start(spf_rule_t* rule) {
    return pthread_create(&rule->health_thread, NULL, health_worker, rule);
}

void health_stop(spf_rule_t* rule) {
    pthread_join(rule->health_thread, NULL);
}

void health_force_check(spf_state_t* state, spf_rule_t* rule) {
    for (int i = 0; i < rule->backend_count; i++) {
        health_check_backend(state, rule, i);
    }
}

void health_mark_down(spf_rule_t* rule, uint8_t idx) {
    if (idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].state = SPF_BACKEND_DOWN;
    pthread_mutex_unlock(&rule->backends[idx].lock);
}

void health_mark_up(spf_rule_t* rule, uint8_t idx) {
    if (idx >= rule->backend_count) return;
    pthread_mutex_lock(&rule->backends[idx].lock);
    rule->backends[idx].state = SPF_BACKEND_UP;
    rule->backends[idx].health_fails = 0;
    pthread_mutex_unlock(&rule->backends[idx].lock);
}

int health_get_status(spf_rule_t* rule, char* buf, size_t len) {
    int written = 0;
    
    for (int i = 0; i < rule->backend_count && written < (int)len - 64; i++) {
        spf_backend_t* b = &rule->backends[i];
        const char* st = b->state == SPF_BACKEND_UP ? "UP" : 
                         b->state == SPF_BACKEND_DOWN ? "DOWN" : "DRAIN";
        written += snprintf(buf + written, len - written,
            "%s:%u %s conns=%u fails=%u\n",
            b->host, b->port, st, b->active_conns, b->health_fails);
    }
    
    return written;
}
