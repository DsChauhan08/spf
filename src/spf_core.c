#include "spf_common.h"
#include <string.h>
#include <time.h>

#ifdef SPF_PLATFORM_ESP32
    #include <Arduino.h>
    #define SPF_MILLIS() millis()
#else
    #include <sys/time.h>
    static uint64_t SPF_MILLIS() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
    }
#endif

void spf_init(spf_state_t* state) {
    memset(state, 0, sizeof(spf_state_t));
    state->running = true;
    state->next_conn_id = 1;

    for (uint32_t i = 0; i < SPF_MAX_IP_TRACKERS; i++) {
        state->trackers[i].ip[0] = '\0';
        state->trackers[i].blocked = false;
    }
}

int spf_add_rule(spf_state_t* state, const spf_rule_t* rule) {
    if (state->rule_count >= SPF_MAX_RULES) {
        return -1; // No space
    }
    
    // Finding any kind of empty slot or matching rule_id
    uint32_t idx = state->rule_count;
    for (uint32_t i = 0; i < SPF_MAX_RULES; i++) {
        if (state->rules[i].listen_port == 0 || 
            state->rules[i].rule_id == rule->rule_id) {
            idx = i;
            break;
        }
    }
    
    memcpy(&state->rules[idx], rule, sizeof(spf_rule_t));
    
    if (idx == state->rule_count) {
        state->rule_count++;
    }
    
    return 0;
}

// Checking if this ip address is blocked or not
bool spf_is_blocked(spf_state_t* state, const char* ip) {
    uint64_t now = SPF_MILLIS() / 1000;
    
    for (uint32_t i = 0; i < SPF_MAX_IP_TRACKERS; i++) {
        if (state->trackers[i].ip[0] != '\0' && 
            strcmp(state->trackers[i].ip, ip) == 0) {
            if (state->trackers[i].blocked && state->trackers[i].block_until > now) {
                return true;
            }
            // Unblock if time expired
            if (state->trackers[i].blocked && state->trackers[i].block_until <= now) {
                state->trackers[i].blocked = false;
                state->trackers[i].count = 0;
                state->trackers[i].strikes = 0;
            }
            return false;
        }
    }
    
    return false;
}

bool spf_register_attempt(spf_state_t* state, const char* ip) {
    uint64_t now = SPF_MILLIS() / 1000;
    
    // trying to find existing tracker or empty slot
    int32_t idx = -1;
    int32_t empty_idx = -1;
    
    for (uint32_t i = 0; i < SPF_MAX_IP_TRACKERS; i++) {
        if (state->trackers[i].ip[0] == '\0' && empty_idx == -1) {
            empty_idx = i;
        }
        if (strcmp(state->trackers[i].ip, ip) == 0) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        if (empty_idx == -1) {
            return true;
        }
        idx = empty_idx;
        strncpy(state->trackers[idx].ip, ip, sizeof(state->trackers[idx].ip) - 1);
        state->trackers[idx].count = 1;
        state->trackers[idx].first_timestamp = now;
        state->trackers[idx].strikes = 0;
        state->trackers[idx].blocked = false;
        return true;
    }
    
    spf_tracker_t* tracker = &state->trackers[idx];
    if (now - tracker->first_timestamp > SPF_SCAN_WINDOW_SEC) {
        tracker->count = 1;
        tracker->first_timestamp = now;
        return true;
    }
    
    tracker->count++;
    if (tracker->count > SPF_SCAN_THRESHOLD) {
        tracker->strikes++;
        
        uint64_t block_duration;
        if (tracker->strikes == 1) {
            block_duration = SPF_BLOCK_FIRST_SEC;
        } else if (tracker->strikes == 2) {
            block_duration = 3600;
        } else {
            block_duration = 86400;
        }
        
        tracker->block_until = now + block_duration;
        tracker->blocked = true;
        tracker->count = 0;
        
        return false;
    }
    
    return true;
}

void spf_token_bucket_init(spf_token_bucket_t* tb, uint64_t rate, double burst) {
    tb->rate = rate;
    tb->capacity = (uint64_t)(rate * burst);
    tb->tokens = (double)tb->capacity;
    tb->last_refill = SPF_MILLIS();
}

uint64_t spf_token_bucket_consume(spf_token_bucket_t* tb, uint64_t want) {
    uint64_t now = SPF_MILLIS();
    double dt = (now - tb->last_refill) / 1000.0;
    
    if (dt > 0.0) {
        tb->tokens += tb->rate * dt;
        if (tb->tokens > (double)tb->capacity) {
            tb->tokens = (double)tb->capacity;
        }
        tb->last_refill = now;
    }
    
    if (tb->tokens >= (double)want) {
        tb->tokens -= (double)want;
        return want;
    } else {
        uint64_t allowed = (uint64_t)tb->tokens;
        tb->tokens = 0.0;
        return allowed;
    }
}
