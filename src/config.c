#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char* trim(char* s) {
    while (isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    if (len == 0) return s;
    char* e = s + len - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static int parse_backend(const char* str, spf_backend_t* b) {
    char host[SPF_IP_MAX_LEN];
    uint16_t port;
    uint16_t weight = 1;
    
    if (sscanf(str, "%45[^:]:%hu:%hu", host, &port, &weight) >= 2) {
        strncpy(b->host, host, SPF_IP_MAX_LEN - 1);
        b->host[SPF_IP_MAX_LEN - 1] = '\0';
        b->port = port;
        b->weight = weight ? weight : 1;
        b->state = SPF_BACKEND_UP;
        return 0;
    }
    return -1;
}

int spf_load_config(spf_state_t* state, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        spf_log(SPF_LOG_ERROR, "config: cannot open %s", path);
        return -1;
    }
    
    strncpy(state->config.config_path, path, SPF_PATH_MAX - 1);
    state->config.config_path[SPF_PATH_MAX - 1] = '\0';
    
    char line[512];
    char section[32] = "";
    spf_rule_t* current_rule = NULL;
    
    while (fgets(line, sizeof(line), f)) {
        char* s = trim(line);
        if (*s == '\0' || *s == '#') continue;
        
        if (*s == '[') {
            char* e = strchr(s, ']');
            if (e) {
                *e = '\0';
                strncpy(section, s + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = '\0';
            }
            continue;
        }
        
        char* eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char* key = trim(s);
        char* val = trim(eq + 1);
        
        spf_log(SPF_LOG_DEBUG, "config: section=[%s] key=[%s] val=[%s]", section, key, val);
        
        if (strcmp(section, "admin") == 0) {
            if (strcmp(key, "bind") == 0) {
                strncpy(state->config.admin.bind_addr, val, SPF_IP_MAX_LEN - 1);
                state->config.admin.bind_addr[SPF_IP_MAX_LEN - 1] = '\0';
            } else if (strcmp(key, "port") == 0) {
                state->config.admin.port = atoi(val);
            } else if (strcmp(key, "token") == 0) {
                strncpy(state->config.admin.token, val, SPF_TOKEN_MAX - 1);
            } else if (strcmp(key, "cert") == 0) {
                strncpy(state->config.admin.cert_path, val, SPF_PATH_MAX - 1);
            } else if (strcmp(key, "key") == 0) {
                strncpy(state->config.admin.key_path, val, SPF_PATH_MAX - 1);
            } else if (strcmp(key, "tls") == 0) {
                state->config.admin.tls_enabled = strcmp(val, "true") == 0;
            }
        }
        else if (strcmp(section, "security") == 0) {
            if (strcmp(key, "enabled") == 0) {
                state->config.security.enabled = strcmp(val, "true") == 0;
            } else if (strcmp(key, "rate_per_ip") == 0) {
                state->config.security.rate_per_ip = atoi(val);
            } else if (strcmp(key, "rate_global") == 0) {
                state->config.security.rate_global = atoi(val);
            } else if (strcmp(key, "webhook") == 0) {
                strncpy(state->config.security.webhook_url, val, sizeof(state->config.security.webhook_url) - 1);
            } else if (strcmp(key, "ddos") == 0) {
                state->config.security.ddos_protection = strcmp(val, "true") == 0;
            } else if (strcmp(key, "proxy_proto") == 0) {
                state->config.security.proxy_proto = strcmp(val, "true") == 0;
            }
        }
        else if (strcmp(section, "metrics") == 0) {
            if (strcmp(key, "enabled") == 0) {
                state->config.metrics.enabled = strcmp(val, "true") == 0;
            } else if (strcmp(key, "port") == 0) {
                state->config.metrics.port = atoi(val);
            }
        }
        else if (strncmp(section, "rule.", 5) == 0) {
            if (strcmp(key, "listen") == 0) {
                spf_rule_t rule;
                memset(&rule, 0, sizeof(rule));
                uint8_t rnd[4];
                spf_random_bytes(rnd, 4);
                uint32_t r;
                memcpy(&r, rnd, 4);
                rule.id = r % 90000 + 10000;
                rule.listen_port = atoi(val);
                rule.enabled = true;
                rule.active = true;
                rule.rate_bps = 100 * 1024 * 1024;
                rule.max_conns = 512; // default per-rule cap tuned for mid-tier host
                rule.accept_rate = state->config.security.rate_global ? state->config.security.rate_global : 200;
                if (rule.accept_rate) {
                    spf_bucket_init(&rule.accept_bucket, rule.accept_rate, 2.0);
                }
                
                pthread_mutex_lock(&state->lock);
                for (int i = 0; i < SPF_MAX_RULES; i++) {
                    if (!state->rules[i].active) {
                        // Safe copy avoiding mutex overwrite (similar to core.c fix)
                        if (state->rules[i].active || state->rules[i].id != 0) {
                            pthread_mutex_destroy(&state->rules[i].lock);
                        }
                        memcpy(&state->rules[i], &rule, sizeof(rule));
                        pthread_mutex_init(&state->rules[i].lock, NULL);
                        current_rule = &state->rules[i];
                        state->rule_count++;
                        break;
                    }
                }
                pthread_mutex_unlock(&state->lock);
            }
            else if (strcmp(key, "backend") == 0 && current_rule) {
                if (current_rule->backend_count < SPF_MAX_BACKENDS) {
                    parse_backend(val, &current_rule->backends[current_rule->backend_count]);
                    pthread_mutex_init(&current_rule->backends[current_rule->backend_count].lock, NULL);
                    current_rule->backend_count++;
                }
            }
            else if (strcmp(key, "lb") == 0 && current_rule) {
                if (strcmp(val, "rr") == 0) current_rule->lb_algo = SPF_LB_ROUNDROBIN;
                else if (strcmp(val, "lc") == 0) current_rule->lb_algo = SPF_LB_LEASTCONN;
                else if (strcmp(val, "ip") == 0) current_rule->lb_algo = SPF_LB_IPHASH;
                else if (strcmp(val, "w") == 0) current_rule->lb_algo = SPF_LB_WEIGHTED;
            }
            else if (strcmp(key, "max_conns") == 0 && current_rule) {
                current_rule->max_conns = (uint32_t)atoi(val);
            }
            else if (strcmp(key, "accept_rate") == 0 && current_rule) {
                current_rule->accept_rate = (uint32_t)atoi(val);
                if (current_rule->accept_rate) {
                    spf_bucket_init(&current_rule->accept_bucket, current_rule->accept_rate, 2.0);
                }
            }
            else if (strcmp(key, "tls") == 0 && current_rule) {
                current_rule->tls_terminate = strcmp(val, "true") == 0;
            }
            else if (strcmp(key, "rate") == 0 && current_rule) {
                current_rule->rate_bps = atol(val);
            }
        }
    }
    
    fclose(f);
    spf_log(SPF_LOG_INFO, "config: loaded %s (%u rules)", path, state->rule_count);
    return 0;
}

int spf_reload_config(spf_state_t* state) {
    if (state->config.config_path[0] == '\0') {
        return -1;
    }
    
    spf_log(SPF_LOG_INFO, "config: reloading...");
    return spf_load_config(state, state->config.config_path);
}

int config_save(spf_state_t* state, const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) return -1;
    
    fprintf(f, "[admin]\n");
    fprintf(f, "bind = %s\n", state->config.admin.bind_addr);
    fprintf(f, "port = %u\n", state->config.admin.port);
    if (state->config.admin.token[0]) {
        fprintf(f, "token = %s\n", state->config.admin.token);
    }
    fprintf(f, "tls = %s\n", state->config.admin.tls_enabled ? "true" : "false");
    fprintf(f, "\n");
    
    fprintf(f, "[security]\n");
    fprintf(f, "enabled = %s\n", state->config.security.enabled ? "true" : "false");
    fprintf(f, "proxy_proto = %s\n", state->config.security.proxy_proto ? "true" : "false");
    fprintf(f, "\n");
    
    fprintf(f, "[metrics]\n");
    fprintf(f, "enabled = %s\n", state->config.metrics.enabled ? "true" : "false");
    fprintf(f, "port = %u\n", state->config.metrics.port);
    fprintf(f, "\n");
    
    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (state->rules[i].active) {
            spf_rule_t* r = &state->rules[i];
            fprintf(f, "[rule.%u]\n", r->id);
            fprintf(f, "listen = %u\n", r->listen_port);
            
            const char* lb = "rr";
            if (r->lb_algo == SPF_LB_LEASTCONN) lb = "lc";
            else if (r->lb_algo == SPF_LB_IPHASH) lb = "ip";
            else if (r->lb_algo == SPF_LB_WEIGHTED) lb = "w";
            fprintf(f, "lb = %s\n", lb);

            if (r->max_conns) {
                fprintf(f, "max_conns = %u\n", r->max_conns);
            }
            if (r->accept_rate) {
                fprintf(f, "accept_rate = %u\n", r->accept_rate);
            }
            
            for (int j = 0; j < r->backend_count; j++) {
                fprintf(f, "backend = %s:%u:%u\n", 
                    r->backends[j].host, r->backends[j].port, r->backends[j].weight);
            }
            fprintf(f, "\n");
        }
    }
    
    fclose(f);
    spf_log(SPF_LOG_INFO, "config: saved to %s", path);
    return 0;
}

void config_dump(spf_state_t* state) {
    spf_log(SPF_LOG_INFO, "--- CONFIG ---");
    spf_log(SPF_LOG_INFO, "admin.bind = %s", state->config.admin.bind_addr);
    spf_log(SPF_LOG_INFO, "admin.port = %u", state->config.admin.port);
    spf_log(SPF_LOG_INFO, "rules = %u", state->rule_count);
}
