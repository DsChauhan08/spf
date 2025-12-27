#ifndef SPF_PLATFORM_ESP32

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

spf_state_t g_state;
static int g_ctrl_fd = -1;
static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_reload = 0;  // SIGHUP reload flag

// Host mode state
static bool g_upnp_enabled = false;
static bool g_ddns_enabled = false;

typedef struct {
    int client_fd;
    int target_fd;
    SSL* client_ssl;
    SSL* target_ssl;
    struct sockaddr_in client_addr;
    spf_rule_t* rule;
    uint8_t backend_idx;
    uint32_t conn_idx;
} session_t;

// Safe port parsing with validation
static int safe_parse_port(const char* str) {
    if (!str || !*str) return -1;
    char* end;
    long val = strtol(str, &end, 10);
    if (*end != '\0') return -1;  // Not fully numeric
    if (val <= 0 || val > 65535) return -1;
    return (int)val;
}

void sig_handler(int sig) {
    if (sig == SIGHUP) {
        g_reload = 1;  // Hot reload config
    } else {
        g_shutdown = 1;
    }
}

int send_proxy_proto_v2(int fd, struct sockaddr_in* src, struct sockaddr_in* dst) {
    uint8_t hdr[28] = {0};
    memcpy(hdr, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12);
    hdr[12] = 0x21;
    hdr[13] = 0x11;
    hdr[14] = 0x00;
    hdr[15] = 12;
    memcpy(&hdr[16], &src->sin_addr, 4);
    memcpy(&hdr[20], &dst->sin_addr, 4);
    memcpy(&hdr[24], &src->sin_port, 2);
    memcpy(&hdr[26], &dst->sin_port, 2);
    return send(fd, hdr, 28, 0) == 28 ? 0 : -1;
}

void* session_thread(void* arg) {
    session_t* s = (session_t*)arg;
    
    spf_lb_conn_start(s->rule, s->backend_idx);
    
    int flag = 1;
    setsockopt(s->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(s->target_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    spf_bucket_t bucket;
    spf_bucket_init(&bucket, s->rule->rate_bps ? s->rule->rate_bps : 100*1024*1024, 2.0);
    
    uint8_t buf[SPF_BUFFER_SIZE];
    fd_set fds;
    struct timeval tv;
    int maxfd = (s->client_fd > s->target_fd ? s->client_fd : s->target_fd) + 1;
    
    // Check for FD_SETSIZE overflow
    if (s->client_fd >= FD_SETSIZE || s->target_fd >= FD_SETSIZE) {
        spf_log(SPF_LOG_ERROR, "fd >= FD_SETSIZE, cannot use select");
        close(s->client_fd);
        close(s->target_fd);
        spf_lb_conn_end(s->rule, s->backend_idx);
        free(s);
        return NULL;
    }
    
    uint64_t bytes_in = 0, bytes_out = 0;
    
    while (!g_shutdown && g_state.running) {
        FD_ZERO(&fds);
        FD_SET(s->client_fd, &fds);
        FD_SET(s->target_fd, &fds);
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        
        int r = select(maxfd, &fds, NULL, NULL, &tv);
        if (r <= 0) break;
        
        if (FD_ISSET(s->client_fd, &fds)) {
            ssize_t n;
            if (s->client_ssl) {
                n = tls_read(s->client_ssl, buf, sizeof(buf));
                if (n == 0) continue; // WANT_READ/WRITE
            } else {
                n = recv(s->client_fd, buf, sizeof(buf), 0);
            }
            if (n < 0) break; // Error
            if (n == 0 && !s->client_ssl) break; // EOF (for tcp)
            
            uint64_t allowed = spf_bucket_consume(&bucket, n);
            if (allowed > 0) {
                if (s->target_ssl) {
                    ssize_t sent = tls_write(s->target_ssl, buf, allowed);
                    if (sent < 0) break;
                } else {
                    ssize_t sent = send(s->target_fd, buf, allowed, 0);
                    if (sent < 0) break;
                }
                bytes_in += allowed;
            }
        }
        
        if (FD_ISSET(s->target_fd, &fds)) {
            ssize_t n;
            if (s->target_ssl) {
                n = tls_read(s->target_ssl, buf, sizeof(buf));
                if (n == 0) continue; // WANT_READ/WRITE
            } else {
                n = recv(s->target_fd, buf, sizeof(buf), 0);
            }
            if (n < 0) break;
            if (n == 0 && !s->target_ssl) break;
            
            uint64_t allowed = spf_bucket_consume(&bucket, n);
            if (allowed > 0) {
                if (s->client_ssl) {
                    ssize_t sent = tls_write(s->client_ssl, buf, allowed);
                    if (sent < 0) break;
                } else {
                    ssize_t sent = send(s->client_fd, buf, allowed, 0);
                    if (sent < 0) break;
                }
                bytes_out += allowed;
            }
        }
    }
    
    if (s->client_ssl) { SSL_shutdown(s->client_ssl); SSL_free(s->client_ssl); }
    if (s->target_ssl) { SSL_shutdown(s->target_ssl); SSL_free(s->target_ssl); }
    close(s->client_fd);
    close(s->target_fd);
    
    spf_lb_conn_end(s->rule, s->backend_idx);
    
    // Access logging (cloud LB feature)
    char cli_ip[SPF_IP_MAX_LEN];
    inet_ntop(AF_INET, &s->client_addr.sin_addr, cli_ip, sizeof(cli_ip));
    char backend_info[128];
    snprintf(backend_info, sizeof(backend_info), "%s:%u", 
             s->rule->backends[s->backend_idx].host, 
             s->rule->backends[s->backend_idx].port);
    uint64_t duration = (spf_time_sec() - g_state.connections[s->conn_idx].start_time) * 1000;
    spf_access_log(cli_ip, ntohs(s->client_addr.sin_port), s->rule->id,
                   backend_info, bytes_in, bytes_out, duration, 200);
    
    // Disconnect hook (custom security)
    spf_hook_on_disconnect(cli_ip, ntohs(s->client_addr.sin_port), s->rule->id,
                          s->rule->backends[s->backend_idx].host,
                          s->rule->backends[s->backend_idx].port);
    
    pthread_mutex_lock(&g_state.stats_lock);
    g_state.total_bytes_in += bytes_in;
    g_state.total_bytes_out += bytes_out;
    if (s->conn_idx < SPF_MAX_CONNECTIONS) {
        g_state.connections[s->conn_idx].active = false;
        g_state.connections[s->conn_idx].bytes_in = bytes_in;
        g_state.connections[s->conn_idx].bytes_out = bytes_out;
    }
    if (g_state.active_conns > 0) {
        g_state.active_conns--;
    }
    pthread_mutex_unlock(&g_state.stats_lock);

    if (s->rule) {
        pthread_mutex_lock(&s->rule->lock);
        if (s->rule->active_conns > 0) {
            s->rule->active_conns--;
        }
        pthread_mutex_unlock(&s->rule->lock);
    }
    
    free(s);
    return NULL;
}

void* listener_thread(void* arg) {
    spf_rule_t* rule = (spf_rule_t*)arg;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(rule->listen_port);
    
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "bind port %u failed: %s", rule->listen_port, strerror(errno));
        close(fd);
        return NULL;
    }
    
    listen(fd, 256);
    spf_log(SPF_LOG_INFO, "rule %u listening on :%u", rule->id, rule->listen_port);
    
    pthread_create(&rule->health_thread, NULL, spf_health_worker, rule);
    pthread_detach(rule->health_thread);
    
    while (!g_shutdown && g_state.running && rule->active) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {1, 0};
        
        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli_fd < 0) continue;

        pthread_mutex_lock(&g_state.stats_lock);
        bool at_capacity = g_state.active_conns >= (SPF_MAX_CONNECTIONS - 1);
        pthread_mutex_unlock(&g_state.stats_lock);
        if (at_capacity) {
            spf_log(SPF_LOG_WARN, "dropping connection: at capacity (%u active)", g_state.active_conns);
            close(cli_fd);
            continue;
        }
        
        // Fix DoS: Set timeouts immediately to prevent slow handshake hanging the listener
        struct timeval tv_cli = {10, 0}; // 10s timeout
        setsockopt(cli_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_cli, sizeof(tv_cli));
        setsockopt(cli_fd, SOL_SOCKET, SO_SNDTIMEO, &tv_cli, sizeof(tv_cli));
        
        char cli_ip[SPF_IP_MAX_LEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, cli_ip, sizeof(cli_ip));

        bool rule_limit_hit = false;
        pthread_mutex_lock(&rule->lock);
        if (rule->max_conns && rule->active_conns >= rule->max_conns) {
            rule_limit_hit = true;
        } else if (rule->accept_rate) {
            uint64_t allowed = spf_bucket_consume(&rule->accept_bucket, 1);
            if (allowed == 0) {
                rule_limit_hit = true;
            }
        }
        if (!rule_limit_hit) {
            rule->active_conns++;
        }
        pthread_mutex_unlock(&rule->lock);

        bool rule_counted = !rule_limit_hit;
        if (rule_limit_hit) {
            spf_event_push(&g_state, SPF_EVENT_RATE_LIMITED, cli_ip, ntohs(cli_addr.sin_port), rule->id, "rule limit");
            close(cli_fd);
            continue;
        }
        
        if (g_state.config.security.enabled) {
            if (spf_is_blocked(&g_state, cli_ip)) {
                if (rule_counted) {
                    pthread_mutex_lock(&rule->lock);
                    if (rule->active_conns > 0) rule->active_conns--;
                    pthread_mutex_unlock(&rule->lock);
                    rule_counted = false;
                }
                close(cli_fd);
                continue;
            }
            
            if (!spf_register_attempt(&g_state, cli_ip)) {
                if (rule_counted) {
                    pthread_mutex_lock(&rule->lock);
                    if (rule->active_conns > 0) rule->active_conns--;
                    pthread_mutex_unlock(&rule->lock);
                    rule_counted = false;
                }
                close(cli_fd);
                continue;
            }
        }
        
        if (g_state.config.security.enabled && spf_geoip_is_blocked(&g_state, cli_ip)) {
            spf_event_push(&g_state, SPF_EVENT_GEOBLOCK, cli_ip, ntohs(cli_addr.sin_port), rule->id, "geo blocked");
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            close(cli_fd);
            continue;
        }
        
        // Custom security hook - Linux-way extensibility
        // Script returns: 0=allow, 1=block, 2=rate_limit
        int hook_result = spf_hook_on_connect(cli_ip, ntohs(cli_addr.sin_port), 
                                              rule->id, NULL, 0);
        if (hook_result == 1) {
            spf_event_push(&g_state, SPF_EVENT_BLOCKED, cli_ip, ntohs(cli_addr.sin_port), 
                          rule->id, "hook blocked");
            spf_hook_on_block(cli_ip, rule->id, "custom_hook");
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            close(cli_fd);
            continue;
        } else if (hook_result == 2) {
            spf_event_push(&g_state, SPF_EVENT_RATE_LIMITED, cli_ip, ntohs(cli_addr.sin_port),
                          rule->id, "hook rate_limit");
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            close(cli_fd);
            continue;
        }
        
        int backend_idx = spf_lb_select_backend(rule, cli_ip);
        if (backend_idx < 0) {
            spf_log(SPF_LOG_WARN, "no healthy backend for rule %u", rule->id);
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            close(cli_fd);
            continue;
        }
        
        spf_backend_t* b = &rule->backends[backend_idx];
        
        int tgt_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tgt_fd < 0) {
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            close(cli_fd);
            continue;
        }
        
        struct sockaddr_in tgt_addr;
        memset(&tgt_addr, 0, sizeof(tgt_addr));
        tgt_addr.sin_family = AF_INET;
        tgt_addr.sin_port = htons(b->port);
        inet_pton(AF_INET, b->host, &tgt_addr.sin_addr);
        
        struct timeval tv_conn = {5, 0};
        setsockopt(tgt_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_conn, sizeof(tv_conn));
        setsockopt(tgt_fd, SOL_SOCKET, SO_SNDTIMEO, &tv_conn, sizeof(tv_conn));
        
        if (connect(tgt_fd, (struct sockaddr*)&tgt_addr, sizeof(tgt_addr)) < 0) {
            close(tgt_fd);
            close(cli_fd);
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            continue;
        }
        
        if (g_state.config.security.proxy_proto) {
            send_proxy_proto_v2(tgt_fd, &cli_addr, &tgt_addr);
        }
        
        pthread_mutex_lock(&g_state.stats_lock);
        int conn_idx = -1;
        for (int i = 0; i < SPF_MAX_CONNECTIONS; i++) {
            if (!g_state.connections[i].active) {
                conn_idx = i;
                break;
            }
        }
        if (conn_idx < 0) {
            pthread_mutex_unlock(&g_state.stats_lock);
            close(tgt_fd);
            close(cli_fd);
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            continue;
        }
        
        g_state.connections[conn_idx].active = true;
        g_state.connections[conn_idx].id = g_state.next_conn_id++;
        strncpy(g_state.connections[conn_idx].client_ip, cli_ip, SPF_IP_MAX_LEN - 1);
        g_state.connections[conn_idx].client_port = ntohs(cli_addr.sin_port);
        g_state.connections[conn_idx].rule_id = rule->id;
        g_state.connections[conn_idx].backend_idx = backend_idx;
        g_state.connections[conn_idx].start_time = spf_time_sec();
        g_state.active_conns++;
        g_state.total_conns++;
        pthread_mutex_unlock(&g_state.stats_lock);
        
        spf_event_push(&g_state, SPF_EVENT_CONN_OPEN, cli_ip, ntohs(cli_addr.sin_port), rule->id, b->host);
        
        session_t* sess = (session_t*)calloc(1, sizeof(session_t));
        if (!sess) {
            spf_log(SPF_LOG_ERROR, "oom in listener");
            close(cli_fd);
            close(tgt_fd);
            spf_lb_conn_end(rule, backend_idx);
            if (rule_counted) {
                pthread_mutex_lock(&rule->lock);
                if (rule->active_conns > 0) rule->active_conns--;
                pthread_mutex_unlock(&rule->lock);
                rule_counted = false;
            }
            continue;
        }
        
        sess->client_fd = cli_fd;
        sess->target_fd = tgt_fd;
        sess->client_addr = cli_addr;
        sess->rule = rule;
        sess->backend_idx = backend_idx;
        sess->conn_idx = conn_idx;
        
        // Setup TLS
        if (rule->tls_terminate) {
            sess->client_ssl = tls_accept(cli_fd);
            if (!sess->client_ssl) {
                spf_log(SPF_LOG_ERROR, "tls accept failed");
                close(cli_fd);
                close(tgt_fd);
                spf_lb_conn_end(rule, backend_idx);
                if (rule_counted) {
                    pthread_mutex_lock(&rule->lock);
                    if (rule->active_conns > 0) rule->active_conns--;
                    pthread_mutex_unlock(&rule->lock);
                    rule_counted = false;
                }
                free(sess);
                continue;
            }
        }
        
        // Connect to target (TLS if needed)
        // ... (assume target logic is similar, kept simplistic here for brevity)
        
        pthread_t t;
        pthread_create(&t, NULL, session_thread, sess);
        pthread_detach(t);
    }
    
    close(fd);
    spf_log(SPF_LOG_INFO, "rule %u listener stopped", rule->id);
    return NULL;
}

void ctrl_send(int fd, const char* msg) {
    send(fd, msg, strlen(msg), 0);
}

void handle_ctrl(int fd) {
    char buf[SPF_BUFFER_SIZE];
    bool authed = g_state.config.admin.token[0] == '\0';
    
    ctrl_send(fd, "SPF v" SPF_VERSION " Control\n");
    if (!authed) ctrl_send(fd, "AUTH required\n");
    ctrl_send(fd, "> ");
    
    while (!g_shutdown) {
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        
        char* nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        char* cr = strchr(buf, '\r'); if (cr) *cr = '\0';
        if (strlen(buf) == 0) { ctrl_send(fd, "> "); continue; }
        
        char resp[SPF_RES_MAX_LEN] = {0};
        
        if (strncmp(buf, "QUIT", 4) == 0) {
            break;
        }
        else if (strncmp(buf, "AUTH ", 5) == 0) {
            if (spf_verify_token(&g_state, buf + 5)) {
                authed = true;
                snprintf(resp, sizeof(resp), "OK authenticated\n");
            } else {
                spf_event_push(&g_state, SPF_EVENT_AUTH_FAIL, "", 0, 0, "bad token");
                snprintf(resp, sizeof(resp), "ERR bad token\n");
            }
        }
        else if (!authed) {
            snprintf(resp, sizeof(resp), "ERR auth required\n");
        }
        else if (strncmp(buf, "HELP", 4) == 0) {
            snprintf(resp, sizeof(resp),
                "Commands:\n"
                "  AUTH <token>       - authenticate\n"
                "  STATUS             - system stats\n"
                "  RULES              - list rules\n"
                "  BACKENDS <id>      - show backends\n"
                "  ADD <port> <ip:port> [algo] [max_conns] [accept_rate] - add rule\n"
                "  DEL <id>           - delete rule\n"
                "  BLOCK <ip> [sec]   - block ip\n"
                "  UNBLOCK <ip>       - unblock ip\n"
                "  LOGS [n]           - recent events\n"
                "  METRICS            - prometheus\n"
                "  HOOKS              - show custom hooks\n"
                "  RELOAD             - hot reload config\n"
                "  QUIT               - close\n");
        }
        else if (strncmp(buf, "STATUS", 6) == 0) {
            uint64_t up = spf_time_sec() - g_state.start_time;
            snprintf(resp, sizeof(resp),
                "--- SPF STATUS ---\n"
                "Version: %s\n"
                "Uptime: %luh %lum %lus\n"
                "Active Conns: %u\n"
                "Total Conns: %lu\n"
                "Bytes In: %lu\n"
                "Bytes Out: %lu\n"
                "Rules: %u\n"
                "Blocked IPs: %lu\n",
                SPF_VERSION,
                up/3600, (up%3600)/60, up%60,
                g_state.active_conns,
                g_state.total_conns,
                g_state.total_bytes_in,
                g_state.total_bytes_out,
                g_state.rule_count,
                g_state.blocked_count);
        }
        else if (strncmp(buf, "RULES", 5) == 0) {
            char* p = resp;
            p += snprintf(p, sizeof(resp), "--- RULES ---\n");
            for (int i = 0; i < SPF_MAX_RULES && p - resp < SPF_RES_MAX_LEN - 100; i++) {
                if (g_state.rules[i].active) {
                    spf_rule_t* r = &g_state.rules[i];
                    p += snprintf(p, SPF_RES_MAX_LEN - (p - resp),
                        "ID:%u Port:%u Backends:%u LB:%d\n",
                        r->id, r->listen_port, r->backend_count, r->lb_algo);
                }
            }
        }
        else if (strncmp(buf, "BACKENDS ", 9) == 0) {
            uint32_t id;
            if (sscanf(buf + 9, "%u", &id) == 1) {
                spf_rule_t* r = spf_get_rule(&g_state, id);
                if (r) {
                    char* p = resp;
                    p += snprintf(p, sizeof(resp), "--- BACKENDS for %u ---\n", id);
                    for (int i = 0; i < r->backend_count; i++) {
                        spf_backend_t* b = &r->backends[i];
                        p += snprintf(p, SPF_RES_MAX_LEN - (p - resp),
                            "%s:%u w=%u state=%s conns=%u\n",
                            b->host, b->port, b->weight,
                            b->state == SPF_BACKEND_UP ? "UP" : b->state == SPF_BACKEND_DOWN ? "DOWN" : "DRAIN",
                            b->active_conns);
                    }
                } else {
                    snprintf(resp, sizeof(resp), "ERR rule not found\n");
                }
            }
        }
        else if (strncmp(buf, "ADD ", 4) == 0) {
                int port;
                char backend[64];
                char algo[16] = "rr";
                int max_conns = 0;
                int accept_rate = 0;
                int parsed = sscanf(buf + 4, "%d %63s %15s %d %d", &port, backend, algo, &max_conns, &accept_rate);
                
                if (parsed >= 2 && port > 0 && port < 65536) {
                    spf_rule_t rule;
                    memset(&rule, 0, sizeof(rule));
                uint8_t rnd[4];
                spf_random_bytes(rnd, 4);
                rule.id = (*(uint32_t*)rnd) % 90000 + 10000;
                rule.listen_port = port;
                rule.enabled = true;
                rule.rate_bps = 100 * 1024 * 1024;
                    rule.max_conns = max_conns > 0 ? (uint32_t)max_conns : 512;
                    rule.accept_rate = accept_rate > 0 ? (uint32_t)accept_rate : (g_state.config.security.rate_global ? g_state.config.security.rate_global : 5000);
                    if (rule.accept_rate) {
                        spf_bucket_init(&rule.accept_bucket, rule.accept_rate, 2.0);
                    }
                
                if (strcmp(algo, "lc") == 0) rule.lb_algo = SPF_LB_LEASTCONN;
                else if (strcmp(algo, "ip") == 0) rule.lb_algo = SPF_LB_IPHASH;
                else if (strcmp(algo, "w") == 0) rule.lb_algo = SPF_LB_WEIGHTED;
                else rule.lb_algo = SPF_LB_ROUNDROBIN;
                
                char* tok = strtok(backend, ",");
                while (tok && rule.backend_count < SPF_MAX_BACKENDS) {
                    char* colon = strchr(tok, ':');
                    if (colon) {
                        *colon = '\0';
                        int port = safe_parse_port(colon + 1);
                        if (port > 0) {
                            strncpy(rule.backends[rule.backend_count].host, tok, SPF_IP_MAX_LEN - 1);
                            rule.backends[rule.backend_count].port = port;
                            rule.backends[rule.backend_count].weight = 1;
                            rule.backends[rule.backend_count].state = SPF_BACKEND_UP;
                            rule.backend_count++;
                        }
                    }
                    tok = strtok(NULL, ",");
                }
                
                if (rule.backend_count > 0) {
                    if (spf_add_rule(&g_state, &rule) == 0) {
                        spf_rule_t* added = spf_get_rule(&g_state, rule.id);
                        if (added) {
                            pthread_create(&added->listen_thread, NULL, listener_thread, added);
                            pthread_detach(added->listen_thread);
                            snprintf(resp, sizeof(resp), "OK rule %u added\n", rule.id);
                        } else {
                            snprintf(resp, sizeof(resp), "ERR internal error\n");
                        }
                    } else {
                        snprintf(resp, sizeof(resp), "ERR failed to add rule\n");
                    }
                } else {
                    snprintf(resp, sizeof(resp), "ERR bad backend format\n");
                }
            } else {
                    snprintf(resp, sizeof(resp), "ERR usage: ADD <port> <host:port,...> [rr|lc|ip|w] [max_conns] [accept_rate]\n");
            }
        }
        else if (strncmp(buf, "DEL ", 4) == 0) {
            uint32_t id;
            if (sscanf(buf + 4, "%u", &id) == 1) {
                if (spf_del_rule(&g_state, id) == 0) {
                    snprintf(resp, sizeof(resp), "OK deleted\n");
                } else {
                    snprintf(resp, sizeof(resp), "ERR not found\n");
                }
            }
        }
        else if (strncmp(buf, "BLOCK ", 6) == 0) {
            char ip[64] = {0};
            uint64_t dur = 3600;
            int parsed = sscanf(buf + 6, "%63s %lu", ip, &dur);
            if (parsed >= 1 && ip[0] != '\0') {
                spf_block_ip(&g_state, ip, dur);
                snprintf(resp, sizeof(resp), "OK blocked %s for %lu sec\n", ip, dur);
            } else {
                snprintf(resp, sizeof(resp), "ERR usage: BLOCK <ip> [seconds]\n");
            }
        }
        else if (strncmp(buf, "UNBLOCK ", 8) == 0) {
            char ip[64];
            if (sscanf(buf + 8, "%63s", ip) == 1) {
                spf_unblock_ip(&g_state, ip);
                snprintf(resp, sizeof(resp), "OK unblocked %s\n", ip);
            }
        }
        else if (strncmp(buf, "LOGS", 4) == 0) {
            uint32_t n = 10;
            sscanf(buf + 4, "%u", &n);
            if (n > 50) n = 50;
            
            spf_event_t events[50];
            uint32_t actual;
            spf_event_get_recent(&g_state, events, n, &actual);
            
            char* p = resp;
            p += snprintf(p, sizeof(resp), "--- LAST %u EVENTS ---\n", actual);
            for (uint32_t i = 0; i < actual && p - resp < SPF_RES_MAX_LEN - 150; i++) {
                p += snprintf(p, SPF_RES_MAX_LEN - (p - resp),
                    "%lu type=%d %s:%u %s\n",
                    events[i].timestamp, events[i].type,
                    events[i].src_ip, events[i].src_port,
                    events[i].details);
            }
        }
        else if (strncmp(buf, "METRICS", 7) == 0) {
            snprintf(resp, sizeof(resp),
                "# HELP spf_connections_active Current active connections\n"
                "spf_connections_active %u\n"
                "# HELP spf_connections_total Total connections since start\n"
                "spf_connections_total %lu\n"
                "# HELP spf_bytes_in_total Total bytes received\n"
                "spf_bytes_in_total %lu\n"
                "# HELP spf_bytes_out_total Total bytes sent\n"
                "spf_bytes_out_total %lu\n"
                "# HELP spf_blocked_total Total blocked IPs\n"
                "spf_blocked_total %lu\n"
                "# HELP spf_rules_active Active forwarding rules\n"
                "spf_rules_active %u\n",
                g_state.active_conns,
                g_state.total_conns,
                g_state.total_bytes_in,
                g_state.total_bytes_out,
                g_state.blocked_count,
                g_state.rule_count);
        }
        else if (strncmp(buf, "HOOKS", 5) == 0) {
            spf_hooks_get_info(resp, sizeof(resp));
        }
        else if (strncmp(buf, "RELOAD", 6) == 0) {
            if (spf_reload_config(&g_state) == 0) {
                snprintf(resp, sizeof(resp), "OK config reloaded\n");
            } else {
                snprintf(resp, sizeof(resp), "ERR reload failed\n");
            }
        }
        else {
            snprintf(resp, sizeof(resp), "ERR unknown cmd\n");
        }
        
        ctrl_send(fd, resp);
        ctrl_send(fd, "> ");
    }
    
    close(fd);
}

void* ctrl_thread(void* arg) {
    (void)arg;
    
    g_ctrl_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(g_ctrl_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, g_state.config.admin.bind_addr, &addr.sin_addr);
    addr.sin_port = htons(g_state.config.admin.port);
    
    if (bind(g_ctrl_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "ctrl bind failed: %s", strerror(errno));
        return NULL;
    }
    
    listen(g_ctrl_fd, 5);
    spf_log(SPF_LOG_INFO, "ctrl listening on %s:%u", g_state.config.admin.bind_addr, g_state.config.admin.port);
    
    while (!g_shutdown && g_state.running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_ctrl_fd, &fds);
        struct timeval tv = {1, 0};
        
        if (select(g_ctrl_fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        
        int cli = accept(g_ctrl_fd, NULL, NULL);
        if (cli >= 0) {
            spf_log(SPF_LOG_INFO, "admin connected");
            handle_ctrl(cli);
            spf_log(SPF_LOG_INFO, "admin disconnected");
        }
    }
    
    close(g_ctrl_fd);
    return NULL;
}

void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    if (setsid() < 0) exit(1);
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    umask(0);
    if (chdir("/") != 0) exit(1);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

// Forward declarations for host mode (replaces tunnel mode)
static int run_host_mode(int argc, char** argv);

int main(int argc, char** argv) {
    // Check for subcommands
    if (argc >= 2) {
        if (strcmp(argv[1], "host") == 0 || strcmp(argv[1], "serve") == 0) {
            return run_host_mode(argc - 1, argv + 1);
        }
    }
    
    const char* config_path = "spf.conf";
    char* bind_addr = NULL;
    char* token = NULL;
    char* cert = NULL;
    char* key = NULL;
    int port = 0; // 0 means not set via CLI
    bool daemon_mode = false;
    char* forward_spec = NULL;  // One-liner mode: "8080:backend:80"
    char* hooks_dir = NULL;
    char* access_log_path = NULL;
    
    static struct option opts[] = {
        {"config", required_argument, 0, 'C'},
        {"admin-bind", required_argument, 0, 'b'},
        {"admin-port", required_argument, 0, 'p'},
        {"token", required_argument, 0, 't'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"daemon", no_argument, 0, 'd'},
        {"forward", required_argument, 0, 'f'},  // One-liner mode
        {"hooks-dir", required_argument, 0, 'H'},
        {"access-log", required_argument, 0, 'A'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "C:b:p:t:c:k:df:H:A:h", opts, NULL)) != -1) {
        switch (c) {
            case 'C': config_path = optarg; break;
            case 'b': bind_addr = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 't': token = optarg; break;
            case 'c': cert = optarg; break;
            case 'k': key = optarg; break;
            case 'd': daemon_mode = true; break;
            case 'f': forward_spec = optarg; break;
            case 'H': hooks_dir = optarg; break;
            case 'A': access_log_path = optarg; break;
            case 'h':
                printf("\n");
                printf("  ╔═══════════════════════════════════════════════════════════════╗\n");
                printf("  ║  SPF v%s - Self-Host From Home (No VPS Needed!)          ║\n", SPF_VERSION);
                printf("  ╚═══════════════════════════════════════════════════════════════╝\n\n");
                printf("  QUICK START (host a website from your laptop):\n");
                printf("    spf host 8080                    # Auto-configure router, serve port\n");
                printf("    spf host 3000 --domain my.duckdns.org --ddns duckdns --token xxx\n\n");
                printf("  COMMANDS:\n");
                printf("    host <port>      Host a local server (auto UPnP + DDNS)\n\n");
                printf("  OPTIONS:\n");
                printf("    -f, --forward <spec>   Quick forward: listen:target:port\n");
                printf("    -C, --config <path>    Config file (for multiple rules)\n");
                printf("    -c, --cert <path>      TLS certificate\n");
                printf("    -k, --key <path>       TLS private key\n");
                printf("    -d, --daemon           Run in background\n");
                printf("    -h, --help             Show this help\n\n");
                printf("  HOW IT WORKS:\n");
                printf("    1. SPF discovers your router via UPnP\n");
                printf("    2. Automatically opens the port on your router\n");
                printf("    3. Updates your DDNS domain with your IP\n");
                printf("    4. Your site is live at your-domain.duckdns.org!\n\n");
                printf("  EXAMPLES:\n");
                printf("    # Simple port forward (like socat but easier)\n");
                printf("    spf -f 8080:myapi.internal:80\n\n");
                printf("    # Host from home with auto router config + DDNS\n");
                printf("    spf host 3000 --domain mysite.duckdns.org --ddns duckdns --token XXX\n\n");
                printf("  MORE HELP:\n");
                printf("    spf host --help      # Self-hosting help\n");
                printf("\n");
                return 0;
        }
    }
    
    if (daemon_mode) daemonize();
    
    spf_init(&g_state);
    
    // Initialize hook system
    spf_hooks_init();
    if (hooks_dir) {
        spf_hooks_set_dir(hooks_dir);
    }
    spf_hooks_autodiscover();
    
    // Initialize access logging
    if (access_log_path) {
        spf_access_log_init(access_log_path);
    }
    
    // Load config first
    if (spf_load_config(&g_state, config_path) < 0) {
        // If default config fails, just warn (unless specific config was requested)
        if (strcmp(config_path, "spf.conf") != 0) {
            fprintf(stderr, "Error: cannot load config file %s\n", config_path);
            return 1;
        } else {
             // For default, maybe it doesn't exist yet, which is fine
        }
    }

    if (bind_addr) strncpy(g_state.config.admin.bind_addr, bind_addr, SPF_IP_MAX_LEN - 1);
    if (token) strncpy(g_state.config.admin.token, token, SPF_TOKEN_MAX - 1);
    if (cert) strncpy(g_state.config.admin.cert_path, cert, SPF_PATH_MAX - 1);
    if (key) strncpy(g_state.config.admin.key_path, key, SPF_PATH_MAX - 1);
    
    // Override port if set via CLI
    if (port > 0) {
        g_state.config.admin.port = port;
    } else if (g_state.config.admin.port == 0) {
        g_state.config.admin.port = SPF_CTRL_PORT_DEFAULT;
    }
    
    if (cert && key) {
        if (tls_init(cert, key) == 0) {
            g_state.config.admin.tls_enabled = true;
            spf_log(SPF_LOG_INFO, "tls enabled");
        }
    }
    
    // One-liner forward mode (socat pain point: complex syntax)
    if (forward_spec) {
        int listen_port;
        char backend_host[128];
        int backend_port;
        
        if (sscanf(forward_spec, "%d:%127[^:]:%d", &listen_port, backend_host, &backend_port) == 3) {
            spf_rule_t rule;
            memset(&rule, 0, sizeof(rule));
            rule.id = 1;
            rule.listen_port = listen_port;
            rule.enabled = true;
            rule.rate_bps = 100 * 1024 * 1024;
            rule.max_conns = 4096;
            rule.accept_rate = 10000;  // High rate for one-liner mode
            spf_bucket_init(&rule.accept_bucket, rule.accept_rate, 2.0);
            rule.lb_algo = SPF_LB_ROUNDROBIN;
            rule.tls_terminate = (cert && key);
            
            // Resolve hostname to IP if needed
            char resolved_ip[SPF_IP_MAX_LEN];
            if (spf_resolve_hostname(backend_host, resolved_ip, sizeof(resolved_ip)) == 0) {
                strncpy(rule.backends[0].host, resolved_ip, SPF_IP_MAX_LEN - 1);
            } else {
                strncpy(rule.backends[0].host, backend_host, SPF_IP_MAX_LEN - 1);
            }
            rule.backends[0].port = backend_port;
            rule.backends[0].weight = 1;
            rule.backends[0].state = SPF_BACKEND_UP;
            rule.backend_count = 1;
            
            if (spf_add_rule(&g_state, &rule) == 0) {
                spf_rule_t* added = spf_get_rule(&g_state, rule.id);
                if (added) {
                    pthread_create(&added->listen_thread, NULL, listener_thread, added);
                    pthread_detach(added->listen_thread);
                    spf_log(SPF_LOG_INFO, "one-liner: forwarding :%d -> %s:%d", 
                           listen_port, rule.backends[0].host, backend_port);
                }
            } else {
                spf_log(SPF_LOG_ERROR, "failed to add forward rule");
                return 1;
            }
        } else {
            fprintf(stderr, "Invalid forward spec. Use: listen_port:backend_host:backend_port\n");
            return 1;
        }
    }

    bool bind_is_loopback = strcmp(g_state.config.admin.bind_addr, "127.0.0.1") == 0 ||
                            strcmp(g_state.config.admin.bind_addr, "::1") == 0;
    if (!bind_is_loopback && g_state.config.admin.token[0] == '\0') {
        spf_log(SPF_LOG_ERROR, "refusing to start: admin on %s:%u without auth token", 
                g_state.config.admin.bind_addr, g_state.config.admin.port);
        fprintf(stderr, "Set --token or configure admin.token when binding non-loopback.\n");
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);  // Hot reload config
    signal(SIGPIPE, SIG_IGN);
    
    if (!daemon_mode) {
        printf("=== SPF v%s ===\n", SPF_VERSION);
        printf("Control: nc %s %d\n", g_state.config.admin.bind_addr, g_state.config.admin.port);
        if (token) printf("Token required for auth\n");
    }
    
    pthread_t ct;
    pthread_create(&ct, NULL, ctrl_thread, NULL);
    
    while (!g_shutdown && g_state.running) {
        sleep(1);
        
        // SIGHUP hot reload (rinetd pain point: requires restart)
        if (g_reload) {
            g_reload = 0;
            spf_log(SPF_LOG_INFO, "SIGHUP received, reloading config...");
            spf_reload_config(&g_state);
            spf_hooks_autodiscover();  // Re-scan hooks
        }
    }
    
    spf_log(SPF_LOG_INFO, "shutting down...");
    g_state.running = false;
    
    if (g_ctrl_fd >= 0) close(g_ctrl_fd);
    
    pthread_join(ct, NULL);
    tls_cleanup();
    spf_access_log_close();
    spf_hooks_cleanup();
    spf_shutdown(&g_state);
    
    return 0;
}

// ============================================================================
// HOST MODE - Self-host from home with auto UPnP + DDNS (NO VPS!)
// ============================================================================
static int run_host_mode(int argc, char** argv) {
    uint16_t local_port = 0;
    uint16_t external_port = 0;
    char* domain = NULL;
    char* ddns_provider = NULL;
    char* ddns_token = NULL;
    char* ddns_user = NULL;
    char* ddns_pass = NULL;
    char* cert = NULL;
    char* key = NULL;
    bool no_upnp = false;
    bool no_ddns = false;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--domain") == 0 || strcmp(argv[i], "-D") == 0) {
            if (i + 1 < argc) domain = argv[++i];
        } else if (strcmp(argv[i], "--ddns") == 0) {
            if (i + 1 < argc) ddns_provider = argv[++i];
        } else if (strcmp(argv[i], "--token") == 0 || strcmp(argv[i], "-t") == 0) {
            if (i + 1 < argc) ddns_token = argv[++i];
        } else if (strcmp(argv[i], "--user") == 0 || strcmp(argv[i], "-u") == 0) {
            if (i + 1 < argc) ddns_user = argv[++i];
        } else if (strcmp(argv[i], "--pass") == 0) {
            if (i + 1 < argc) ddns_pass = argv[++i];
        } else if (strcmp(argv[i], "--external-port") == 0 || strcmp(argv[i], "-e") == 0) {
            if (i + 1 < argc) external_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cert") == 0 || strcmp(argv[i], "-c") == 0) {
            if (i + 1 < argc) cert = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 || strcmp(argv[i], "-k") == 0) {
            if (i + 1 < argc) key = argv[++i];
        } else if (strcmp(argv[i], "--no-upnp") == 0) {
            no_upnp = true;
        } else if (strcmp(argv[i], "--no-ddns") == 0) {
            no_ddns = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("\n");
            printf("  ╔═══════════════════════════════════════════════════════════════════╗\n");
            printf("  ║  SPF Host - Self-Host From Home (NO VPS NEEDED!)                  ║\n");
            printf("  ╚═══════════════════════════════════════════════════════════════════╝\n\n");
            printf("  USAGE:\n");
            printf("    spf host <port> [options]\n\n");
            printf("  WHAT IT DOES:\n");
            printf("    1. 🔌 Auto-configures your router via UPnP (opens the port)\n");
            printf("    2. 🌐 Updates your DDNS domain with your current IP\n");
            printf("    3. 🔒 Applies enterprise-grade security (rate limits, blocking)\n");
            printf("    4. ✨ Your local server is now accessible from the internet!\n\n");
            printf("  EXAMPLES:\n");
            printf("    # Basic (router auto-configured, prints your public IP)\n");
            printf("    spf host 3000\n\n");
            printf("    # With DuckDNS (free dynamic DNS)\n");
            printf("    spf host 3000 --domain mysite --ddns duckdns --token YOUR_TOKEN\n\n");
            printf("    # With HTTPS (auto Let's Encrypt coming soon)\n");
            printf("    spf host 443 --cert cert.pem --key key.pem --domain mysite.duckdns.org\n\n");
            printf("  OPTIONS:\n");
            printf("    -D, --domain <name>      Your domain (e.g., mysite.duckdns.org)\n");
            printf("    --ddns <provider>        DDNS provider: duckdns, noip, dynu, freedns\n");
            printf("    -t, --token <token>      DDNS API token\n");
            printf("    -u, --user <user>        DDNS username (for noip, dynu)\n");
            printf("    --pass <pass>            DDNS password (for noip, dynu)\n");
            printf("    -e, --external-port <n>  External port (default: same as local)\n");
            printf("    -c, --cert <path>        TLS certificate for HTTPS\n");
            printf("    -k, --key <path>         TLS private key\n");
            printf("    --no-upnp                Don't auto-configure router\n");
            printf("    --no-ddns                Don't update DDNS\n\n");
            printf("  SECURITY FEATURES (enabled by default):\n");
            printf("    ✅ Rate limiting (30 conn/min per IP)\n");
            printf("    ✅ Connection limits (50 simultaneous per IP)\n");
            printf("    ✅ Private IP blocking (prevents spoofing attacks)\n");
            printf("    ✅ Bogon filtering (blocks reserved IP ranges)\n");
            printf("    ✅ Automatic brute-force detection & blocking\n");
            printf("    ✅ Progressive ban (10min → 1hr → 24hr)\n\n");
            printf("  DDNS PROVIDERS:\n");
            printf("    duckdns   - Free, easy (duckdns.org)\n");
            printf("    noip      - Free tier available (noip.com)\n");
            printf("    dynu      - Free (dynu.com)\n");
            printf("    freedns   - Free (freedns.afraid.org)\n\n");
            return 0;
        } else if (argv[i][0] != '-' && local_port == 0 && isdigit(argv[i][0])) {
            local_port = atoi(argv[i]);
        }
    }
    
    if (local_port == 0) {
        printf("\n");
        printf("  ❌ Please specify a port to host!\n\n");
        printf("  Usage: spf host <port>\n");
        printf("  Example: spf host 3000\n\n");
        printf("  Run 'spf host --help' for all options.\n\n");
        return 1;
    }
    
    if (external_port == 0) {
        external_port = local_port;
    }
    
    // Check if local port is listening
    int test_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (test_sock >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(local_port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(test_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("\n");
            printf("  ⚠️  Warning: Nothing seems to be listening on port %u\n", local_port);
            printf("     Make sure your server is running!\n\n");
        }
        close(test_sock);
    }
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("║  🏠 SPF Host - Self-Host From Home (NO VPS NEEDED!)                  ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                      ║\n");
    printf("║  Local Port: %-5u                                                   ║\n", local_port);
    printf("║  External Port: %-5u                                                ║\n", external_port);
    if (domain) {
        printf("║  Domain: %-30s                        ║\n", domain);
    }
    if (cert && key) {
        printf("║  TLS: Enabled (HTTPS)                                                ║\n");
    }
    printf("║                                                                      ║\n");
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);
    
    // Initialize security module
    spf_security_init();
    printf("║  🔒 Security: ENABLED (strict home-hosting mode)                     ║\n");
    
    // Initialize UPnP and open port on router
    char external_ip[SPF_IP_MAX_LEN] = {0};
    char local_ip[SPF_IP_MAX_LEN] = {0};
    
    if (!no_upnp) {
        printf("║                                                                      ║\n");
        printf("║  🔌 Discovering router...                                            ║\n");
        
        if (spf_upnp_init() == 0) {
            g_upnp_enabled = true;
            spf_upnp_get_external_ip(external_ip, sizeof(external_ip));
            spf_upnp_get_local_ip(local_ip, sizeof(local_ip));
            
            printf("║     Router found: %s                                      ║\n", spf_upnp_type_str());
            printf("║     Local IP: %-15s                                      ║\n", local_ip);
            printf("║     External IP: %-15s                                   ║\n", external_ip);
            
            // Open port
            char desc[64];
            snprintf(desc, sizeof(desc), "SPF Host Port %u", external_port);
            if (spf_upnp_add_port(external_port, local_port, "TCP", desc) == 0) {
                printf("║     ✅ Port %u opened on router!                                    ║\n", external_port);
            } else {
                printf("║     ⚠️  Could not open port (may need manual config)                ║\n");
            }
        } else {
            printf("║     ⚠️  No UPnP router found - configure port forwarding manually    ║\n");
        }
    }
    
    // Initialize DDNS
    if (!no_ddns && ddns_provider && ddns_token) {
        printf("║                                                                      ║\n");
        printf("║  🌐 Setting up Dynamic DNS...                                        ║\n");
        
        spf_ddns_provider_t provider = spf_ddns_parse_provider(ddns_provider);
        if (provider != SPF_DDNS_NONE) {
            if (spf_ddns_init(provider, domain, ddns_token) == 0) {
                g_ddns_enabled = true;
                if (ddns_user && ddns_pass) {
                    spf_ddns_set_credentials(ddns_user, ddns_pass);
                }
                printf("║     ✅ DDNS configured: %s                                  ║\n", ddns_provider);
            }
        } else {
            printf("║     ⚠️  Unknown DDNS provider: %s                                 ║\n", ddns_provider);
        }
    }
    
    printf("║                                                                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════╣\n");
    
    if (external_ip[0] && domain) {
        printf("║  🌍 Your site is now accessible at:                                  ║\n");
        if (cert && key) {
            printf("║     https://%s                                        ║\n", domain);
        } else {
            printf("║     http://%s                                         ║\n", domain);
        }
    } else if (external_ip[0]) {
        printf("║  🌍 Your site is now accessible at:                                  ║\n");
        if (cert && key) {
            printf("║     https://%s:%u                                          ║\n", external_ip, external_port);
        } else {
            printf("║     http://%s:%u                                           ║\n", external_ip, external_port);
        }
    } else {
        printf("║  🌍 Configure your router to forward port %u to this machine        ║\n", external_port);
    }
    
    printf("║                                                                      ║\n");
    printf("║  Press Ctrl+C to stop (port mapping will be removed)                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Initialize TLS if certs provided
    if (cert && key) {
        if (tls_init(cert, key) == 0) {
            spf_log(SPF_LOG_INFO, "host: TLS enabled");
        }
    }
    
    // Initialize main state and create forwarding rule
    spf_init(&g_state);
    spf_hooks_init();
    spf_hooks_autodiscover();
    
    // Create rule to forward external:port -> localhost:local_port
    spf_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    rule.id = 1;
    rule.listen_port = local_port;  // We listen on local port
    rule.enabled = true;
    rule.active = true;
    rule.tls_terminate = (cert && key);
    rule.lb_algo = SPF_LB_ROUNDROBIN;
    rule.max_conns = 1000;
    rule.accept_rate = 200;
    spf_bucket_init(&rule.accept_bucket, rule.accept_rate, 2.0);
    
    // Backend is localhost (the user's app)
    strncpy(rule.backends[0].host, "127.0.0.1", SPF_IP_MAX_LEN - 1);
    rule.backends[0].port = local_port;
    rule.backends[0].weight = 1;
    rule.backends[0].state = SPF_BACKEND_UP;
    rule.backend_count = 1;
    
    if (spf_add_rule(&g_state, &rule) == 0) {
        spf_rule_t* added = spf_get_rule(&g_state, rule.id);
        if (added) {
            pthread_create(&added->listen_thread, NULL, listener_thread, added);
            pthread_detach(added->listen_thread);
        }
    }
    
    // Main loop
    while (!g_shutdown && g_state.running) {
        sleep(1);
    }
    
    // Cleanup
    printf("\n");
    spf_log(SPF_LOG_INFO, "host: shutting down...");
    
    if (g_upnp_enabled) {
        spf_log(SPF_LOG_INFO, "host: removing port mapping...");
        spf_upnp_remove_port(external_port, "TCP");
        spf_upnp_cleanup();
    }
    
    if (g_ddns_enabled) {
        spf_ddns_cleanup();
    }
    
    spf_security_cleanup();
    spf_hooks_cleanup();
    tls_cleanup();
    spf_shutdown(&g_state);
    
    printf("  ✅ Cleanup complete. Port mapping removed.\n\n");
    
    return 0;
}

#endif
