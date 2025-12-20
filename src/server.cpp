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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static spf_state_t g_state;
static int g_ctrl_fd = -1;
static volatile sig_atomic_t g_shutdown = 0;

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

static SSL_CTX* g_ssl_ctx = NULL;

void sig_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

int tls_init(const char* cert, const char* key) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ssl_ctx) return -1;
    
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    
    if (cert && key && access(cert, R_OK) == 0) {
        if (SSL_CTX_use_certificate_file(g_ssl_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
            SSL_CTX_free(g_ssl_ctx);
            g_ssl_ctx = NULL;
            return -1;
        }
        if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
            SSL_CTX_free(g_ssl_ctx);
            g_ssl_ctx = NULL;
            return -1;
        }
    }
    
    return 0;
}

void tls_cleanup(void) {
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    EVP_cleanup();
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
                n = SSL_read(s->client_ssl, buf, sizeof(buf));
            } else {
                n = recv(s->client_fd, buf, sizeof(buf), 0);
            }
            if (n <= 0) break;
            
            uint64_t allowed = spf_bucket_consume(&bucket, n);
            if (allowed > 0) {
                if (s->target_ssl) {
                    SSL_write(s->target_ssl, buf, allowed);
                } else {
                    send(s->target_fd, buf, allowed, 0);
                }
                bytes_in += allowed;
            }
        }
        
        if (FD_ISSET(s->target_fd, &fds)) {
            ssize_t n;
            if (s->target_ssl) {
                n = SSL_read(s->target_ssl, buf, sizeof(buf));
            } else {
                n = recv(s->target_fd, buf, sizeof(buf), 0);
            }
            if (n <= 0) break;
            
            uint64_t allowed = spf_bucket_consume(&bucket, n);
            if (allowed > 0) {
                if (s->client_ssl) {
                    SSL_write(s->client_ssl, buf, allowed);
                } else {
                    send(s->client_fd, buf, allowed, 0);
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
    
    free(s);
    return NULL;
}

void* health_worker(void* arg) {
    spf_rule_t* rule = (spf_rule_t*)arg;
    
    while (!g_shutdown && g_state.running && rule->active) {
        for (int i = 0; i < rule->backend_count; i++) {
            spf_backend_t* b = &rule->backends[i];
            if (b->state == SPF_BACKEND_DRAIN) continue;
            
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;
            
            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(b->port);
            inet_pton(AF_INET, b->host, &addr.sin_addr);
            
            int ok = connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0;
            close(fd);
            
            pthread_mutex_lock(&b->lock);
            if (ok) {
                if (b->state == SPF_BACKEND_DOWN) {
                    b->state = SPF_BACKEND_UP;
                    spf_event_push(&g_state, SPF_EVENT_HEALTH_UP, b->host, b->port, rule->id, "backend recovered");
                    spf_log(SPF_LOG_INFO, "backend %s:%u up", b->host, b->port);
                }
                b->health_fails = 0;
            } else {
                b->health_fails++;
                if (b->health_fails >= 3 && b->state == SPF_BACKEND_UP) {
                    b->state = SPF_BACKEND_DOWN;
                    spf_event_push(&g_state, SPF_EVENT_HEALTH_DOWN, b->host, b->port, rule->id, "health check failed");
                    spf_log(SPF_LOG_WARN, "backend %s:%u down", b->host, b->port);
                }
            }
            b->last_health_check = spf_time_sec();
            pthread_mutex_unlock(&b->lock);
        }
        
        sleep(SPF_HEALTH_INTERVAL_MS / 1000);
    }
    
    return NULL;
}

void* listener_thread(void* arg) {
    spf_rule_t* rule = (spf_rule_t*)arg;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
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
    
    pthread_create(&rule->health_thread, NULL, health_worker, rule);
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
        
        char cli_ip[SPF_IP_MAX_LEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, cli_ip, sizeof(cli_ip));
        
        if (spf_is_blocked(&g_state, cli_ip)) {
            close(cli_fd);
            continue;
        }
        
        if (!spf_register_attempt(&g_state, cli_ip)) {
            close(cli_fd);
            continue;
        }
        
        if (g_state.config.security.enabled && spf_geoip_is_blocked(&g_state, cli_ip)) {
            spf_event_push(&g_state, SPF_EVENT_GEOBLOCK, cli_ip, ntohs(cli_addr.sin_port), rule->id, "geo blocked");
            close(cli_fd);
            continue;
        }
        
        int backend_idx = spf_lb_select_backend(rule, cli_ip);
        if (backend_idx < 0) {
            spf_log(SPF_LOG_WARN, "no healthy backend for rule %u", rule->id);
            close(cli_fd);
            continue;
        }
        
        spf_backend_t* b = &rule->backends[backend_idx];
        
        int tgt_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tgt_fd < 0) {
            close(cli_fd);
            continue;
        }
        
        struct sockaddr_in tgt_addr = {0};
        tgt_addr.sin_family = AF_INET;
        tgt_addr.sin_port = htons(b->port);
        inet_pton(AF_INET, b->host, &tgt_addr.sin_addr);
        
        struct timeval tv_conn = {5, 0};
        setsockopt(tgt_fd, SOL_SOCKET, SO_SNDTIMEO, &tv_conn, sizeof(tv_conn));
        
        if (connect(tgt_fd, (struct sockaddr*)&tgt_addr, sizeof(tgt_addr)) < 0) {
            close(tgt_fd);
            close(cli_fd);
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
        
        session_t* sess = (session_t*)malloc(sizeof(session_t));
        if (!sess) {
            pthread_mutex_lock(&g_state.stats_lock);
            g_state.connections[conn_idx].active = false;
            g_state.active_conns--;
            pthread_mutex_unlock(&g_state.stats_lock);
            close(tgt_fd);
            close(cli_fd);
            continue;
        }
        sess->client_fd = cli_fd;
        sess->target_fd = tgt_fd;
        sess->client_ssl = NULL;
        sess->target_ssl = NULL;
        sess->client_addr = cli_addr;
        sess->rule = rule;
        sess->backend_idx = backend_idx;
        sess->conn_idx = conn_idx;
        
        if (rule->tls_terminate && g_ssl_ctx) {
            sess->client_ssl = SSL_new(g_ssl_ctx);
            SSL_set_fd(sess->client_ssl, cli_fd);
            if (SSL_accept(sess->client_ssl) <= 0) {
                SSL_free(sess->client_ssl);
                pthread_mutex_lock(&g_state.stats_lock);
                g_state.connections[conn_idx].active = false;
                g_state.active_conns--;
                pthread_mutex_unlock(&g_state.stats_lock);
                close(cli_fd);
                close(tgt_fd);
                free(sess);
                continue;
            }
        }
        
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
                "  ADD <port> <ip:port> [algo] - add rule\n"
                "  DEL <id>           - delete rule\n"
                "  BLOCK <ip> [sec]   - block ip\n"
                "  UNBLOCK <ip>       - unblock ip\n"
                "  LOGS [n]           - recent events\n"
                "  METRICS            - prometheus\n"
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
            int parsed = sscanf(buf + 4, "%d %63s %15s", &port, backend, algo);
            
            if (parsed >= 2 && port > 0 && port < 65536) {
                spf_rule_t rule = {0};
                uint8_t rnd[4];
                spf_random_bytes(rnd, 4);
                rule.id = (*(uint32_t*)rnd) % 90000 + 10000;
                rule.listen_port = port;
                rule.enabled = true;
                rule.rate_bps = 100 * 1024 * 1024;
                
                if (strcmp(algo, "lc") == 0) rule.lb_algo = SPF_LB_LEASTCONN;
                else if (strcmp(algo, "ip") == 0) rule.lb_algo = SPF_LB_IPHASH;
                else if (strcmp(algo, "w") == 0) rule.lb_algo = SPF_LB_WEIGHTED;
                else rule.lb_algo = SPF_LB_ROUNDROBIN;
                
                char* tok = strtok(backend, ",");
                while (tok && rule.backend_count < SPF_MAX_BACKENDS) {
                    char* colon = strchr(tok, ':');
                    if (colon) {
                        *colon = '\0';
                        strncpy(rule.backends[rule.backend_count].host, tok, SPF_IP_MAX_LEN - 1);
                        rule.backends[rule.backend_count].port = atoi(colon + 1);
                        rule.backends[rule.backend_count].weight = 1;
                        rule.backends[rule.backend_count].state = SPF_BACKEND_UP;
                        rule.backend_count++;
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
                snprintf(resp, sizeof(resp), "ERR usage: ADD <port> <host:port,...> [rr|lc|ip|w]\n");
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
    
    struct sockaddr_in addr = {0};
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
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int main(int argc, char** argv) {
    char* bind_addr = NULL;
    char* token = NULL;
    char* cert = NULL;
    char* key = NULL;
    int port = SPF_CTRL_PORT_DEFAULT;
    bool daemon_mode = false;
    
    static struct option opts[] = {
        {"admin-bind", required_argument, 0, 'b'},
        {"admin-port", required_argument, 0, 'p'},
        {"token", required_argument, 0, 't'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"daemon", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "b:p:t:c:k:dh", opts, NULL)) != -1) {
        switch (c) {
            case 'b': bind_addr = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 't': token = optarg; break;
            case 'c': cert = optarg; break;
            case 'k': key = optarg; break;
            case 'd': daemon_mode = true; break;
            case 'h':
                printf("SPF v%s - Production Network Forwarder\n\n", SPF_VERSION);
                printf("Usage: %s [options]\n\n", argv[0]);
                printf("Options:\n");
                printf("  -b, --admin-bind <ip>  Bind address (default: 127.0.0.1)\n");
                printf("  -p, --admin-port <n>   Control port (default: 8081)\n");
                printf("  -t, --token <str>      Auth token (required for remote)\n");
                printf("  -c, --cert <path>      TLS certificate\n");
                printf("  -k, --key <path>       TLS private key\n");
                printf("  -d, --daemon           Run as daemon\n");
                printf("  -h, --help             Show this help\n");
                return 0;
        }
    }
    
    if (daemon_mode) daemonize();
    
    spf_init(&g_state);
    
    if (bind_addr) strncpy(g_state.config.admin.bind_addr, bind_addr, SPF_IP_MAX_LEN - 1);
    if (token) strncpy(g_state.config.admin.token, token, SPF_TOKEN_MAX - 1);
    if (cert) strncpy(g_state.config.admin.cert_path, cert, SPF_PATH_MAX - 1);
    if (key) strncpy(g_state.config.admin.key_path, key, SPF_PATH_MAX - 1);
    g_state.config.admin.port = port;
    
    if (cert && key) {
        if (tls_init(cert, key) == 0) {
            g_state.config.admin.tls_enabled = true;
            spf_log(SPF_LOG_INFO, "tls enabled");
        }
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
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
    }
    
    spf_log(SPF_LOG_INFO, "shutting down...");
    g_state.running = false;
    
    if (g_ctrl_fd >= 0) close(g_ctrl_fd);
    
    pthread_join(ct, NULL);
    tls_cleanup();
    spf_shutdown(&g_state);
    
    return 0;
}

#endif
