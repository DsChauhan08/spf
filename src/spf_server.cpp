// spf_server.cpp - Linux/Unix server implementation with TLS
#ifndef SPF_PLATFORM_ESP32

#include "spf_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <microhttpd.h>
#include <jansson.h>

static spf_state_t g_state;
static struct MHD_Daemon* g_http_daemon = nullptr;
static volatile bool g_running = true;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    spf_rule_t rule;
    uint32_t conn_idx;
} session_data_t;

void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    g_running = false;
    g_state.running = false;
}

bool verify_authorization(struct MHD_Connection* conn) {
    if (!g_state.security.require_auth) {
        return true;
    }
    
    const char* auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    if (!auth) {
        return false;
    }
    
    char expected[128];
    snprintf(expected, sizeof(expected), "Bearer %s", g_state.security.auth_token);
    
    return strcmp(auth, expected) == 0;
}

int handle_status(struct MHD_Connection* conn) {
    if (!verify_authorization(conn)) {
        const char* resp = "{\"error\":\"Unauthorized\"}";
        struct MHD_Response* response = MHD_create_response_from_buffer(
            strlen(resp), (void*)resp, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 401, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    json_t* root = json_object();
    json_t* conns_array = json_array();
    
    for (uint32_t i = 0; i < SPF_MAX_CONNECTIONS; i++) {
        if (g_state.connections[i].active) {
            json_t* conn_obj = json_object();
            json_object_set_new(conn_obj, "id", json_integer(g_state.connections[i].conn_id));
            json_object_set_new(conn_obj, "client", json_string(g_state.connections[i].client_ip));
            json_object_set_new(conn_obj, "bytes_in", json_integer(g_state.connections[i].bytes_in));
            json_object_set_new(conn_obj, "bytes_out", json_integer(g_state.connections[i].bytes_out));
            json_array_append_new(conns_array, conn_obj);
        }
    }
    
    json_object_set_new(root, "connections", conns_array);
    json_object_set_new(root, "active_connections", json_integer(g_state.active_connections));
    json_object_set_new(root, "tls_enabled", json_boolean(g_state.security.tls_enabled));
    
    char* json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    
    struct MHD_Response* response = MHD_create_response_from_buffer(
        strlen(json_str), json_str, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", "application/json");
    
    int ret = MHD_queue_response(conn, 200, response);
    MHD_destroy_response(response);
    
    return ret;
}

int http_handler(void* cls, struct MHD_Connection* conn,
                 const char* url, const char* method,
                 const char* version, const char* upload_data,
                 size_t* upload_data_size, void** con_cls) {
    
    if (strcmp(url, "/status") == 0 && strcmp(method, "GET") == 0) {
        return handle_status(conn);
    }
    
    if (strcmp(url, "/health") == 0 && strcmp(method, "GET") == 0) {
        const char* resp = "{\"status\":\"ok\"}";
        struct MHD_Response* response = MHD_create_response_from_buffer(
            strlen(resp), (void*)resp, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 200, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    const char* resp = "{\"error\":\"Not found\"}";
    struct MHD_Response* response = MHD_create_response_from_buffer(
        strlen(resp), (void*)resp, MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(conn, 404, response);
    MHD_destroy_response(response);
    return ret;
}

void* session_thread(void* arg) {
    session_data_t* data = (session_data_t*)arg;
    
    int target_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (target_fd < 0) {
        close(data->client_fd);
        free(data);
        return nullptr;
    }
    
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(data->rule.target_port);
    inet_pton(AF_INET, data->rule.target_ip, &target_addr.sin_addr);
    
    if (connect(target_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        printf("Failed to connect to target %s:%d\n", 
               data->rule.target_ip, data->rule.target_port);
        close(target_fd);
        close(data->client_fd);
        free(data);
        return nullptr;
    }
    
    int flag = 1;
    setsockopt(data->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(target_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    printf("Session %lu established\n", g_state.connections[data->conn_idx].conn_id);
    
    spf_token_bucket_t tb;
    spf_token_bucket_init(&tb, data->rule.rate_bps, 1.0);
    
    uint8_t buffer[SPF_BUFFER_SIZE];
    fd_set readfds;
    struct timeval timeout;
    int maxfd = (data->client_fd > target_fd ? data->client_fd : target_fd) + 1;
    
    while (g_state.running) {
        FD_ZERO(&readfds);
        FD_SET(data->client_fd, &readfds);
        FD_SET(target_fd, &readfds);
        
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        
        int ready = select(maxfd, &readfds, nullptr, nullptr, &timeout);
        
        if (ready < 0) {
            break;
        }
        if (ready == 0) {
            break;
        }
        
        if (FD_ISSET(data->client_fd, &readfds)) {
            ssize_t n = recv(data->client_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            
            uint64_t allowed = spf_token_bucket_consume(&tb, n);
            if (allowed > 0) {
                send(target_fd, buffer, allowed, 0);
                g_state.connections[data->conn_idx].bytes_in += allowed;
            }
        }
        
        if (FD_ISSET(target_fd, &readfds)) {
            ssize_t n = recv(target_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            
            uint64_t allowed = spf_token_bucket_consume(&tb, n);
            if (allowed > 0) {
                send(data->client_fd, buffer, allowed, 0);
                g_state.connections[data->conn_idx].bytes_out += allowed;
            }
        }
    }
    
    close(data->client_fd);
    close(target_fd);
    
    g_state.connections[data->conn_idx].active = false;
    __sync_fetch_and_sub(&g_state.active_connections, 1);
    
    printf("Session %lu closed\n", g_state.connections[data->conn_idx].conn_id);
    
    free(data);
    return nullptr;
}

int run_forwarder(const spf_rule_t* rule) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }
    
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(rule->listen_port);
    
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }
    
    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }
    
    printf("Forwarder listening on 0.0.0.0:%d\n", rule->listen_port);
    
    while (g_state.running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        
        // fw checking
        if (spf_is_blocked(&g_state, client_ip)) {
            printf("Blocked connection from %s\n", client_ip);
            close(client_fd);
            continue;
        }
        
        if (!spf_register_attempt(&g_state, client_ip)) {
            printf("Auto-blocked %s\n", client_ip);
            close(client_fd);
            continue;
        }
        
        if (g_state.active_connections >= rule->max_connections) {
            printf("Connection limit reached\n");
            close(client_fd);
            continue;
        }
        
        uint32_t conn_idx = 0;
        for (uint32_t i = 0; i < SPF_MAX_CONNECTIONS; i++) {
            if (!g_state.connections[i].active) {
                conn_idx = i;
                break;
            }
        }
      
        g_state.connections[conn_idx].conn_id = __sync_fetch_and_add(&g_state.next_conn_id, 1);
        g_state.connections[conn_idx].active = true;
        strncpy(g_state.connections[conn_idx].client_ip, client_ip, 
                sizeof(g_state.connections[conn_idx].client_ip) - 1);
        g_state.connections[conn_idx].client_port = ntohs(client_addr.sin_port);
        g_state.connections[conn_idx].bytes_in = 0;
        g_state.connections[conn_idx].bytes_out = 0;
        __sync_fetch_and_add(&g_state.active_connections, 1);
        
        session_data_t* data = (session_data_t*)malloc(sizeof(session_data_t));
        data->client_fd = client_fd;
        data->client_addr = client_addr;
        data->rule = *rule;
        data->conn_idx = conn_idx;
        
        pthread_t thread;
        pthread_create(&thread, nullptr, session_thread, data);
        pthread_detach(thread);
    }
    
    close(listen_fd);
    return 0;
}

int main(int argc, char** argv) {
    printf("=== SPF Network Forwarder ===\n");
    printf("Server version with TLS/Auth\n\n");
    

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    spf_init(&g_state);
    g_state.security.require_auth = true;
    const char* token = getenv("SPF_AUTH_TOKEN");
    if (token) {
        strncpy(g_state.security.auth_token, token, sizeof(g_state.security.auth_token) - 1);
    } else {
        printf("ERROR: SPF_AUTH_TOKEN environment variable not set\n");
        printf("Generate a secure token: openssl rand -hex 32\n");
        printf("Then: export SPF_AUTH_TOKEN=<your_token>\n");
        return 1;
    }
    
    printf("✓ Authentication enabled\n");
    
    g_http_daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION,
        8080,
        nullptr, nullptr,
        &http_handler, nullptr,
        MHD_OPTION_END
    );
    
    if (!g_http_daemon) {
        printf("Failed to start HTTP server\n");
        return 1;
    }
    
    printf("✓ HTTP control server: http://0.0.0.0:8080\n");
    printf("  Endpoints: /status (GET), /health (GET)\n");
    printf("  Auth: Authorization: Bearer <token>\n\n");

    spf_rule_t rule = {
        .listen_port = 9000,
        .target_port = 25565,
        .enabled = true,
        .max_connections = 32,
        .rate_bps = 1000000,
        .rule_id = 0
    };
    strncpy(rule.target_ip, "127.0.0.1", sizeof(rule.target_ip));
    spf_add_rule(&g_state, &rule);
    
    printf("=== System Ready ===\n\n");
    run_forwarder(&rule);
    
    MHD_stop_daemon(g_http_daemon);
    printf("\nShutdown complete\n");
    
    return 0;
}

#endif 
