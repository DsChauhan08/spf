#include "common.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

static int g_metrics_fd = -1;
static pthread_t g_metrics_thread;
static volatile bool g_metrics_running = false;

typedef struct {
    const char* name;
    const char* help;
    const char* type;
} metric_def_t;

static const metric_def_t metrics[] = {
    {"spf_connections_active", "Current active connections", "gauge"},
    {"spf_connections_total", "Total connections since start", "counter"},
    {"spf_bytes_in_total", "Total bytes received", "counter"},
    {"spf_bytes_out_total", "Total bytes sent", "counter"},
    {"spf_blocked_total", "Total blocked IPs", "counter"},
    {"spf_rules_active", "Active forwarding rules", "gauge"},
    {"spf_uptime_seconds", "Uptime in seconds", "counter"},
    {NULL, NULL, NULL}
};

int metrics_format(spf_state_t* state, char* buf, size_t len) {
    int written = 0;
    uint64_t uptime = spf_time_sec() - state->start_time;
    
    for (int i = 0; metrics[i].name; i++) {
        written += snprintf(buf + written, len - written,
            "# HELP %s %s\n# TYPE %s %s\n",
            metrics[i].name, metrics[i].help,
            metrics[i].name, metrics[i].type);
    }
    
    written += snprintf(buf + written, len - written,
        "spf_connections_active %u\n"
        "spf_connections_total %lu\n"
        "spf_bytes_in_total %lu\n"
        "spf_bytes_out_total %lu\n"
        "spf_blocked_total %lu\n"
        "spf_rules_active %u\n"
        "spf_uptime_seconds %lu\n",
        state->active_conns,
        state->total_conns,
        state->total_bytes_in,
        state->total_bytes_out,
        state->blocked_count,
        state->rule_count,
        uptime);
    
    for (int i = 0; i < SPF_MAX_RULES; i++) {
        if (state->rules[i].active) {
            spf_rule_t* r = &state->rules[i];
            for (int j = 0; j < r->backend_count; j++) {
                spf_backend_t* b = &r->backends[j];
                written += snprintf(buf + written, len - written,
                    "spf_backend_up{rule=\"%u\",backend=\"%s:%u\"} %d\n"
                    "spf_backend_conns{rule=\"%u\",backend=\"%s:%u\"} %u\n",
                    r->id, b->host, b->port, b->state == SPF_BACKEND_UP ? 1 : 0,
                    r->id, b->host, b->port, b->active_conns);
            }
        }
    }
    
    return written;
}

static void handle_metrics_request(int fd, spf_state_t* state) {
    char req[1024];
    ssize_t n = recv(fd, req, sizeof(req), 0);
    if (n <= 0) {
        close(fd);
        return;
    }
    
    char body[8192];
    int body_len = metrics_format(state, body, sizeof(body));
    
    char resp[8192 + 256];
    int resp_len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        body_len, body);
    
    send(fd, resp, resp_len, 0);
    close(fd);
}

static void* metrics_worker(void* arg) {
    spf_state_t* state = (spf_state_t*)arg;
    
    g_metrics_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_metrics_fd < 0) return NULL;
    
    int opt = 1;
    setsockopt(g_metrics_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(state->config.metrics.port);
    
    if (bind(g_metrics_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "metrics: bind failed");
        close(g_metrics_fd);
        return NULL;
    }
    
    listen(g_metrics_fd, 5);
    spf_log(SPF_LOG_INFO, "metrics: listening on :%u", state->config.metrics.port);
    
    while (g_metrics_running && state->running) {
        // Check FD_SETSIZE limit
        if (g_metrics_fd >= FD_SETSIZE) {
            spf_log(SPF_LOG_ERROR, "metrics: fd >= FD_SETSIZE");
            break;
        }
        
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_metrics_fd, &fds);
        struct timeval tv = {1, 0};
        
        if (select(g_metrics_fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        
        int client = accept(g_metrics_fd, NULL, NULL);
        if (client >= 0) {
            handle_metrics_request(client, state);
        }
    }
    
    close(g_metrics_fd);
    return NULL;
}

int metrics_start(spf_state_t* state) {
    if (!state->config.metrics.enabled) {
        spf_log(SPF_LOG_INFO, "metrics: disabled");
        return 0;
    }
    
    g_metrics_running = true;
    return pthread_create(&g_metrics_thread, NULL, metrics_worker, state);
}

void metrics_stop(void) {
    g_metrics_running = false;
    if (g_metrics_fd >= 0) {
        close(g_metrics_fd);
        g_metrics_fd = -1;
    }
    pthread_join(g_metrics_thread, NULL);
}

int metrics_to_json(spf_state_t* state, char* buf, size_t len) {
    uint64_t uptime = spf_time_sec() - state->start_time;
    
    return snprintf(buf, len,
        "{"
        "\"active_conns\":%u,"
        "\"total_conns\":%lu,"
        "\"bytes_in\":%lu,"
        "\"bytes_out\":%lu,"
        "\"blocked\":%lu,"
        "\"rules\":%u,"
        "\"uptime\":%lu"
        "}",
        state->active_conns,
        state->total_conns,
        state->total_bytes_in,
        state->total_bytes_out,
        state->blocked_count,
        state->rule_count,
        uptime);
}
