#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#if defined(ESP32) || defined(ESP_PLATFORM)
    #define SPF_PLATFORM_ESP32
#elif defined(_WIN32) || defined(_WIN64)
    #define SPF_PLATFORM_WINDOWS
#elif defined(__linux__)
    #define SPF_PLATFORM_LINUX
#elif defined(__APPLE__)
    #define SPF_PLATFORM_MACOS
#else
    #define SPF_PLATFORM_GENERIC
#endif

#define SPF_VERSION "2.0.0"

#define SPF_MAX_CONNECTIONS 4096
#define SPF_MAX_RULES 128
#define SPF_MAX_BACKENDS 16
#define SPF_MAX_IP_TRACKERS 8192
#define SPF_MAX_EVENTS 4096
#define SPF_MAX_BLOCKLIST 65536

#define SPF_BUFFER_SIZE 8192
#define SPF_CMD_MAX_LEN 512
#define SPF_RES_MAX_LEN 4096
#define SPF_IP_MAX_LEN 46
#define SPF_PATH_MAX 512
#define SPF_TOKEN_MAX 128

#define SPF_CTRL_PORT_DEFAULT 8081
#define SPF_METRICS_PORT_DEFAULT 9100

#define SPF_SCAN_THRESHOLD 10
#define SPF_SCAN_WINDOW_SEC 30
#define SPF_BLOCK_FIRST_SEC 600
#define SPF_BLOCK_SECOND_SEC 3600
#define SPF_BLOCK_PERMA_SEC 86400

#define SPF_HEALTH_INTERVAL_MS 5000
#define SPF_HEALTH_TIMEOUT_MS 2000

typedef enum {
    SPF_LB_ROUNDROBIN = 0,
    SPF_LB_LEASTCONN,
    SPF_LB_IPHASH,
    SPF_LB_WEIGHTED,
    SPF_LB_RANDOM
} spf_lb_algo_t;

typedef enum {
    SPF_BACKEND_UP = 0,
    SPF_BACKEND_DOWN,
    SPF_BACKEND_DRAIN
} spf_backend_state_t;

typedef enum {
    SPF_EVENT_CONN_OPEN = 0,
    SPF_EVENT_CONN_CLOSE,
    SPF_EVENT_AUTH_FAIL,
    SPF_EVENT_BLOCKED,
    SPF_EVENT_RATE_LIMITED,
    SPF_EVENT_HEALTH_DOWN,
    SPF_EVENT_HEALTH_UP,
    SPF_EVENT_GEOBLOCK,
    SPF_EVENT_THREAT_MATCH,
    SPF_EVENT_ANOMALY,
    SPF_EVENT_DDOS
} spf_event_type_t;

typedef enum {
    SPF_LOG_DEBUG = 0,
    SPF_LOG_INFO,
    SPF_LOG_WARN,
    SPF_LOG_ERROR,
    SPF_LOG_SECURITY
} spf_log_level_t;

typedef struct {
    char host[SPF_IP_MAX_LEN];
    uint16_t port;
    uint16_t weight;
    spf_backend_state_t state;
    uint32_t active_conns;
    uint64_t total_conns;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t last_health_check;
    uint8_t health_fails;
    bool tls_enabled;
    pthread_mutex_t lock;
} spf_backend_t;

typedef struct {
    uint64_t rate;
    uint64_t capacity;
    double tokens;
    uint64_t last_refill;
} spf_bucket_t;

typedef struct {
    uint32_t id;
    char name[64];
    uint16_t listen_port;
    bool enabled;
    bool active;
    bool tls_terminate;
    spf_lb_algo_t lb_algo;
    spf_backend_t backends[SPF_MAX_BACKENDS];
    uint8_t backend_count;
    uint32_t rr_index;
    uint64_t rate_bps;
    uint32_t max_conns;
    uint32_t accept_rate;      // connections per second limit (0 = unlimited)
    spf_bucket_t accept_bucket; // token bucket for accept throttling
    uint32_t active_conns;     // current active connections for this rule
    pthread_t listen_thread;
    pthread_t health_thread;
    pthread_mutex_t lock;
} spf_rule_t;

typedef struct {
    uint64_t id;
    char client_ip[SPF_IP_MAX_LEN];
    uint16_t client_port;
    uint32_t rule_id;
    uint8_t backend_idx;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t start_time;
    bool active;
    bool proxy_proto_sent;
} spf_conn_t;

typedef struct {
    char ip[SPF_IP_MAX_LEN];
    uint32_t count;
    uint64_t first_ts;
    uint64_t last_ts;
    uint8_t strikes;
    uint64_t block_until;
    bool blocked;
    uint64_t bytes_total;
    uint32_t conns_total;
} spf_tracker_t;

typedef struct {
    spf_event_type_t type;
    uint64_t timestamp;
    char src_ip[SPF_IP_MAX_LEN];
    uint16_t src_port;
    uint32_t rule_id;
    char details[256];
} spf_event_t;

typedef struct {
    char bind_addr[SPF_IP_MAX_LEN];
    uint16_t port;
    char token[SPF_TOKEN_MAX];
    bool tls_enabled;
    char cert_path[SPF_PATH_MAX];
    char key_path[SPF_PATH_MAX];
} spf_admin_cfg_t;

typedef struct {
    bool enabled;
    char countries_block[64][3];
    uint8_t country_count;
    char blocklist_urls[8][256];
    uint8_t blocklist_count;
    uint32_t rate_per_ip;
    uint32_t rate_global;
    char webhook_url[256];
    bool ddos_protection;
    bool proxy_proto;
    bool anomaly_detection;
} spf_security_cfg_t;

typedef struct {
    bool enabled;
    uint16_t port;
} spf_metrics_cfg_t;

typedef struct {
    spf_admin_cfg_t admin;
    spf_security_cfg_t security;
    spf_metrics_cfg_t metrics;
    char config_path[SPF_PATH_MAX];
    bool daemon_mode;
    spf_log_level_t log_level;
} spf_config_t;

typedef struct {
    uint32_t* ips;
    uint32_t count;
    uint32_t capacity;
    pthread_rwlock_t lock;
} spf_blocklist_t;

typedef struct {
    spf_event_t events[SPF_MAX_EVENTS];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    pthread_mutex_t lock;
} spf_event_log_t;

typedef struct {
    spf_rule_t rules[SPF_MAX_RULES];
    spf_conn_t connections[SPF_MAX_CONNECTIONS];
    spf_tracker_t trackers[SPF_MAX_IP_TRACKERS];
    spf_blocklist_t blocklist;
    spf_event_log_t events;
    spf_config_t config;
    uint32_t rule_count;
    uint32_t active_conns;
    uint64_t next_conn_id;
    uint64_t total_bytes_in;
    uint64_t total_bytes_out;
    uint64_t total_conns;
    uint64_t blocked_count;
    uint64_t start_time;
    volatile bool running;
    bool authenticated;
    pthread_mutex_t lock;
    pthread_mutex_t stats_lock;
} spf_state_t;

#ifdef __cplusplus
extern "C" {
#endif

extern spf_state_t g_state;

void spf_init(spf_state_t* state);
void spf_shutdown(spf_state_t* state);

int spf_add_rule(spf_state_t* state, const spf_rule_t* rule);
int spf_del_rule(spf_state_t* state, uint32_t rule_id);
spf_rule_t* spf_get_rule(spf_state_t* state, uint32_t rule_id);

bool spf_is_blocked(spf_state_t* state, const char* ip);
bool spf_register_attempt(spf_state_t* state, const char* ip);
void spf_block_ip(spf_state_t* state, const char* ip, uint64_t duration_sec);
void spf_unblock_ip(spf_state_t* state, const char* ip);

void spf_bucket_init(spf_bucket_t* tb, uint64_t rate, double burst);
uint64_t spf_bucket_consume(spf_bucket_t* tb, uint64_t want);

int spf_load_config(spf_state_t* state, const char* path);
int spf_reload_config(spf_state_t* state);

bool spf_verify_token(spf_state_t* state, const char* token);
void spf_generate_token(char* buf, size_t len);

void spf_log(spf_log_level_t level, const char* fmt, ...);
void spf_event_push(spf_state_t* state, spf_event_type_t type, const char* ip, uint16_t port, uint32_t rule_id, const char* details);
void spf_event_get_recent(spf_state_t* state, spf_event_t* out, uint32_t count, uint32_t* actual);

int spf_lb_select_backend(spf_rule_t* rule, const char* client_ip);
void spf_lb_conn_start(spf_rule_t* rule, uint8_t backend_idx);
void spf_lb_conn_end(spf_rule_t* rule, uint8_t backend_idx);

void* spf_health_worker(void* arg);
void spf_health_check_backend(spf_rule_t* rule, uint8_t idx);

int spf_blocklist_load(spf_blocklist_t* bl, const char* url);
bool spf_blocklist_contains(spf_blocklist_t* bl, const char* ip);

bool spf_geoip_is_blocked(spf_state_t* state, const char* ip);
int spf_geoip_init(const char* db_path);
void spf_geoip_cleanup(void);

int spf_webhook_alert(const char* url, const spf_event_t* event);

uint64_t spf_time_ms(void);
uint64_t spf_time_sec(void);
void spf_random_bytes(uint8_t* buf, size_t len);
uint32_t spf_hash_ip(const char* ip);

// TLS
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

int tls_init(const char* cert, const char* key);
void tls_cleanup(void);
SSL_CTX* tls_get_server_ctx(void);
SSL_CTX* tls_get_client_ctx(void);
SSL* tls_accept(int fd);
SSL* tls_connect(int fd, const char* hostname);
ssize_t tls_read(SSL* ssl, void* buf, size_t len);
ssize_t tls_write(SSL* ssl, const void* buf, size_t len);
void tls_close(SSL* ssl);
int tls_set_client_cert(const char* cert, const char* key);
int tls_require_client_cert(void);
const char* tls_get_cipher(SSL* ssl);
const char* tls_get_version(SSL* ssl);

#ifdef __cplusplus
}
#endif

#endif
