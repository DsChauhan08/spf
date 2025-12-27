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

#define SPF_VERSION "2.2.0"

// Protocol types - UDP support (rinetd/socat pain point: no UDP)
typedef enum {
    SPF_PROTO_TCP = 0,
    SPF_PROTO_UDP
} spf_proto_t;

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
    spf_proto_t protocol;          // TCP or UDP
    spf_backend_t backends[SPF_MAX_BACKENDS];
    uint8_t backend_count;
    uint32_t drain_timeout_sec;   // Connection draining timeout (cloud LB feature)
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
    char hooks_dir[SPF_PATH_MAX];  // Custom security hooks directory
    char access_log[SPF_PATH_MAX]; // Access log file path
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

// Hook system (Linux-way extensibility)
typedef enum {
    SPF_HOOK_ON_CONNECT = 0,
    SPF_HOOK_ON_DISCONNECT,
    SPF_HOOK_ON_BLOCK,
    SPF_HOOK_ON_HEALTH,
    SPF_HOOK_COUNT
} spf_hook_type_t;

void spf_hooks_init(void);
void spf_hooks_cleanup(void);
void spf_hooks_set_dir(const char* dir);
int spf_hooks_add(spf_hook_type_t type, const char* path, bool async, uint32_t timeout_ms);
int spf_hooks_autodiscover(void);
int spf_hooks_run(spf_hook_type_t type, const char* client_ip, uint16_t client_port,
                  uint32_t rule_id, const char* backend_ip, uint16_t backend_port);
int spf_hook_on_connect(const char* client_ip, uint16_t client_port,
                        uint32_t rule_id, const char* backend_ip, uint16_t backend_port);
void spf_hook_on_disconnect(const char* client_ip, uint16_t client_port,
                            uint32_t rule_id, const char* backend_ip, uint16_t backend_port);
void spf_hook_on_block(const char* client_ip, uint32_t rule_id, const char* reason);
void spf_hook_on_health(const char* backend_ip, uint16_t backend_port,
                        uint32_t rule_id, bool is_up);
int spf_hooks_get_info(char* buf, size_t len);

// DNS hostname resolution (rinetd pain point: only IPs)
int spf_resolve_hostname(const char* hostname, char* ip_out, size_t ip_len);

// Access logging (cloud LB feature)
void spf_access_log(const char* client_ip, uint16_t client_port, uint32_t rule_id,
                   const char* backend, uint64_t bytes_in, uint64_t bytes_out,
                   uint64_t duration_ms, int status);
int spf_access_log_init(const char* path);
void spf_access_log_close(void);

// ============================================================================
// UPnP / NAT-PMP - Automatic Router Port Forwarding (NO VPS NEEDED!)
// ============================================================================
// Automatically configures your router to forward ports
// Works with most home routers via UPnP IGD or NAT-PMP
//
// Usage:
//   spf_upnp_init();                                    // Discover router
//   spf_upnp_add_port(80, 8080, "TCP", "Web Server");  // Forward port

int spf_upnp_init(void);
int spf_upnp_add_port(uint16_t external_port, uint16_t internal_port,
                      const char* protocol, const char* description);
int spf_upnp_remove_port(uint16_t external_port, const char* protocol);
int spf_upnp_get_external_ip(char* out, size_t len);
int spf_upnp_get_local_ip(char* out, size_t len);
int spf_upnp_get_gateway_ip(char* out, size_t len);
bool spf_upnp_available(void);
const char* spf_upnp_type_str(void);
void spf_upnp_status(char* buf, size_t len);
void spf_upnp_cleanup(void);

// ============================================================================
// DDNS - Dynamic DNS Client (NO STATIC IP NEEDED!)
// ============================================================================
// Automatically updates your domain when your IP changes
// Supports: DuckDNS, No-IP, Cloudflare, FreeDNS, Dynu, Custom
//
// Usage:
//   spf_ddns_init(SPF_DDNS_DUCKDNS, "mydomain", "my-token");
//   // IP is now automatically updated every 5 minutes

typedef enum {
    SPF_DDNS_NONE = 0,
    SPF_DDNS_DUCKDNS,
    SPF_DDNS_NOIP,
    SPF_DDNS_CLOUDFLARE,
    SPF_DDNS_FREEDNS,
    SPF_DDNS_DYNU,
    SPF_DDNS_CUSTOM
} spf_ddns_provider_t;

typedef struct {
    spf_ddns_provider_t provider;
    char domain[256];
    char token[256];          // API token/key
    char username[128];       // For providers that need username
    char password[128];       // For providers that need password
    char custom_url[512];     // For custom provider
    char zone_id[64];         // For Cloudflare
    char record_id[64];       // For Cloudflare
    bool enabled;
} spf_ddns_config_t;

int spf_ddns_init(spf_ddns_provider_t provider, const char* domain, const char* token);
int spf_ddns_set_credentials(const char* username, const char* password);
int spf_ddns_set_cloudflare(const char* zone_id, const char* record_id);
int spf_ddns_set_custom_url(const char* url);
int spf_ddns_update_now(void);
int spf_ddns_get_ip(char* out, size_t len);
void spf_ddns_status(char* buf, size_t len);
spf_ddns_provider_t spf_ddns_parse_provider(const char* name);
void spf_ddns_cleanup(void);

// ============================================================================
// SECURITY MODULE - Enterprise-grade protection for home hosting
// ============================================================================
// Multiple layers of security to safely expose your home server
//
// Features:
//   - Per-IP rate limiting (DDoS protection)
//   - Private/Bogon IP blocking
//   - Connection limits
//   - Automatic brute-force detection
//   - HTTP request validation

void spf_security_init(void);
int spf_security_check_connection(const char* client_ip, uint16_t port, bool is_external);
void spf_security_connection_closed(const char* client_ip);
void spf_security_block_ip(const char* ip, time_t duration);
void spf_security_unblock_ip(const char* ip);
bool spf_security_is_blocked(const char* ip);
void spf_security_configure(bool block_private, bool block_bogons, bool strict,
                           uint32_t max_conn_per_ip, uint32_t rate_per_ip,
                           uint32_t global_rate);
void spf_security_status(char* buf, size_t len);
void spf_security_list_blocked(char* buf, size_t len);
void spf_security_cleanup(void);
int spf_security_check_http_request(const char* method, const char* path, size_t content_length);
void spf_security_add_headers(char* headers, size_t max_len);

// Advanced security features
int spf_security_check_payload(const char* data, size_t len);
void spf_security_track_slow(const char* ip, size_t bytes);
bool spf_security_is_slow_loris(const char* ip);
void spf_security_clear_slow(const char* ip);
int spf_security_check_user_agent(const char* ua);
void spf_security_update_fingerprint(const char* ip, bool is_error);
int spf_security_get_anomaly_score(const char* ip);

// ============================================================================
// SECURITY HARDENING - Privilege dropping, resource limits, memory protection
// ============================================================================
// Enterprise-grade OS-level security hardening
//
// Features:
//   - Privilege dropping after binding to ports
//   - Resource limits (prevent DoS via resource exhaustion)
//   - Disable core dumps (prevent credential leakage)
//   - Chroot support
//   - Secure memory allocation

int spf_hardening_init(void);
int spf_hardening_drop_privileges(void);
void spf_hardening_configure(const char* user, const char* group,
                            bool drop_privs, uint32_t max_files,
                            uint32_t max_mem_mb);
void spf_hardening_set_chroot(const char* path);
void spf_hardening_status(char* buf, size_t len);
void* spf_secure_alloc(size_t size);
void spf_secure_free(void* ptr, size_t size);
int spf_secure_compare(const void* a, const void* b, size_t len);
int spf_secure_validate_path(const char* path);

// ============================================================================
// SECURITY CONFIGURATION - User-configurable security parameters
// ============================================================================
// Allows users to customize all security settings via config file or CLI
//
// Usage:
//   spf_secconfig_load("/etc/spf/security.conf");
//   spf_secconfig_set("rate_limit_requests", "200");
//   spf_secconfig_set("sql_injection_check", "true");

typedef struct spf_security_config spf_security_config_t;

const spf_security_config_t* spf_secconfig_get(void);
int spf_secconfig_set(const char* key, const char* value);
int spf_secconfig_load(const char* path);
bool spf_secconfig_is_whitelisted(const char* ip);
bool spf_secconfig_is_blacklisted(const char* ip);
bool spf_secconfig_is_allowed_path(const char* path);
void spf_secconfig_dump(void);
void spf_secconfig_generate_example(const char* path);

#ifdef __cplusplus
}
#endif

#endif
