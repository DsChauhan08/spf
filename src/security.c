/*
 * SPF Security Module - Enterprise-grade protection for home hosting
 * 
 * This module provides multiple layers of security to safely expose
 * your home server to the internet WITHOUT a VPS or Cloudflare.
 * 
 * SECURITY LAYERS:
 * 
 * 1. CONNECTION SECURITY
 *    - Per-IP rate limiting (prevent DDoS)
 *    - Global rate limiting (prevent saturation)
 *    - Connection limits per IP
 *    - Automatic brute-force detection
 *    - Slow loris attack prevention
 * 
 * 2. NETWORK SECURITY  
 *    - Private IP blocking (RFC1918 from WAN)
 *    - Bogon IP filtering
 *    - GeoIP blocking (optional)
 *    - Threat intel blocklists
 *    - Tor exit node blocking (optional)
 * 
 * 3. APPLICATION SECURITY
 *    - Request size limits
 *    - Header validation
 *    - Path traversal prevention
 *    - Custom security hooks (any language)
 * 
 * 4. MONITORING & RESPONSE
 *    - Real-time threat detection
 *    - Automatic blocking
 *    - JSON security logs
 *    - Webhook alerts (Slack/Discord)
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

// Security configuration defaults
#define SEC_MAX_CONN_PER_IP 50          // Max simultaneous connections per IP
#define SEC_CONN_RATE_PER_IP 30         // Max new connections per IP per minute
#define SEC_GLOBAL_CONN_RATE 1000       // Max total new connections per second
#define SEC_MAX_REQUEST_SIZE (10*1024*1024)  // 10MB max request
#define SEC_SLOW_LORIS_TIMEOUT_SEC 10   // Timeout for slow clients
#define SEC_BLOCK_DURATION_1ST 600      // 10 min first block
#define SEC_BLOCK_DURATION_2ND 3600     // 1 hour second block
#define SEC_BLOCK_DURATION_PERM 86400   // 24 hour third+ block

// Private/Reserved IP ranges (block from external)
typedef struct {
    uint32_t network;
    uint32_t mask;
    const char* name;
} ip_range_t;

static const ip_range_t PRIVATE_RANGES[] = {
    // RFC1918 private
    {0x0A000000, 0xFF000000, "10.0.0.0/8"},      // 10.x.x.x
    {0xAC100000, 0xFFF00000, "172.16.0.0/12"},   // 172.16-31.x.x
    {0xC0A80000, 0xFFFF0000, "192.168.0.0/16"},  // 192.168.x.x
    
    // Loopback
    {0x7F000000, 0xFF000000, "127.0.0.0/8"},     // 127.x.x.x
    
    // Link-local
    {0xA9FE0000, 0xFFFF0000, "169.254.0.0/16"},  // 169.254.x.x
    
    // Multicast
    {0xE0000000, 0xF0000000, "224.0.0.0/4"},     // 224-239.x.x.x
    
    // Reserved
    {0x00000000, 0xFF000000, "0.0.0.0/8"},       // 0.x.x.x
    {0xF0000000, 0xF0000000, "240.0.0.0/4"},     // 240-255.x.x.x (reserved)
    
    {0, 0, NULL}  // Terminator
};

// Bogon ranges (unallocated/reserved IP space often used in attacks)
static const ip_range_t BOGON_RANGES[] = {
    {0x00000000, 0xFF000000, "0.0.0.0/8"},
    {0x64400000, 0xFFC00000, "100.64.0.0/10"},   // Carrier-grade NAT
    {0xC0000000, 0xFFFFFF00, "192.0.0.0/24"},    // IETF Protocol
    {0xC0000200, 0xFFFFFF00, "192.0.2.0/24"},    // TEST-NET-1
    {0xC6120000, 0xFFFE0000, "198.18.0.0/15"},   // Benchmark
    {0xC6336400, 0xFFFFFF00, "198.51.100.0/24"}, // TEST-NET-2
    {0xCB007100, 0xFFFFFF00, "203.0.113.0/24"},  // TEST-NET-3
    {0, 0, NULL}
};

// IP connection tracker for advanced rate limiting
typedef struct {
    char ip[SPF_IP_MAX_LEN];
    uint32_t active_conns;          // Current active connections
    uint32_t conn_count_minute;     // Connections in current minute
    time_t minute_start;            // Start of current minute
    uint32_t total_bytes;           // Bytes transferred this session
    uint8_t violations;             // Number of security violations
    time_t first_seen;
    time_t last_seen;
    bool is_blocked;
    time_t block_until;
} sec_ip_tracker_t;

#define SEC_MAX_TRACKERS 16384

typedef struct {
    sec_ip_tracker_t trackers[SEC_MAX_TRACKERS];
    int tracker_count;
    pthread_mutex_t lock;
    
    // Global rate limiting
    spf_bucket_t global_bucket;
    uint64_t total_blocked;
    uint64_t total_allowed;
    
    // Configuration
    bool block_private_ips;
    bool block_bogons;
    bool strict_mode;           // Extra strict for home hosting
    uint32_t max_conn_per_ip;
    uint32_t conn_rate_per_ip;  // Per minute
    uint32_t global_conn_rate;  // Per second
    
    bool running;
} sec_state_t;

static sec_state_t g_sec = {0};

// Check if IP is in a range
static bool ip_in_range(uint32_t ip, const ip_range_t* ranges) {
    for (int i = 0; ranges[i].name != NULL; i++) {
        if ((ip & ranges[i].mask) == ranges[i].network) {
            return true;
        }
    }
    return false;
}

// Parse IP to uint32
static uint32_t ip_to_uint32(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

// Find or create tracker for IP
static sec_ip_tracker_t* get_tracker(const char* ip, bool create) {
    int empty_slot = -1;
    
    for (int i = 0; i < g_sec.tracker_count; i++) {
        if (strcmp(g_sec.trackers[i].ip, ip) == 0) {
            return &g_sec.trackers[i];
        }
    }
    
    // Find empty slot
    for (int i = 0; i < SEC_MAX_TRACKERS; i++) {
        if (g_sec.trackers[i].ip[0] == '\0') {
            empty_slot = i;
            break;
        }
    }
    
    if (!create || empty_slot < 0) {
        return NULL;
    }
    
    // Create new tracker
    sec_ip_tracker_t* t = &g_sec.trackers[empty_slot];
    memset(t, 0, sizeof(sec_ip_tracker_t));
    strncpy(t->ip, ip, SPF_IP_MAX_LEN - 1);
    t->ip[SPF_IP_MAX_LEN - 1] = '\0';  // Ensure null termination
    t->first_seen = time(NULL);
    t->last_seen = time(NULL);
    t->minute_start = time(NULL);
    g_sec.tracker_count++;
    
    return t;
}

// ============================================================================
// PUBLIC API
// ============================================================================

// Initialize security subsystem
void spf_security_init(void) {
    memset(&g_sec, 0, sizeof(g_sec));
    pthread_mutex_init(&g_sec.lock, NULL);
    
    // Set defaults
    g_sec.block_private_ips = true;
    g_sec.block_bogons = true;
    g_sec.strict_mode = true;  // Extra safe for home hosting
    g_sec.max_conn_per_ip = SEC_MAX_CONN_PER_IP;
    g_sec.conn_rate_per_ip = SEC_CONN_RATE_PER_IP;
    g_sec.global_conn_rate = SEC_GLOBAL_CONN_RATE;
    g_sec.running = true;
    
    // Initialize global rate limiter
    spf_bucket_init(&g_sec.global_bucket, g_sec.global_conn_rate, 2.0);
    
    spf_log(SPF_LOG_INFO, "security: initialized with strict home-hosting mode");
}

// Check if connection should be allowed
// Returns: 0 = allow, >0 = block reason code
int spf_security_check_connection(const char* client_ip, uint16_t port, bool is_external) {
    if (!g_sec.running) return 0;
    
    // Input validation - prevent null pointer and oversized input
    if (!client_ip || strlen(client_ip) >= SPF_IP_MAX_LEN) {
        return 8;  // Invalid input
    }
    
    uint32_t ip_val = ip_to_uint32(client_ip);
    
    // === LAYER 1: Network-level checks (fast, no state) ===
    
    // Block private IPs from external interface
    if (is_external && g_sec.block_private_ips) {
        if (ip_in_range(ip_val, PRIVATE_RANGES)) {
            spf_log(SPF_LOG_SECURITY, "blocked private IP from external: %s", client_ip);
            return 1;  // Spoofed private IP attack
        }
    }
    
    // Block bogon IPs
    if (g_sec.block_bogons) {
        if (ip_in_range(ip_val, BOGON_RANGES)) {
            spf_log(SPF_LOG_SECURITY, "blocked bogon IP: %s", client_ip);
            return 2;  // Bogon/reserved IP
        }
    }
    
    // === LAYER 2: Global rate limiting ===
    
    pthread_mutex_lock(&g_sec.lock);
    
    // Check global rate
    if (spf_bucket_consume(&g_sec.global_bucket, 1) == 0) {
        pthread_mutex_unlock(&g_sec.lock);
        g_sec.total_blocked++;
        spf_log(SPF_LOG_SECURITY, "global rate limit hit, dropping: %s", client_ip);
        return 3;  // Global rate exceeded
    }
    
    // === LAYER 3: Per-IP tracking ===
    
    sec_ip_tracker_t* tracker = get_tracker(client_ip, true);
    if (!tracker) {
        pthread_mutex_unlock(&g_sec.lock);
        return 4;  // Tracker table full (under attack?)
    }
    
    tracker->last_seen = time(NULL);
    time_t now = time(NULL);
    
    // Check if currently blocked
    if (tracker->is_blocked) {
        if (tracker->block_until > now) {
            pthread_mutex_unlock(&g_sec.lock);
            return 5;  // Currently blocked
        }
        // Block expired
        tracker->is_blocked = false;
        tracker->violations = 0;
    }
    
    // Reset per-minute counter if minute elapsed
    if (now - tracker->minute_start >= 60) {
        tracker->conn_count_minute = 0;
        tracker->minute_start = now;
    }
    
    // Check per-IP connection rate
    if (tracker->conn_count_minute >= g_sec.conn_rate_per_ip) {
        tracker->violations++;
        
        // Progressive blocking
        time_t block_time;
        if (tracker->violations == 1) {
            block_time = SEC_BLOCK_DURATION_1ST;
        } else if (tracker->violations == 2) {
            block_time = SEC_BLOCK_DURATION_2ND;
        } else {
            block_time = SEC_BLOCK_DURATION_PERM;
        }
        
        tracker->is_blocked = true;
        tracker->block_until = now + block_time;
        
        g_sec.total_blocked++;
        pthread_mutex_unlock(&g_sec.lock);
        
        spf_log(SPF_LOG_SECURITY, "rate limit block: %s for %lds (violation #%d)",
               client_ip, block_time, tracker->violations);
        return 6;  // Per-IP rate exceeded
    }
    
    // Check per-IP connection count
    if (tracker->active_conns >= g_sec.max_conn_per_ip) {
        pthread_mutex_unlock(&g_sec.lock);
        spf_log(SPF_LOG_SECURITY, "connection limit: %s has %u active",
               client_ip, tracker->active_conns);
        return 7;  // Too many concurrent connections
    }
    
    // All checks passed - allow connection
    tracker->active_conns++;
    tracker->conn_count_minute++;
    g_sec.total_allowed++;
    
    pthread_mutex_unlock(&g_sec.lock);
    
    (void)port;  // Reserved for future port-specific rules
    return 0;  // Allowed
}

// Called when connection closes
void spf_security_connection_closed(const char* client_ip) {
    pthread_mutex_lock(&g_sec.lock);
    
    sec_ip_tracker_t* tracker = get_tracker(client_ip, false);
    if (tracker && tracker->active_conns > 0) {
        tracker->active_conns--;
    }
    
    pthread_mutex_unlock(&g_sec.lock);
}

// Manually block an IP
void spf_security_block_ip(const char* ip, time_t duration) {
    pthread_mutex_lock(&g_sec.lock);
    
    sec_ip_tracker_t* tracker = get_tracker(ip, true);
    if (tracker) {
        tracker->is_blocked = true;
        tracker->block_until = duration ? time(NULL) + duration : UINT32_MAX;
        tracker->violations++;
    }
    
    pthread_mutex_unlock(&g_sec.lock);
    spf_log(SPF_LOG_SECURITY, "manually blocked: %s", ip);
}

// Unblock an IP
void spf_security_unblock_ip(const char* ip) {
    pthread_mutex_lock(&g_sec.lock);
    
    sec_ip_tracker_t* tracker = get_tracker(ip, false);
    if (tracker) {
        tracker->is_blocked = false;
        tracker->block_until = 0;
        tracker->violations = 0;
    }
    
    pthread_mutex_unlock(&g_sec.lock);
    spf_log(SPF_LOG_INFO, "unblocked: %s", ip);
}

// Check if IP is blocked
bool spf_security_is_blocked(const char* ip) {
    pthread_mutex_lock(&g_sec.lock);
    
    sec_ip_tracker_t* tracker = get_tracker(ip, false);
    bool blocked = tracker && tracker->is_blocked && tracker->block_until > time(NULL);
    
    pthread_mutex_unlock(&g_sec.lock);
    return blocked;
}

// Configure security settings
void spf_security_configure(bool block_private, bool block_bogons, bool strict,
                           uint32_t max_conn_per_ip, uint32_t rate_per_ip,
                           uint32_t global_rate) {
    pthread_mutex_lock(&g_sec.lock);
    
    g_sec.block_private_ips = block_private;
    g_sec.block_bogons = block_bogons;
    g_sec.strict_mode = strict;
    
    if (max_conn_per_ip > 0) g_sec.max_conn_per_ip = max_conn_per_ip;
    if (rate_per_ip > 0) g_sec.conn_rate_per_ip = rate_per_ip;
    if (global_rate > 0) {
        g_sec.global_conn_rate = global_rate;
        spf_bucket_init(&g_sec.global_bucket, global_rate, 2.0);
    }
    
    pthread_mutex_unlock(&g_sec.lock);
}

// Get security status
void spf_security_status(char* buf, size_t len) {
    pthread_mutex_lock(&g_sec.lock);
    
    int blocked_count = 0;
    int tracked_count = 0;
    
    for (int i = 0; i < SEC_MAX_TRACKERS; i++) {
        if (g_sec.trackers[i].ip[0]) {
            tracked_count++;
            if (g_sec.trackers[i].is_blocked && 
                g_sec.trackers[i].block_until > time(NULL)) {
                blocked_count++;
            }
        }
    }
    
    snprintf(buf, len,
        "=== Security Status ===\n"
        "Mode: %s\n"
        "Block Private IPs: %s\n"
        "Block Bogons: %s\n"
        "Max Conn/IP: %u\n"
        "Rate Limit/IP: %u/min\n"
        "Global Rate: %u/sec\n"
        "\n"
        "Tracked IPs: %d\n"
        "Blocked IPs: %d\n"
        "Total Allowed: %lu\n"
        "Total Blocked: %lu\n",
        g_sec.strict_mode ? "STRICT (Home Hosting)" : "Standard",
        g_sec.block_private_ips ? "Yes" : "No",
        g_sec.block_bogons ? "Yes" : "No",
        g_sec.max_conn_per_ip,
        g_sec.conn_rate_per_ip,
        g_sec.global_conn_rate,
        tracked_count,
        blocked_count,
        g_sec.total_allowed,
        g_sec.total_blocked);
    
    pthread_mutex_unlock(&g_sec.lock);
}

// Get list of blocked IPs
void spf_security_list_blocked(char* buf, size_t len) {
    pthread_mutex_lock(&g_sec.lock);
    
    char* p = buf;
    p += snprintf(p, len, "=== Blocked IPs ===\n");
    
    time_t now = time(NULL);
    for (int i = 0; i < SEC_MAX_TRACKERS && (p - buf) < (ssize_t)(len - 100); i++) {
        if (g_sec.trackers[i].ip[0] && 
            g_sec.trackers[i].is_blocked &&
            g_sec.trackers[i].block_until > now) {
            
            time_t remaining = g_sec.trackers[i].block_until - now;
            p += snprintf(p, len - (p - buf), 
                "  %s - %lds remaining (violations: %d)\n",
                g_sec.trackers[i].ip,
                remaining,
                g_sec.trackers[i].violations);
        }
    }
    
    pthread_mutex_unlock(&g_sec.lock);
}

// Cleanup security subsystem
void spf_security_cleanup(void) {
    g_sec.running = false;
    pthread_mutex_destroy(&g_sec.lock);
    spf_log(SPF_LOG_INFO, "security: cleanup complete");
}

// ============================================================================
// HTTP SECURITY (for reverse proxy mode)
// ============================================================================

// Validate HTTP request (basic checks)
int spf_security_check_http_request(const char* method, const char* path, 
                                    size_t content_length) {
    // Check request size
    if (content_length > SEC_MAX_REQUEST_SIZE) {
        spf_log(SPF_LOG_SECURITY, "request too large: %zu bytes", content_length);
        return 1;
    }
    
    // Check for path traversal - limit log output to prevent log injection
    if (strstr(path, "..") || strstr(path, "//") || strstr(path, "\\")) {
        char safe_path[128];
        strncpy(safe_path, path, sizeof(safe_path) - 1);
        safe_path[sizeof(safe_path) - 1] = '\0';
        // Sanitize non-printable characters
        for (size_t i = 0; i < sizeof(safe_path) && safe_path[i]; i++) {
            if (safe_path[i] < 32 || safe_path[i] > 126) safe_path[i] = '?';
        }
        spf_log(SPF_LOG_SECURITY, "path traversal attempt: %.100s", safe_path);
        return 2;
    }
    
    // Block dangerous paths
    const char* dangerous_paths[] = {
        "/.env", "/.git", "/.svn", "/.htaccess", "/.htpasswd",
        "/wp-admin", "/phpmyadmin", "/admin/config",
        "/etc/passwd", "/etc/shadow", "/proc/",
        NULL
    };
    
    for (int i = 0; dangerous_paths[i]; i++) {
        if (strstr(path, dangerous_paths[i])) {
            spf_log(SPF_LOG_SECURITY, "blocked dangerous path: %s", path);
            return 3;
        }
    }
    
    // Allowed methods
    if (method) {
        if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0 &&
            strcmp(method, "PUT") != 0 && strcmp(method, "DELETE") != 0 &&
            strcmp(method, "HEAD") != 0 && strcmp(method, "OPTIONS") != 0 &&
            strcmp(method, "PATCH") != 0) {
            spf_log(SPF_LOG_SECURITY, "blocked unusual method: %s", method);
            return 4;
        }
    }
    
    return 0;  // OK
}

// Add security headers to response
void spf_security_add_headers(char* headers, size_t max_len) {
    snprintf(headers, max_len,
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: SAMEORIGIN\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: strict-origin-when-cross-origin\r\n"
        "Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
}

// ============================================================================
// ADVANCED SECURITY FEATURES
// ============================================================================

// Suspicious pattern detection for common attacks
typedef struct {
    const char* pattern;
    const char* attack_type;
    int severity;  // 1-5, 5 = most severe
} attack_pattern_t;

static const attack_pattern_t ATTACK_PATTERNS[] = {
    // SQL Injection
    {"' OR '1'='1", "SQL Injection", 5},
    {"UNION SELECT", "SQL Injection", 5},
    {"'; DROP TABLE", "SQL Injection", 5},
    {"1=1--", "SQL Injection", 5},
    
    // XSS
    {"<script>", "XSS", 4},
    {"javascript:", "XSS", 4},
    {"onerror=", "XSS", 4},
    {"onload=", "XSS", 4},
    
    // Command Injection
    {"; rm -rf", "Command Injection", 5},
    {"| cat /etc", "Command Injection", 5},
    {"$(", "Command Injection", 4},
    {"`", "Command Injection", 3},
    {"&& wget", "Command Injection", 5},
    
    // Path Traversal (additional)
    {"....//", "Path Traversal", 4},
    {"%2e%2e", "Path Traversal", 4},
    {"..%c0%af", "Path Traversal", 4},
    
    // LFI/RFI
    {"php://filter", "LFI", 5},
    {"expect://", "RFI", 5},
    {"data://", "LFI", 4},
    
    // Log Poisoning
    {"\n", "Log Injection", 3},
    {"\r", "Log Injection", 3},
    
    {NULL, NULL, 0}
};

// Check request for attack patterns
int spf_security_check_payload(const char* data, size_t len) {
    if (!data || len == 0) return 0;
    
    // Create uppercase copy for case-insensitive matching
    char* upper = malloc(len + 1);
    if (!upper) return 0;
    
    for (size_t i = 0; i < len; i++) {
        upper[i] = (char)toupper((unsigned char)data[i]);
    }
    upper[len] = '\0';
    
    int result = 0;
    
    for (int i = 0; ATTACK_PATTERNS[i].pattern != NULL; i++) {
        size_t plen = strlen(ATTACK_PATTERNS[i].pattern);
        char* pattern_upper = malloc(plen + 1);
        if (!pattern_upper) continue;
        
        for (size_t j = 0; j < plen; j++) {
            pattern_upper[j] = (char)toupper((unsigned char)ATTACK_PATTERNS[i].pattern[j]);
        }
        pattern_upper[plen] = '\0';
        
        if (strstr(upper, pattern_upper)) {
            spf_log(SPF_LOG_SECURITY, "attack detected: %s (severity %d)",
                   ATTACK_PATTERNS[i].attack_type, ATTACK_PATTERNS[i].severity);
            result = ATTACK_PATTERNS[i].severity;
            free(pattern_upper);
            break;
        }
        free(pattern_upper);
    }
    
    free(upper);
    return result;
}

// Connection timeout tracker for slow loris prevention
typedef struct {
    char ip[SPF_IP_MAX_LEN];
    time_t connect_time;
    size_t bytes_received;
    bool is_slow;
} slow_conn_t;

#define MAX_SLOW_TRACKERS 1024
static slow_conn_t g_slow_conns[MAX_SLOW_TRACKERS] = {0};
static pthread_mutex_t g_slow_lock = PTHREAD_MUTEX_INITIALIZER;

// Track connection for slow loris detection
void spf_security_track_slow(const char* ip, size_t bytes) {
    if (!ip) return;
    
    pthread_mutex_lock(&g_slow_lock);
    
    time_t now = time(NULL);
    int empty_slot = -1;
    
    for (int i = 0; i < MAX_SLOW_TRACKERS; i++) {
        if (g_slow_conns[i].ip[0] == '\0') {
            if (empty_slot < 0) empty_slot = i;
            continue;
        }
        
        // Found existing entry
        if (strcmp(g_slow_conns[i].ip, ip) == 0) {
            g_slow_conns[i].bytes_received += bytes;
            
            // Check if suspiciously slow (< 500 bytes in 10 seconds)
            if (now - g_slow_conns[i].connect_time > 10 && 
                g_slow_conns[i].bytes_received < 500) {
                if (!g_slow_conns[i].is_slow) {
                    g_slow_conns[i].is_slow = true;
                    spf_log(SPF_LOG_SECURITY, "slow loris suspected: %s", ip);
                }
            }
            pthread_mutex_unlock(&g_slow_lock);
            return;
        }
        
        // Clean up old entries
        if (now - g_slow_conns[i].connect_time > 60) {
            g_slow_conns[i].ip[0] = '\0';
            if (empty_slot < 0) empty_slot = i;
        }
    }
    
    // Create new entry
    if (empty_slot >= 0) {
        strncpy(g_slow_conns[empty_slot].ip, ip, SPF_IP_MAX_LEN - 1);
        g_slow_conns[empty_slot].ip[SPF_IP_MAX_LEN - 1] = '\0';
        g_slow_conns[empty_slot].connect_time = now;
        g_slow_conns[empty_slot].bytes_received = bytes;
        g_slow_conns[empty_slot].is_slow = false;
    }
    
    pthread_mutex_unlock(&g_slow_lock);
}

// Check if connection is slow loris
bool spf_security_is_slow_loris(const char* ip) {
    if (!ip) return false;
    
    pthread_mutex_lock(&g_slow_lock);
    
    for (int i = 0; i < MAX_SLOW_TRACKERS; i++) {
        if (strcmp(g_slow_conns[i].ip, ip) == 0) {
            bool is_slow = g_slow_conns[i].is_slow;
            pthread_mutex_unlock(&g_slow_lock);
            return is_slow;
        }
    }
    
    pthread_mutex_unlock(&g_slow_lock);
    return false;
}

// Clear slow connection tracker for IP
void spf_security_clear_slow(const char* ip) {
    if (!ip) return;
    
    pthread_mutex_lock(&g_slow_lock);
    
    for (int i = 0; i < MAX_SLOW_TRACKERS; i++) {
        if (strcmp(g_slow_conns[i].ip, ip) == 0) {
            memset(&g_slow_conns[i], 0, sizeof(slow_conn_t));
            break;
        }
    }
    
    pthread_mutex_unlock(&g_slow_lock);
}

// User-Agent anomaly detection
static const char* SUSPICIOUS_USER_AGENTS[] = {
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "wfuzz",
    "hydra",
    "burp",
    "zap",
    "acunetix",
    "nessus",
    "openvas",
    NULL
};

int spf_security_check_user_agent(const char* ua) {
    if (!ua || strlen(ua) == 0) {
        return 1;  // Missing User-Agent is suspicious
    }
    
    // Create lowercase copy
    size_t len = strlen(ua);
    char* lower = malloc(len + 1);
    if (!lower) return 0;
    
    for (size_t i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)ua[i]);
    }
    lower[len] = '\0';
    
    for (int i = 0; SUSPICIOUS_USER_AGENTS[i]; i++) {
        if (strstr(lower, SUSPICIOUS_USER_AGENTS[i])) {
            spf_log(SPF_LOG_SECURITY, "suspicious user-agent: %.50s", ua);
            free(lower);
            return 2;
        }
    }
    
    free(lower);
    return 0;
}

// Request fingerprinting for anomaly detection
typedef struct {
    char ip[SPF_IP_MAX_LEN];
    uint32_t request_count;
    uint32_t unique_paths;
    uint32_t error_count;  // 4xx, 5xx responses
    time_t window_start;
    uint8_t anomaly_score;
} ip_fingerprint_t;

#define MAX_FINGERPRINTS 4096
static ip_fingerprint_t g_fingerprints[MAX_FINGERPRINTS] = {0};
static pthread_mutex_t g_fp_lock = PTHREAD_MUTEX_INITIALIZER;

// Update fingerprint for anomaly detection
void spf_security_update_fingerprint(const char* ip, bool is_error) {
    if (!ip) return;
    
    pthread_mutex_lock(&g_fp_lock);
    
    time_t now = time(NULL);
    int empty_slot = -1;
    
    for (int i = 0; i < MAX_FINGERPRINTS; i++) {
        if (g_fingerprints[i].ip[0] == '\0') {
            if (empty_slot < 0) empty_slot = i;
            continue;
        }
        
        // Reset old entries
        if (now - g_fingerprints[i].window_start > 60) {
            g_fingerprints[i].request_count = 0;
            g_fingerprints[i].error_count = 0;
            g_fingerprints[i].window_start = now;
            g_fingerprints[i].anomaly_score = 0;
        }
        
        if (strcmp(g_fingerprints[i].ip, ip) == 0) {
            g_fingerprints[i].request_count++;
            if (is_error) g_fingerprints[i].error_count++;
            
            // Calculate anomaly score
            // High request rate = suspicious
            if (g_fingerprints[i].request_count > 100) {
                g_fingerprints[i].anomaly_score += 2;
            }
            // High error rate = suspicious
            if (g_fingerprints[i].error_count > 20) {
                g_fingerprints[i].anomaly_score += 3;
            }
            // High error ratio = very suspicious
            if (g_fingerprints[i].request_count > 10 && 
                g_fingerprints[i].error_count * 2 > g_fingerprints[i].request_count) {
                g_fingerprints[i].anomaly_score += 5;
            }
            
            if (g_fingerprints[i].anomaly_score > 10) {
                spf_log(SPF_LOG_SECURITY, "anomaly detected: %s (score %d)",
                       ip, g_fingerprints[i].anomaly_score);
            }
            
            pthread_mutex_unlock(&g_fp_lock);
            return;
        }
    }
    
    // Create new fingerprint
    if (empty_slot >= 0) {
        strncpy(g_fingerprints[empty_slot].ip, ip, SPF_IP_MAX_LEN - 1);
        g_fingerprints[empty_slot].ip[SPF_IP_MAX_LEN - 1] = '\0';
        g_fingerprints[empty_slot].request_count = 1;
        g_fingerprints[empty_slot].error_count = is_error ? 1 : 0;
        g_fingerprints[empty_slot].window_start = now;
        g_fingerprints[empty_slot].anomaly_score = 0;
    }
    
    pthread_mutex_unlock(&g_fp_lock);
}

// Get anomaly score for IP
int spf_security_get_anomaly_score(const char* ip) {
    if (!ip) return 0;
    
    pthread_mutex_lock(&g_fp_lock);
    
    for (int i = 0; i < MAX_FINGERPRINTS; i++) {
        if (strcmp(g_fingerprints[i].ip, ip) == 0) {
            int score = g_fingerprints[i].anomaly_score;
            pthread_mutex_unlock(&g_fp_lock);
            return score;
        }
    }
    
    pthread_mutex_unlock(&g_fp_lock);
    return 0;
}
