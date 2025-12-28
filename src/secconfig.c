/*
 * SPF Security Configuration Module
 * 
 * Allows users to customize security settings via config file or CLI.
 * Makes enterprise security accessible to home users without expertise.
 * 
 * Configuration can be done via:
 *   1. Config file (spf.conf)
 *   2. Command-line arguments
 *   3. Runtime API (for advanced users)
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>

// User-configurable security settings
struct spf_security_config {
    // Rate limiting
    uint32_t rate_limit_requests;      // Max requests per window
    uint32_t rate_limit_window_sec;    // Window size in seconds
    uint32_t max_connections_per_ip;   // Max concurrent connections per IP
    uint32_t max_total_connections;    // Max total connections
    
    // Attack prevention
    bool enable_sql_injection_check;
    bool enable_xss_check;
    bool enable_command_injection_check;
    bool enable_path_traversal_check;
    bool enable_slow_loris_protection;
    bool enable_user_agent_check;
    
    // TLS settings
    char tls_min_version[16];          // "1.2" or "1.3"
    char tls_ciphers[512];             // Cipher suite string
    bool tls_require_client_cert;
    
    // IP filtering
    char ip_whitelist[4096];           // Comma-separated IPs
    char ip_blacklist[4096];           // Comma-separated IPs
    bool geo_blocking_enabled;
    char geo_blocked_countries[256];   // Comma-separated country codes
    
    // Request limits
    uint32_t max_request_size;         // Max request body size in bytes
    uint32_t max_header_size;          // Max total headers size
    uint32_t max_uri_length;           // Max URI length
    uint32_t request_timeout_sec;      // Request timeout
    
    // Logging
    bool log_blocked_requests;
    bool log_suspicious_activity;
    bool anonymize_logs;               // Hash IPs in logs
    
    // Custom rules (user-defined)
    char custom_block_patterns[4096];  // Comma-separated regex patterns
    char custom_allow_paths[4096];     // Paths to skip security checks
    
    // Advanced
    uint32_t anomaly_threshold;        // Score threshold for blocking
    bool enable_honeypot;              // Enable honeypot endpoints
    bool enable_auto_block;            // Auto-block on repeated violations
    uint32_t auto_block_threshold;     // Violations before auto-block
    uint32_t auto_block_duration_min;  // Auto-block duration in minutes
};

// Default security configuration (secure by default)
static spf_security_config_t g_sec_config = {
    // Rate limiting
    .rate_limit_requests = 100,
    .rate_limit_window_sec = 60,
    .max_connections_per_ip = 10,
    .max_total_connections = 1000,
    
    // Attack prevention (all enabled by default)
    .enable_sql_injection_check = true,
    .enable_xss_check = true,
    .enable_command_injection_check = true,
    .enable_path_traversal_check = true,
    .enable_slow_loris_protection = true,
    .enable_user_agent_check = true,
    
    // TLS settings
    .tls_min_version = "1.2",
    .tls_ciphers = "",  // Empty = use secure defaults
    .tls_require_client_cert = false,
    
    // IP filtering
    .ip_whitelist = "",
    .ip_blacklist = "",
    .geo_blocking_enabled = false,
    .geo_blocked_countries = "",
    
    // Request limits
    .max_request_size = 10 * 1024 * 1024,  // 10 MB
    .max_header_size = 16 * 1024,           // 16 KB
    .max_uri_length = 8192,
    .request_timeout_sec = 30,
    
    // Logging
    .log_blocked_requests = true,
    .log_suspicious_activity = true,
    .anonymize_logs = false,
    
    // Custom rules
    .custom_block_patterns = "",
    .custom_allow_paths = "",
    
    // Advanced
    .anomaly_threshold = 80,
    .enable_honeypot = false,
    .enable_auto_block = true,
    .auto_block_threshold = 10,
    .auto_block_duration_min = 60
};

// Get current config (read-only)
const spf_security_config_t* spf_secconfig_get(void) {
    return &g_sec_config;
}

// Helper to parse boolean from string
static bool parse_bool(const char* value) {
    if (!value) return false;
    return (strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "yes") == 0 ||
            strcasecmp(value, "1") == 0 ||
            strcasecmp(value, "on") == 0);
}

// Helper to safely copy string
static void safe_strcpy(char* dest, size_t dest_size, const char* src) {
    if (!dest || dest_size == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

// Set a configuration option by name
int spf_secconfig_set(const char* key, const char* value) {
    if (!key || !value) return -1;
    
    // Rate limiting
    if (strcasecmp(key, "rate_limit_requests") == 0) {
        g_sec_config.rate_limit_requests = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "rate_limit_window") == 0) {
        g_sec_config.rate_limit_window_sec = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "max_connections_per_ip") == 0) {
        g_sec_config.max_connections_per_ip = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "max_total_connections") == 0) {
        g_sec_config.max_total_connections = (uint32_t)atoi(value);
    }
    
    // Attack prevention
    else if (strcasecmp(key, "sql_injection_check") == 0) {
        g_sec_config.enable_sql_injection_check = parse_bool(value);
    }
    else if (strcasecmp(key, "xss_check") == 0) {
        g_sec_config.enable_xss_check = parse_bool(value);
    }
    else if (strcasecmp(key, "command_injection_check") == 0) {
        g_sec_config.enable_command_injection_check = parse_bool(value);
    }
    else if (strcasecmp(key, "path_traversal_check") == 0) {
        g_sec_config.enable_path_traversal_check = parse_bool(value);
    }
    else if (strcasecmp(key, "slow_loris_protection") == 0) {
        g_sec_config.enable_slow_loris_protection = parse_bool(value);
    }
    else if (strcasecmp(key, "user_agent_check") == 0) {
        g_sec_config.enable_user_agent_check = parse_bool(value);
    }
    
    // TLS settings
    else if (strcasecmp(key, "tls_min_version") == 0) {
        safe_strcpy(g_sec_config.tls_min_version, sizeof(g_sec_config.tls_min_version), value);
    }
    else if (strcasecmp(key, "tls_ciphers") == 0) {
        safe_strcpy(g_sec_config.tls_ciphers, sizeof(g_sec_config.tls_ciphers), value);
    }
    else if (strcasecmp(key, "tls_require_client_cert") == 0) {
        g_sec_config.tls_require_client_cert = parse_bool(value);
    }
    
    // IP filtering
    else if (strcasecmp(key, "ip_whitelist") == 0) {
        safe_strcpy(g_sec_config.ip_whitelist, sizeof(g_sec_config.ip_whitelist), value);
    }
    else if (strcasecmp(key, "ip_blacklist") == 0) {
        safe_strcpy(g_sec_config.ip_blacklist, sizeof(g_sec_config.ip_blacklist), value);
    }
    else if (strcasecmp(key, "geo_blocking") == 0) {
        g_sec_config.geo_blocking_enabled = parse_bool(value);
    }
    else if (strcasecmp(key, "geo_blocked_countries") == 0) {
        safe_strcpy(g_sec_config.geo_blocked_countries, sizeof(g_sec_config.geo_blocked_countries), value);
    }
    
    // Request limits
    else if (strcasecmp(key, "max_request_size") == 0) {
        g_sec_config.max_request_size = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "max_header_size") == 0) {
        g_sec_config.max_header_size = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "max_uri_length") == 0) {
        g_sec_config.max_uri_length = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "request_timeout") == 0) {
        g_sec_config.request_timeout_sec = (uint32_t)atoi(value);
    }
    
    // Logging
    else if (strcasecmp(key, "log_blocked_requests") == 0) {
        g_sec_config.log_blocked_requests = parse_bool(value);
    }
    else if (strcasecmp(key, "log_suspicious_activity") == 0) {
        g_sec_config.log_suspicious_activity = parse_bool(value);
    }
    else if (strcasecmp(key, "anonymize_logs") == 0) {
        g_sec_config.anonymize_logs = parse_bool(value);
    }
    
    // Custom rules
    else if (strcasecmp(key, "custom_block_patterns") == 0) {
        safe_strcpy(g_sec_config.custom_block_patterns, sizeof(g_sec_config.custom_block_patterns), value);
    }
    else if (strcasecmp(key, "custom_allow_paths") == 0) {
        safe_strcpy(g_sec_config.custom_allow_paths, sizeof(g_sec_config.custom_allow_paths), value);
    }
    
    // Advanced
    else if (strcasecmp(key, "anomaly_threshold") == 0) {
        g_sec_config.anomaly_threshold = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "enable_honeypot") == 0) {
        g_sec_config.enable_honeypot = parse_bool(value);
    }
    else if (strcasecmp(key, "auto_block") == 0) {
        g_sec_config.enable_auto_block = parse_bool(value);
    }
    else if (strcasecmp(key, "auto_block_threshold") == 0) {
        g_sec_config.auto_block_threshold = (uint32_t)atoi(value);
    }
    else if (strcasecmp(key, "auto_block_duration") == 0) {
        g_sec_config.auto_block_duration_min = (uint32_t)atoi(value);
    }
    else {
        return -1;  // Unknown key
    }
    
    return 0;
}

// Load security configuration from file
int spf_secconfig_load(const char* path) {
    if (!path) return -1;
    
    FILE* fp = fopen(path, "r");
    if (!fp) {
        spf_log(SPF_LOG_WARN, "secconfig: cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    
    char line[1024];
    int lineno = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        
        // Skip empty lines and comments
        char* p = line;
        while (isspace(*p)) p++;
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        
        // Parse key=value
        char* eq = strchr(p, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char* key = p;
        char* value = eq + 1;
        
        // Trim key
        char* end = key + strlen(key) - 1;
        while (end > key && isspace(*end)) *end-- = '\0';
        
        // Trim value
        while (isspace(*value)) value++;
        end = value + strlen(value) - 1;
        while (end > value && (isspace(*end) || *end == '\n')) *end-- = '\0';
        
        // Remove quotes if present
        if ((*value == '"' || *value == '\'') && strlen(value) > 1) {
            char quote = *value++;
            end = value + strlen(value) - 1;
            if (*end == quote) *end = '\0';
        }
        
        // Set the option
        if (spf_secconfig_set(key, value) != 0) {
            spf_log(SPF_LOG_WARN, "secconfig: unknown option '%s' at line %d", key, lineno);
        }
    }
    
    fclose(fp);
    spf_log(SPF_LOG_INFO, "secconfig: loaded configuration from %s", path);
    return 0;
}

// Check if IP is in whitelist
bool spf_secconfig_is_whitelisted(const char* ip) {
    if (!ip || g_sec_config.ip_whitelist[0] == '\0') return false;
    return strstr(g_sec_config.ip_whitelist, ip) != NULL;
}

// Check if IP is in blacklist
bool spf_secconfig_is_blacklisted(const char* ip) {
    if (!ip || g_sec_config.ip_blacklist[0] == '\0') return false;
    return strstr(g_sec_config.ip_blacklist, ip) != NULL;
}

// Check if path is in allow list (skip security checks)
bool spf_secconfig_is_allowed_path(const char* path) {
    if (!path || g_sec_config.custom_allow_paths[0] == '\0') return false;
    return strstr(g_sec_config.custom_allow_paths, path) != NULL;
}

// Print current configuration
void spf_secconfig_dump(void) {
    spf_log(SPF_LOG_INFO, "=== Security Configuration ===");
    spf_log(SPF_LOG_INFO, "Rate Limiting:");
    spf_log(SPF_LOG_INFO, "  rate_limit_requests = %u", g_sec_config.rate_limit_requests);
    spf_log(SPF_LOG_INFO, "  rate_limit_window = %u", g_sec_config.rate_limit_window_sec);
    spf_log(SPF_LOG_INFO, "  max_connections_per_ip = %u", g_sec_config.max_connections_per_ip);
    spf_log(SPF_LOG_INFO, "  max_total_connections = %u", g_sec_config.max_total_connections);
    
    spf_log(SPF_LOG_INFO, "Attack Prevention:");
    spf_log(SPF_LOG_INFO, "  sql_injection_check = %s", g_sec_config.enable_sql_injection_check ? "on" : "off");
    spf_log(SPF_LOG_INFO, "  xss_check = %s", g_sec_config.enable_xss_check ? "on" : "off");
    spf_log(SPF_LOG_INFO, "  command_injection_check = %s", g_sec_config.enable_command_injection_check ? "on" : "off");
    spf_log(SPF_LOG_INFO, "  path_traversal_check = %s", g_sec_config.enable_path_traversal_check ? "on" : "off");
    spf_log(SPF_LOG_INFO, "  slow_loris_protection = %s", g_sec_config.enable_slow_loris_protection ? "on" : "off");
    spf_log(SPF_LOG_INFO, "  user_agent_check = %s", g_sec_config.enable_user_agent_check ? "on" : "off");
    
    spf_log(SPF_LOG_INFO, "TLS:");
    spf_log(SPF_LOG_INFO, "  tls_min_version = %s", g_sec_config.tls_min_version);
    spf_log(SPF_LOG_INFO, "  tls_require_client_cert = %s", g_sec_config.tls_require_client_cert ? "on" : "off");
    
    spf_log(SPF_LOG_INFO, "Request Limits:");
    spf_log(SPF_LOG_INFO, "  max_request_size = %u", g_sec_config.max_request_size);
    spf_log(SPF_LOG_INFO, "  max_header_size = %u", g_sec_config.max_header_size);
    spf_log(SPF_LOG_INFO, "  max_uri_length = %u", g_sec_config.max_uri_length);
    spf_log(SPF_LOG_INFO, "  request_timeout = %u", g_sec_config.request_timeout_sec);
    
    spf_log(SPF_LOG_INFO, "Advanced:");
    spf_log(SPF_LOG_INFO, "  anomaly_threshold = %u", g_sec_config.anomaly_threshold);
    spf_log(SPF_LOG_INFO, "  auto_block = %s", g_sec_config.enable_auto_block ? "on" : "off");
    spf_log(SPF_LOG_INFO, "  auto_block_threshold = %u", g_sec_config.auto_block_threshold);
    spf_log(SPF_LOG_INFO, "  auto_block_duration = %u min", g_sec_config.auto_block_duration_min);
}

// Generate example configuration file
void spf_secconfig_generate_example(const char* path) {
    FILE* fp = fopen(path, "w");
    if (!fp) {
        spf_log(SPF_LOG_ERROR, "secconfig: cannot create %s: %s", path, strerror(errno));
        return;
    }
    
    fprintf(fp, "# SPF Security Config\n\n");
    fprintf(fp, "rate_limit_requests=100\nrate_limit_window=60\n");
    fprintf(fp, "max_connections_per_ip=10\nmax_total_connections=1000\n\n");
    fprintf(fp, "sql_injection_check=true\nxss_check=true\n");
    fprintf(fp, "command_injection_check=true\npath_traversal_check=true\n");
    fprintf(fp, "slow_loris_protection=true\nuser_agent_check=true\n\n");
    fprintf(fp, "tls_min_version=1.2\ntls_require_client_cert=false\n\n");
    fprintf(fp, "#ip_whitelist=192.168.1.1\n#ip_blacklist=1.2.3.4\n");
    fprintf(fp, "geo_blocking=false\n\n");
    fprintf(fp, "max_request_size=10485760\nmax_header_size=16384\n");
    fprintf(fp, "max_uri_length=8192\nrequest_timeout=30\n\n");
    fprintf(fp, "log_blocked_requests=true\nlog_suspicious_activity=true\n");
    fprintf(fp, "anonymize_logs=false\n\n");
    fprintf(fp, "anomaly_threshold=80\nenable_honeypot=false\n");
    fprintf(fp, "auto_block=true\nauto_block_threshold=10\nauto_block_duration=60\n");
    
    fclose(fp);
    spf_log(SPF_LOG_INFO, "secconfig: generated %s", path);
}
