/*
 * SPF Dynamic DNS (DDNS) Client
 * 
 * Automatically updates your domain to point to your home IP - NO STATIC IP NEEDED!
 * 
 * Supported providers:
 *   - DuckDNS (free)
 *   - No-IP
 *   - Cloudflare DNS
 *   - FreeDNS (afraid.org)
 *   - Dynu
 *   - Custom URL-based updates
 * 
 * How it works:
 *   1. Detects your external IP (via UPnP or external service)
 *   2. Compares with last known IP
 *   3. If changed, updates your DDNS provider
 *   4. Periodic checks to handle IP changes
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define DDNS_CHECK_INTERVAL 300
#define DDNS_FORCE_UPDATE_INTERVAL 86400

static const char* const IP_SERVICES[] = {
    "api.ipify.org", "ifconfig.me", "icanhazip.com", NULL
};

// Use spf_ddns_provider_t and spf_ddns_config_t from common.h

typedef struct {
    spf_ddns_config_t config;
    char current_ip[SPF_IP_MAX_LEN];
    char last_ip[SPF_IP_MAX_LEN];
    time_t last_check;
    time_t last_update;
    int update_count;
    int error_count;
    bool running;
    pthread_t update_thread;
    pthread_mutex_t lock;
} spf_ddns_state_t;

static spf_ddns_state_t g_ddns = {0};

// Forward declarations
static int ddns_detect_ip(char* out, size_t len);
static int ddns_update_duckdns(const char* domain, const char* token, const char* ip);
static int ddns_update_noip(const char* domain, const char* user, const char* pass, const char* ip);
static int ddns_update_cloudflare(const char* zone, const char* record, const char* token, 
                                  const char* domain, const char* ip);
static int ddns_update_freedns(const char* token);
static int ddns_update_dynu(const char* domain, const char* user, const char* pass, const char* ip);
static int ddns_update_custom(const char* url, const char* ip);
static void* ddns_update_thread(void* arg);

// HTTPS GET request helper
static int https_get(const char* host, const char* path, const char* auth_header,
                    char* response, size_t resp_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct hostent* he = gethostbyname(host);
    if (!he) { close(fd); return -1; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    // Setup SSL
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }
    
    // Build request
    char request[2048];
    if (auth_header && auth_header[0]) {
        snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s\r\n"
            "Connection: close\r\n"
            "User-Agent: SPF-DDNS/1.0\r\n"
            "\r\n",
            path, host, auth_header);
    } else {
        snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "User-Agent: SPF-DDNS/1.0\r\n"
            "\r\n",
            path, host);
    }
    
    SSL_write(ssl, request, strlen(request));
    
    // Read response
    size_t total = 0;
    int n;
    while ((n = SSL_read(ssl, response + total, resp_len - total - 1)) > 0) {
        total += n;
        if (total >= resp_len - 1) break;
    }
    response[total] = '\0';
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    
    return (int)total;
}

// HTTP GET (plain, for IP detection fallback)
static int http_get_simple(const char* host, const char* path, char* response, size_t resp_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct hostent* he = gethostbyname(host);
    if (!he) { close(fd); return -1; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    char request[512];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);
    
    send(fd, request, strlen(request), 0);
    
    size_t total = 0;
    ssize_t n;
    while ((n = recv(fd, response + total, resp_len - total - 1, 0)) > 0) {
        total += n;
    }
    response[total] = '\0';
    
    close(fd);
    return (int)total;
}

// Detect external IP address
static int ddns_detect_ip(char* out, size_t len) {
    extern int spf_upnp_get_external_ip(char* out, size_t len);
    if (spf_upnp_get_external_ip(out, len) == 0 && out[0]) return 0;
    
    char response[512];
    for (int i = 0; IP_SERVICES[i]; i++) {
        if (http_get_simple(IP_SERVICES[i], "/", response, sizeof(response)) > 0) {
            // Extract IP from response body (after HTTP headers)
            char* body = strstr(response, "\r\n\r\n");
            if (body) {
                body += 4;
                // Trim whitespace
                while (*body == ' ' || *body == '\n' || *body == '\r') body++;
                char* end = body;
                while (*end && *end != ' ' && *end != '\n' && *end != '\r') end++;
                *end = '\0';
                
                // Validate IP format
                struct in_addr addr;
                if (inet_pton(AF_INET, body, &addr) == 1) {
                    strncpy(out, body, len - 1);
                    out[len - 1] = '\0';
                    return 0;
                }
            }
        }
    }
    
    return -1;
}

// Update DuckDNS
static int ddns_update_duckdns(const char* domain, const char* token, const char* ip) {
    char path[512];
    snprintf(path, sizeof(path), 
            "/update?domains=%s&token=%s&ip=%s",
            domain, token, ip);
    
    char response[1024];
    if (https_get("www.duckdns.org", path, NULL, response, sizeof(response)) > 0) {
        if (strstr(response, "OK")) {
            return 0;
        }
    }
    return -1;
}

// Update No-IP
static int ddns_update_noip(const char* domain, const char* user, const char* pass, const char* ip) {
    char path[512];
    snprintf(path, sizeof(path),
            "/nic/update?hostname=%s&myip=%s",
            domain, ip);
    
    // Base64 encode credentials
    char creds[256];
    snprintf(creds, sizeof(creds), "%s:%s", user, pass);
    
    // Simple base64 encoding
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char b64_creds[512];
    size_t in_len = strlen(creds);
    size_t out_idx = 0;
    
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t n = ((uint32_t)creds[i]) << 16;
        if (i + 1 < in_len) n |= ((uint32_t)creds[i + 1]) << 8;
        if (i + 2 < in_len) n |= (uint32_t)creds[i + 2];
        
        b64_creds[out_idx++] = b64[(n >> 18) & 0x3F];
        b64_creds[out_idx++] = b64[(n >> 12) & 0x3F];
        b64_creds[out_idx++] = (i + 1 < in_len) ? b64[(n >> 6) & 0x3F] : '=';
        b64_creds[out_idx++] = (i + 2 < in_len) ? b64[n & 0x3F] : '=';
    }
    b64_creds[out_idx] = '\0';
    
    char auth[768];
    snprintf(auth, sizeof(auth), "Authorization: Basic %s", b64_creds);
    
    char response[1024];
    if (https_get("dynupdate.no-ip.com", path, auth, response, sizeof(response)) > 0) {
        if (strstr(response, "good") || strstr(response, "nochg")) {
            return 0;
        }
    }
    return -1;
}

// Update Cloudflare DNS
static int ddns_update_cloudflare(const char* zone, const char* record, const char* token,
                                  const char* domain, const char* ip) {
    (void)domain;  // Domain used for display only
    
    // Cloudflare requires PUT with JSON body - simplified implementation
    char path[256];
    snprintf(path, sizeof(path), "/client/v4/zones/%s/dns_records/%s", zone, record);
    
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s\r\nContent-Type: application/json", token);
    
    // This is a simplified version - real implementation would need PUT with JSON
    spf_log(SPF_LOG_DEBUG, "ddns: cloudflare update for %s -> %s", domain, ip);
    spf_log(SPF_LOG_WARN, "ddns: cloudflare requires zone_id and record_id configuration");
    
    return -1;  // Not fully implemented
}

// Update FreeDNS (afraid.org)
static int ddns_update_freedns(const char* token) {
    char path[512];
    snprintf(path, sizeof(path), "/dynamic/update.php?%s", token);
    
    char response[1024];
    if (https_get("freedns.afraid.org", path, NULL, response, sizeof(response)) > 0) {
        if (strstr(response, "Updated") || strstr(response, "has not changed")) {
            return 0;
        }
    }
    return -1;
}

// Update Dynu
static int ddns_update_dynu(const char* domain, const char* user, const char* pass, const char* ip) {
    char path[512];
    snprintf(path, sizeof(path),
            "/nic/update?hostname=%s&myip=%s&username=%s&password=%s",
            domain, ip, user, pass);
    
    char response[1024];
    if (https_get("api.dynu.com", path, NULL, response, sizeof(response)) > 0) {
        if (strstr(response, "good") || strstr(response, "nochg")) {
            return 0;
        }
    }
    return -1;
}

// Update custom URL
static int ddns_update_custom(const char* url, const char* ip) {
    // Replace {{IP}} placeholder in URL
    char final_url[1024];
    const char* placeholder = strstr(url, "{{IP}}");
    if (placeholder) {
        size_t prefix_len = placeholder - url;
        strncpy(final_url, url, prefix_len);
        final_url[prefix_len] = '\0';
        strcat(final_url, ip);
        strcat(final_url, placeholder + 6);
    } else {
        strncpy(final_url, url, sizeof(final_url) - 1);
    }
    
    // Parse URL and make request
    char host[256] = {0};
    char path[512] = "/";
    bool use_https = false;
    
    const char* p = final_url;
    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        use_https = true;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }
    
    const char* slash = strchr(p, '/');
    if (slash) {
        strncpy(host, p, slash - p);
        strncpy(path, slash, sizeof(path) - 1);
    } else {
        strncpy(host, p, sizeof(host) - 1);
    }
    
    char response[1024];
    int result;
    
    if (use_https) {
        result = https_get(host, path, NULL, response, sizeof(response));
    } else {
        result = http_get_simple(host, path, response, sizeof(response));
    }
    
    if (result > 0) {
        spf_log(SPF_LOG_DEBUG, "ddns: custom update response: %.100s", response);
        return 0;  // Assume success if we got a response
    }
    return -1;
}

// Perform DDNS update
static int ddns_do_update(const char* ip) {
    spf_ddns_config_t* cfg = &g_ddns.config;
    int result = -1;
    
    switch (cfg->provider) {
        case SPF_DDNS_DUCKDNS:
            result = ddns_update_duckdns(cfg->domain, cfg->token, ip);
            break;
            
        case SPF_DDNS_NOIP:
            result = ddns_update_noip(cfg->domain, cfg->username, cfg->password, ip);
            break;
            
        case SPF_DDNS_CLOUDFLARE:
            result = ddns_update_cloudflare(cfg->zone_id, cfg->record_id, 
                                           cfg->token, cfg->domain, ip);
            break;
            
        case SPF_DDNS_FREEDNS:
            result = ddns_update_freedns(cfg->token);
            break;
            
        case SPF_DDNS_DYNU:
            result = ddns_update_dynu(cfg->domain, cfg->username, cfg->password, ip);
            break;
            
        case SPF_DDNS_CUSTOM:
            result = ddns_update_custom(cfg->custom_url, ip);
            break;
            
        default:
            break;
    }
    
    return result;
}

// DDNS update thread
static void* ddns_update_thread(void* arg) {
    (void)arg;
    
    while (g_ddns.running) {
        sleep(DDNS_CHECK_INTERVAL);
        
        if (!g_ddns.running || !g_ddns.config.enabled) continue;
        
        pthread_mutex_lock(&g_ddns.lock);
        
        char ip[SPF_IP_MAX_LEN];
        if (ddns_detect_ip(ip, sizeof(ip)) == 0) {
            strncpy(g_ddns.current_ip, ip, sizeof(g_ddns.current_ip) - 1);
            g_ddns.last_check = time(NULL);
            
            bool ip_changed = strcmp(ip, g_ddns.last_ip) != 0;
            bool force_update = (time(NULL) - g_ddns.last_update) > DDNS_FORCE_UPDATE_INTERVAL;
            
            if (ip_changed || force_update) {
                if (ip_changed) {
                    spf_log(SPF_LOG_INFO, "ddns: IP changed: %s -> %s", 
                           g_ddns.last_ip[0] ? g_ddns.last_ip : "(none)", ip);
                }
                
                if (ddns_do_update(ip) == 0) {
                    strncpy(g_ddns.last_ip, ip, sizeof(g_ddns.last_ip) - 1);
                    g_ddns.last_update = time(NULL);
                    g_ddns.update_count++;
                    spf_log(SPF_LOG_INFO, "ddns: updated %s -> %s", 
                           g_ddns.config.domain, ip);
                } else {
                    g_ddns.error_count++;
                    spf_log(SPF_LOG_ERROR, "ddns: update failed for %s", 
                           g_ddns.config.domain);
                }
            }
        } else {
            g_ddns.error_count++;
            spf_log(SPF_LOG_WARN, "ddns: failed to detect external IP");
        }
        
        pthread_mutex_unlock(&g_ddns.lock);
    }
    
    return NULL;
}

// ============================================================================
// PUBLIC API
// ============================================================================

// Initialize DDNS with provider configuration
int spf_ddns_init(spf_ddns_provider_t provider, const char* domain, const char* token) {
    memset(&g_ddns, 0, sizeof(g_ddns));
    pthread_mutex_init(&g_ddns.lock, NULL);
    
    g_ddns.config.provider = provider;
    if (domain) strncpy(g_ddns.config.domain, domain, sizeof(g_ddns.config.domain) - 1);
    if (token) strncpy(g_ddns.config.token, token, sizeof(g_ddns.config.token) - 1);
    g_ddns.config.enabled = true;
    g_ddns.running = true;
    
    // Detect initial IP
    if (ddns_detect_ip(g_ddns.current_ip, sizeof(g_ddns.current_ip)) == 0) {
        spf_log(SPF_LOG_INFO, "ddns: current external IP: %s", g_ddns.current_ip);
        
        // Do initial update
        if (ddns_do_update(g_ddns.current_ip) == 0) {
            strncpy(g_ddns.last_ip, g_ddns.current_ip, sizeof(g_ddns.last_ip) - 1);
            g_ddns.last_update = time(NULL);
            g_ddns.update_count++;
            spf_log(SPF_LOG_INFO, "ddns: initial update complete for %s", domain);
        }
    }
    
    // Start update thread
    pthread_create(&g_ddns.update_thread, NULL, ddns_update_thread, NULL);
    
    return 0;
}

// Configure with username/password (for No-IP, Dynu, etc.)
int spf_ddns_set_credentials(const char* username, const char* password) {
    pthread_mutex_lock(&g_ddns.lock);
    if (username) strncpy(g_ddns.config.username, username, sizeof(g_ddns.config.username) - 1);
    if (password) strncpy(g_ddns.config.password, password, sizeof(g_ddns.config.password) - 1);
    pthread_mutex_unlock(&g_ddns.lock);
    return 0;
}

// Configure Cloudflare (needs zone and record IDs)
int spf_ddns_set_cloudflare(const char* zone_id, const char* record_id) {
    pthread_mutex_lock(&g_ddns.lock);
    if (zone_id) strncpy(g_ddns.config.zone_id, zone_id, sizeof(g_ddns.config.zone_id) - 1);
    if (record_id) strncpy(g_ddns.config.record_id, record_id, sizeof(g_ddns.config.record_id) - 1);
    pthread_mutex_unlock(&g_ddns.lock);
    return 0;
}

// Configure custom update URL
int spf_ddns_set_custom_url(const char* url) {
    pthread_mutex_lock(&g_ddns.lock);
    if (url) strncpy(g_ddns.config.custom_url, url, sizeof(g_ddns.config.custom_url) - 1);
    g_ddns.config.provider = SPF_DDNS_CUSTOM;
    pthread_mutex_unlock(&g_ddns.lock);
    return 0;
}

// Force an immediate update
int spf_ddns_update_now(void) {
    pthread_mutex_lock(&g_ddns.lock);
    
    char ip[SPF_IP_MAX_LEN];
    int result = -1;
    
    if (ddns_detect_ip(ip, sizeof(ip)) == 0) {
        strncpy(g_ddns.current_ip, ip, sizeof(g_ddns.current_ip) - 1);
        result = ddns_do_update(ip);
        if (result == 0) {
            strncpy(g_ddns.last_ip, ip, sizeof(g_ddns.last_ip) - 1);
            g_ddns.last_update = time(NULL);
            g_ddns.update_count++;
        }
    }
    
    pthread_mutex_unlock(&g_ddns.lock);
    return result;
}

// Get current external IP
int spf_ddns_get_ip(char* out, size_t len) {
    pthread_mutex_lock(&g_ddns.lock);
    if (g_ddns.current_ip[0]) {
        strncpy(out, g_ddns.current_ip, len - 1);
        out[len - 1] = '\0';
        pthread_mutex_unlock(&g_ddns.lock);
        return 0;
    }
    pthread_mutex_unlock(&g_ddns.lock);
    return ddns_detect_ip(out, len);
}

// Get DDNS status
void spf_ddns_status(char* buf, size_t len) {
    pthread_mutex_lock(&g_ddns.lock);
    
    const char* provider_names[] = {
        "None", "DuckDNS", "No-IP", "Cloudflare", "FreeDNS", "Dynu", "Custom"
    };
    
    char* p = buf;
    p += snprintf(p, len, "=== DDNS Status ===\n");
    p += snprintf(p, len - (p - buf), "Provider: %s\n", 
                 provider_names[g_ddns.config.provider]);
    p += snprintf(p, len - (p - buf), "Domain: %s\n",
                 g_ddns.config.domain[0] ? g_ddns.config.domain : "Not configured");
    p += snprintf(p, len - (p - buf), "Enabled: %s\n",
                 g_ddns.config.enabled ? "Yes" : "No");
    p += snprintf(p, len - (p - buf), "Current IP: %s\n",
                 g_ddns.current_ip[0] ? g_ddns.current_ip : "Unknown");
    p += snprintf(p, len - (p - buf), "Last Update: %s",
                 g_ddns.last_update ? ctime(&g_ddns.last_update) : "Never\n");
    p += snprintf(p, len - (p - buf), "Update Count: %d\n", g_ddns.update_count);
    p += snprintf(p, len - (p - buf), "Error Count: %d\n", g_ddns.error_count);
    
    pthread_mutex_unlock(&g_ddns.lock);
}

// Parse provider from string
spf_ddns_provider_t spf_ddns_parse_provider(const char* name) {
    if (!name) return SPF_DDNS_NONE;
    if (strcasecmp(name, "duckdns") == 0) return SPF_DDNS_DUCKDNS;
    if (strcasecmp(name, "noip") == 0 || strcasecmp(name, "no-ip") == 0) return SPF_DDNS_NOIP;
    if (strcasecmp(name, "cloudflare") == 0 || strcasecmp(name, "cf") == 0) return SPF_DDNS_CLOUDFLARE;
    if (strcasecmp(name, "freedns") == 0 || strcasecmp(name, "afraid") == 0) return SPF_DDNS_FREEDNS;
    if (strcasecmp(name, "dynu") == 0) return SPF_DDNS_DYNU;
    if (strcasecmp(name, "custom") == 0) return SPF_DDNS_CUSTOM;
    return SPF_DDNS_NONE;
}

// Cleanup
void spf_ddns_cleanup(void) {
    g_ddns.running = false;
    
    if (g_ddns.update_thread) {
        pthread_join(g_ddns.update_thread, NULL);
    }
    
    pthread_mutex_destroy(&g_ddns.lock);
    spf_log(SPF_LOG_INFO, "ddns: cleanup complete");
}
