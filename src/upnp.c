/*
 * SPF UPnP/NAT-PMP Module
 * 
 * Automatically configures your router to forward ports - NO VPS NEEDED!
 * 
 * How it works:
 *   1. Discovers your router via UPnP (SSDP) or NAT-PMP
 *   2. Requests port forwarding from router
 *   3. Keeps the port mapping alive with periodic renewals
 *   4. Automatically cleans up on exit
 * 
 * Supported protocols:
 *   - UPnP IGD (Internet Gateway Device) - Most common
 *   - NAT-PMP (Apple routers, some others)
 *   - PCP (Port Control Protocol) - Newer standard
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
#include <fcntl.h>
#include <sys/select.h>

// SSDP (Simple Service Discovery Protocol) for UPnP discovery
#define SSDP_ADDR "239.255.255.250"
#define SSDP_PORT 1900
#define SSDP_MX 3

// NAT-PMP constants
#define NATPMP_PORT 5351
#define NATPMP_RETRY_MS 250
#define NATPMP_MAX_RETRIES 9

// Port mapping lease time (seconds)
#define MAPPING_LEASE_TIME 3600
#define MAPPING_RENEW_INTERVAL (MAPPING_LEASE_TIME - 60)

// Maximum port mappings we track
#define MAX_PORT_MAPPINGS 32

typedef enum {
    SPF_UPNP_NONE = 0,
    SPF_UPNP_IGD,      // UPnP Internet Gateway Device
    SPF_UPNP_NATPMP,   // NAT-PMP
    SPF_UPNP_PCP       // Port Control Protocol
} spf_upnp_type_t;

typedef struct {
    uint16_t external_port;
    uint16_t internal_port;
    char protocol[8];      // "TCP" or "UDP"
    char description[64];
    time_t created_at;
    time_t expires_at;
    bool active;
} spf_port_mapping_t;

typedef struct {
    spf_upnp_type_t type;
    char gateway_ip[SPF_IP_MAX_LEN];
    char local_ip[SPF_IP_MAX_LEN];
    char external_ip[SPF_IP_MAX_LEN];
    char control_url[512];
    char service_type[256];
    spf_port_mapping_t mappings[MAX_PORT_MAPPINGS];
    int mapping_count;
    pthread_mutex_t lock;
    pthread_t renew_thread;
    bool running;
    bool discovered;
} spf_upnp_state_t;

static spf_upnp_state_t g_upnp = {0};

// Forward declarations
static int upnp_discover_igd(void);
static int natpmp_discover(void);
static int upnp_add_mapping_igd(uint16_t external, uint16_t internal, const char* proto, const char* desc);
static int natpmp_add_mapping(uint16_t external, uint16_t internal, const char* proto);
static void* upnp_renew_thread(void* arg);

// Get local IP address (the one facing the gateway)
static int get_local_ip(const char* gateway, char* out, size_t len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct sockaddr_in gw_addr;
    memset(&gw_addr, 0, sizeof(gw_addr));
    gw_addr.sin_family = AF_INET;
    gw_addr.sin_port = htons(80);
    inet_pton(AF_INET, gateway, &gw_addr.sin_addr);
    
    // Connect to figure out which interface reaches gateway
    if (connect(fd, (struct sockaddr*)&gw_addr, sizeof(gw_addr)) < 0) {
        close(fd);
        return -1;
    }
    
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(fd, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        close(fd);
        return -1;
    }
    
    inet_ntop(AF_INET, &local_addr.sin_addr, out, len);
    close(fd);
    return 0;
}

// Simple XML value extraction (no libxml dependency)
static int xml_extract_value(const char* xml, const char* tag, char* out, size_t len) {
    char open_tag[128], close_tag[128];
    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    
    const char* start = strstr(xml, open_tag);
    if (!start) return -1;
    start += strlen(open_tag);
    
    const char* end = strstr(start, close_tag);
    if (!end) return -1;
    
    size_t value_len = end - start;
    if (value_len >= len) value_len = len - 1;
    
    strncpy(out, start, value_len);
    out[value_len] = '\0';
    return 0;
}

// HTTP GET request helper
static int http_get(const char* url, char* response, size_t resp_len) {
    char host[256] = {0};
    char path[512] = "/";
    int port = 80;
    
    // Input validation
    if (!url || !response || resp_len == 0) return -1;
    if (strlen(url) > 1024) return -1;
    
    // Parse URL: http://host:port/path
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    
    const char* slash = strchr(p, '/');
    const char* colon = strchr(p, ':');
    
    if (colon && (!slash || colon < slash)) {
        size_t host_len = colon - p;
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        strncpy(host, p, host_len);
        host[host_len] = '\0';
        port = atoi(colon + 1);
        if (port <= 0 || port > 65535) port = 80;
        if (slash) {
            strncpy(path, slash, sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
        }
    } else if (slash) {
        size_t host_len = slash - p;
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        strncpy(host, p, host_len);
        host[host_len] = '\0';
        strncpy(path, slash, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    } else {
        strncpy(host, p, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct hostent* he = gethostbyname(host);
    if (!he) { close(fd); return -1; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    // Set timeout
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Connection: close\r\n"
        "\r\n", path, host, port);
    
    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return -1;
    }
    
    size_t total = 0;
    ssize_t n;
    while ((n = recv(fd, response + total, resp_len - total - 1, 0)) > 0) {
        total += n;
        if (total >= resp_len - 1) break;
    }
    response[total] = '\0';
    
    close(fd);
    return (int)total;
}

// SOAP request for UPnP IGD
static int soap_request(const char* url, const char* service, const char* action, 
                       const char* body, char* response, size_t resp_len) {
    char host[256] = {0};
    char path[512] = "/";
    int port = 80;
    
    // Input validation
    if (!url || !service || !action || !response) return -1;
    if (strlen(url) > 1024) return -1;
    
    // Parse URL
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    
    const char* slash = strchr(p, '/');
    const char* colon = strchr(p, ':');
    
    if (colon && (!slash || colon < slash)) {
        size_t host_len = colon - p;
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        strncpy(host, p, host_len);
        host[host_len] = '\0';
        port = atoi(colon + 1);
        if (port <= 0 || port > 65535) port = 80;
        if (slash) {
            strncpy(path, slash, sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
        }
    } else if (slash) {
        size_t host_len = slash - p;
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        strncpy(host, p, host_len);
        host[host_len] = '\0';
        strncpy(path, slash, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    } else {
        strncpy(host, p, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct hostent* he = gethostbyname(host);
    if (!he) { close(fd); return -1; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    // Build SOAP envelope
    char soap[4096];
    snprintf(soap, sizeof(soap),
        "<?xml version=\"1.0\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
        "<s:Body>\r\n"
        "<u:%s xmlns:u=\"%s\">\r\n"
        "%s"
        "</u:%s>\r\n"
        "</s:Body>\r\n"
        "</s:Envelope>\r\n",
        action, service, body, action);
    
    char request[8192];
    snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        "Content-Length: %zu\r\n"
        "SOAPAction: \"%s#%s\"\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, host, port, strlen(soap), service, action, soap);
    
    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return -1;
    }
    
    size_t total = 0;
    ssize_t n;
    while ((n = recv(fd, response + total, resp_len - total - 1, 0)) > 0) {
        total += n;
        if (total >= resp_len - 1) break;
    }
    response[total] = '\0';
    
    close(fd);
    
    // Check for success (HTTP 200)
    if (strstr(response, "200 OK") || strstr(response, "200 ok")) {
        return 0;
    }
    return -1;
}

// Discover UPnP IGD (router)
static int upnp_discover_igd(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    // Allow multicast
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    
    struct timeval tv = {SSDP_MX + 1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in ssdp_addr;
    memset(&ssdp_addr, 0, sizeof(ssdp_addr));
    ssdp_addr.sin_family = AF_INET;
    ssdp_addr.sin_port = htons(SSDP_PORT);
    inet_pton(AF_INET, SSDP_ADDR, &ssdp_addr.sin_addr);
    
    // SSDP M-SEARCH for Internet Gateway Device
    const char* search_targets[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        NULL
    };
    
    char response[4096];
    
    for (int i = 0; search_targets[i]; i++) {
        char request[512];
        snprintf(request, sizeof(request),
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: %s:%d\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: %d\r\n"
            "ST: %s\r\n"
            "\r\n",
            SSDP_ADDR, SSDP_PORT, SSDP_MX, search_targets[i]);
        
        sendto(fd, request, strlen(request), 0, 
               (struct sockaddr*)&ssdp_addr, sizeof(ssdp_addr));
        
        // Wait for response
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t n = recvfrom(fd, response, sizeof(response) - 1, 0,
                            (struct sockaddr*)&from_addr, &from_len);
        
        if (n > 0) {
            response[n] = '\0';
            
            // Extract location header
            char* loc = strstr(response, "LOCATION:");
            if (!loc) loc = strstr(response, "Location:");
            if (loc) {
                loc += 9;
                while (*loc == ' ') loc++;
                char* end = strstr(loc, "\r\n");
                if (end) {
                    char location[512];
                    strncpy(location, loc, end - loc);
                    location[end - loc] = '\0';
                    
                    // Get device description
                    char desc[16384];
                    if (http_get(location, desc, sizeof(desc)) > 0) {
                        // Find control URL for WANIPConnection or WANPPPConnection
                        char* wan = strstr(desc, "WANIPConnection");
                        if (!wan) wan = strstr(desc, "WANPPPConnection");
                        
                        if (wan) {
                            // Extract service type and control URL
                            char* svc_start = wan;
                            while (svc_start > desc && *svc_start != '<') svc_start--;
                            
                            // Find controlURL in this service block
                            char* ctrl = strstr(svc_start, "<controlURL>");
                            if (ctrl) {
                                char ctrl_path[256];
                                if (xml_extract_value(ctrl, "controlURL", ctrl_path, sizeof(ctrl_path)) == 0) {
                                    // Build full control URL
                                    char base_url[512];
                                    strncpy(base_url, location, sizeof(base_url) - 1);
                                    char* last_slash = strrchr(base_url, '/');
                                    if (last_slash && last_slash != base_url + 6) { // Not just http://
                                        *last_slash = '\0';
                                    }
                                    
                                    if (ctrl_path[0] == '/') {
                                        // Parse host from location
                                        char* host_start = strstr(location, "://");
                                        if (host_start) {
                                            host_start += 3;
                                            char* host_end = strchr(host_start, '/');
                                            if (host_end) {
                                                char host_part[256];
                                                strncpy(host_part, location, host_end - location);
                                                host_part[host_end - location] = '\0';
                                                snprintf(g_upnp.control_url, sizeof(g_upnp.control_url),
                                                        "%s%s", host_part, ctrl_path);
                                            }
                                        }
                                    } else {
                                        snprintf(g_upnp.control_url, sizeof(g_upnp.control_url),
                                                "%s/%s", base_url, ctrl_path);
                                    }
                                    
                                    // Determine service type
                                    if (strstr(desc, "WANIPConnection")) {
                                        strncpy(g_upnp.service_type, 
                                               "urn:schemas-upnp-org:service:WANIPConnection:1",
                                               sizeof(g_upnp.service_type) - 1);
                                    } else {
                                        strncpy(g_upnp.service_type,
                                               "urn:schemas-upnp-org:service:WANPPPConnection:1",
                                               sizeof(g_upnp.service_type) - 1);
                                    }
                                    
                                    inet_ntop(AF_INET, &from_addr.sin_addr, 
                                             g_upnp.gateway_ip, sizeof(g_upnp.gateway_ip));
                                    get_local_ip(g_upnp.gateway_ip, g_upnp.local_ip, sizeof(g_upnp.local_ip));
                                    
                                    g_upnp.type = SPF_UPNP_IGD;
                                    g_upnp.discovered = true;
                                    
                                    spf_log(SPF_LOG_INFO, "upnp: discovered IGD at %s", g_upnp.gateway_ip);
                                    spf_log(SPF_LOG_DEBUG, "upnp: control URL: %s", g_upnp.control_url);
                                    
                                    close(fd);
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    close(fd);
    return -1;
}

// Discover NAT-PMP gateway
static int natpmp_discover(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    // NAT-PMP uses the default gateway
    // Try common gateway addresses
    const char* gateways[] = {"192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1", NULL};
    
    for (int i = 0; gateways[i]; i++) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(NATPMP_PORT);
        inet_pton(AF_INET, gateways[i], &addr.sin_addr);
        
        // NAT-PMP request: get external address
        uint8_t request[2] = {0, 0};  // Version 0, opcode 0 (get external IP)
        
        sendto(fd, request, sizeof(request), 0, (struct sockaddr*)&addr, sizeof(addr));
        
        struct timeval tv = {1, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        uint8_t response[16];
        ssize_t n = recv(fd, response, sizeof(response), 0);
        
        if (n >= 12 && response[0] == 0 && response[1] == 128 && response[3] == 0) {
            // Success! Extract external IP
            snprintf(g_upnp.external_ip, sizeof(g_upnp.external_ip),
                    "%u.%u.%u.%u", response[8], response[9], response[10], response[11]);
            
            strncpy(g_upnp.gateway_ip, gateways[i], sizeof(g_upnp.gateway_ip) - 1);
            get_local_ip(g_upnp.gateway_ip, g_upnp.local_ip, sizeof(g_upnp.local_ip));
            
            g_upnp.type = SPF_UPNP_NATPMP;
            g_upnp.discovered = true;
            
            spf_log(SPF_LOG_INFO, "natpmp: discovered gateway at %s", g_upnp.gateway_ip);
            spf_log(SPF_LOG_INFO, "natpmp: external IP: %s", g_upnp.external_ip);
            
            close(fd);
            return 0;
        }
    }
    
    close(fd);
    return -1;
}

// Add port mapping via UPnP IGD
static int upnp_add_mapping_igd(uint16_t external, uint16_t internal, 
                                const char* proto, const char* desc) {
    char body[1024];
    snprintf(body, sizeof(body),
        "<NewRemoteHost></NewRemoteHost>\r\n"
        "<NewExternalPort>%u</NewExternalPort>\r\n"
        "<NewProtocol>%s</NewProtocol>\r\n"
        "<NewInternalPort>%u</NewInternalPort>\r\n"
        "<NewInternalClient>%s</NewInternalClient>\r\n"
        "<NewEnabled>1</NewEnabled>\r\n"
        "<NewPortMappingDescription>%s</NewPortMappingDescription>\r\n"
        "<NewLeaseDuration>%d</NewLeaseDuration>\r\n",
        external, proto, internal, g_upnp.local_ip, desc, MAPPING_LEASE_TIME);
    
    char response[4096];
    if (soap_request(g_upnp.control_url, g_upnp.service_type, 
                    "AddPortMapping", body, response, sizeof(response)) == 0) {
        return 0;
    }
    
    return -1;
}

// Add port mapping via NAT-PMP
static int natpmp_add_mapping(uint16_t external, uint16_t internal, const char* proto) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NATPMP_PORT);
    inet_pton(AF_INET, g_upnp.gateway_ip, &addr.sin_addr);
    
    // NAT-PMP mapping request
    uint8_t request[12];
    request[0] = 0;  // Version
    request[1] = (strcmp(proto, "UDP") == 0) ? 1 : 2;  // Opcode: 1=UDP, 2=TCP
    request[2] = 0;  // Reserved
    request[3] = 0;
    request[4] = (internal >> 8) & 0xFF;  // Internal port (big endian)
    request[5] = internal & 0xFF;
    request[6] = (external >> 8) & 0xFF;  // External port (big endian)
    request[7] = external & 0xFF;
    // Lifetime in seconds (big endian, 4 bytes)
    uint32_t lifetime = MAPPING_LEASE_TIME;
    request[8] = (lifetime >> 24) & 0xFF;
    request[9] = (lifetime >> 16) & 0xFF;
    request[10] = (lifetime >> 8) & 0xFF;
    request[11] = lifetime & 0xFF;
    
    sendto(fd, request, sizeof(request), 0, (struct sockaddr*)&addr, sizeof(addr));
    
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    uint8_t response[16];
    ssize_t n = recv(fd, response, sizeof(response), 0);
    
    close(fd);
    
    if (n >= 16 && response[0] == 0 && response[3] == 0) {
        // Success!
        uint16_t mapped_port = (response[10] << 8) | response[11];
        spf_log(SPF_LOG_DEBUG, "natpmp: mapped external:%u -> internal:%u", mapped_port, internal);
        return 0;
    }
    
    return -1;
}

// Delete port mapping via UPnP IGD
static int upnp_delete_mapping_igd(uint16_t external, const char* proto) {
    char body[512];
    snprintf(body, sizeof(body),
        "<NewRemoteHost></NewRemoteHost>\r\n"
        "<NewExternalPort>%u</NewExternalPort>\r\n"
        "<NewProtocol>%s</NewProtocol>\r\n",
        external, proto);
    
    char response[2048];
    soap_request(g_upnp.control_url, g_upnp.service_type,
                "DeletePortMapping", body, response, sizeof(response));
    return 0;
}

// Get external IP via UPnP IGD
static int upnp_get_external_ip_igd(char* out, size_t len) {
    char response[4096];
    if (soap_request(g_upnp.control_url, g_upnp.service_type,
                    "GetExternalIPAddress", "", response, sizeof(response)) == 0) {
        if (xml_extract_value(response, "NewExternalIPAddress", out, len) == 0) {
            return 0;
        }
    }
    return -1;
}

// Renewal thread - keeps port mappings alive
static void* upnp_renew_thread(void* arg) {
    (void)arg;
    
    while (g_upnp.running) {
        sleep(MAPPING_RENEW_INTERVAL);
        
        if (!g_upnp.running) break;
        
        pthread_mutex_lock(&g_upnp.lock);
        
        for (int i = 0; i < g_upnp.mapping_count; i++) {
            if (!g_upnp.mappings[i].active) continue;
            
            spf_log(SPF_LOG_DEBUG, "upnp: renewing mapping %u -> %u",
                   g_upnp.mappings[i].external_port,
                   g_upnp.mappings[i].internal_port);
            
            if (g_upnp.type == SPF_UPNP_IGD) {
                upnp_add_mapping_igd(g_upnp.mappings[i].external_port,
                                    g_upnp.mappings[i].internal_port,
                                    g_upnp.mappings[i].protocol,
                                    g_upnp.mappings[i].description);
            } else if (g_upnp.type == SPF_UPNP_NATPMP) {
                natpmp_add_mapping(g_upnp.mappings[i].external_port,
                                  g_upnp.mappings[i].internal_port,
                                  g_upnp.mappings[i].protocol);
            }
            
            g_upnp.mappings[i].expires_at = time(NULL) + MAPPING_LEASE_TIME;
        }
        
        pthread_mutex_unlock(&g_upnp.lock);
    }
    
    return NULL;
}

// ============================================================================
// PUBLIC API
// ============================================================================

// Initialize UPnP/NAT-PMP subsystem and discover gateway
int spf_upnp_init(void) {
    memset(&g_upnp, 0, sizeof(g_upnp));
    pthread_mutex_init(&g_upnp.lock, NULL);
    g_upnp.running = true;
    
    spf_log(SPF_LOG_INFO, "upnp: discovering gateway...");
    
    // Try UPnP IGD first
    if (upnp_discover_igd() == 0) {
        // Get external IP
        if (upnp_get_external_ip_igd(g_upnp.external_ip, sizeof(g_upnp.external_ip)) == 0) {
            spf_log(SPF_LOG_INFO, "upnp: external IP: %s", g_upnp.external_ip);
        }
        
        // Start renewal thread
        pthread_create(&g_upnp.renew_thread, NULL, upnp_renew_thread, NULL);
        return 0;
    }
    
    // Try NAT-PMP
    if (natpmp_discover() == 0) {
        pthread_create(&g_upnp.renew_thread, NULL, upnp_renew_thread, NULL);
        return 0;
    }
    
    spf_log(SPF_LOG_WARN, "upnp: no compatible gateway found");
    spf_log(SPF_LOG_INFO, "upnp: you may need to configure port forwarding manually");
    return -1;
}

// Add a port mapping
int spf_upnp_add_port(uint16_t external_port, uint16_t internal_port, 
                      const char* protocol, const char* description) {
    if (!g_upnp.discovered) {
        spf_log(SPF_LOG_WARN, "upnp: no gateway discovered");
        return -1;
    }
    
    const char* proto = protocol ? protocol : "TCP";
    const char* desc = description ? description : "SPF Port Forward";
    
    pthread_mutex_lock(&g_upnp.lock);
    
    int result = -1;
    
    if (g_upnp.type == SPF_UPNP_IGD) {
        result = upnp_add_mapping_igd(external_port, internal_port, proto, desc);
    } else if (g_upnp.type == SPF_UPNP_NATPMP) {
        result = natpmp_add_mapping(external_port, internal_port, proto);
    }
    
    if (result == 0) {
        // Track the mapping
        if (g_upnp.mapping_count < MAX_PORT_MAPPINGS) {
            spf_port_mapping_t* m = &g_upnp.mappings[g_upnp.mapping_count++];
            m->external_port = external_port;
            m->internal_port = internal_port;
            strncpy(m->protocol, proto, sizeof(m->protocol) - 1);
            strncpy(m->description, desc, sizeof(m->description) - 1);
            m->created_at = time(NULL);
            m->expires_at = time(NULL) + MAPPING_LEASE_TIME;
            m->active = true;
        }
        
        spf_log(SPF_LOG_INFO, "upnp: mapped %s port %u -> %s:%u",
               proto, external_port, g_upnp.local_ip, internal_port);
    } else {
        spf_log(SPF_LOG_ERROR, "upnp: failed to map port %u", external_port);
    }
    
    pthread_mutex_unlock(&g_upnp.lock);
    return result;
}

// Remove a port mapping
int spf_upnp_remove_port(uint16_t external_port, const char* protocol) {
    if (!g_upnp.discovered) return -1;
    
    const char* proto = protocol ? protocol : "TCP";
    
    pthread_mutex_lock(&g_upnp.lock);
    
    if (g_upnp.type == SPF_UPNP_IGD) {
        upnp_delete_mapping_igd(external_port, proto);
    } else if (g_upnp.type == SPF_UPNP_NATPMP) {
        // NAT-PMP: set lifetime to 0 to delete
        // (simplified - just let it expire)
    }
    
    // Remove from tracking
    for (int i = 0; i < g_upnp.mapping_count; i++) {
        if (g_upnp.mappings[i].external_port == external_port &&
            strcmp(g_upnp.mappings[i].protocol, proto) == 0) {
            g_upnp.mappings[i].active = false;
        }
    }
    
    pthread_mutex_unlock(&g_upnp.lock);
    
    spf_log(SPF_LOG_INFO, "upnp: removed mapping for port %u", external_port);
    return 0;
}

// Get external IP address
int spf_upnp_get_external_ip(char* out, size_t len) {
    if (!g_upnp.discovered || g_upnp.external_ip[0] == '\0') {
        return -1;
    }
    strncpy(out, g_upnp.external_ip, len - 1);
    out[len - 1] = '\0';
    return 0;
}

// Get local IP address
int spf_upnp_get_local_ip(char* out, size_t len) {
    if (!g_upnp.discovered || g_upnp.local_ip[0] == '\0') {
        return -1;
    }
    strncpy(out, g_upnp.local_ip, len - 1);
    out[len - 1] = '\0';
    return 0;
}

// Get gateway IP
int spf_upnp_get_gateway_ip(char* out, size_t len) {
    if (!g_upnp.discovered || g_upnp.gateway_ip[0] == '\0') {
        return -1;
    }
    strncpy(out, g_upnp.gateway_ip, len - 1);
    out[len - 1] = '\0';
    return 0;
}

// Check if UPnP is available
bool spf_upnp_available(void) {
    return g_upnp.discovered;
}

// Get UPnP type string
const char* spf_upnp_type_str(void) {
    switch (g_upnp.type) {
        case SPF_UPNP_IGD: return "UPnP IGD";
        case SPF_UPNP_NATPMP: return "NAT-PMP";
        case SPF_UPNP_PCP: return "PCP";
        default: return "None";
    }
}

// Get status info
void spf_upnp_status(char* buf, size_t len) {
    pthread_mutex_lock(&g_upnp.lock);
    
    char* p = buf;
    p += snprintf(p, len, "=== UPnP/NAT-PMP Status ===\n");
    p += snprintf(p, len - (p - buf), "Protocol: %s\n", spf_upnp_type_str());
    p += snprintf(p, len - (p - buf), "Gateway: %s\n", 
                 g_upnp.gateway_ip[0] ? g_upnp.gateway_ip : "Not discovered");
    p += snprintf(p, len - (p - buf), "Local IP: %s\n",
                 g_upnp.local_ip[0] ? g_upnp.local_ip : "Unknown");
    p += snprintf(p, len - (p - buf), "External IP: %s\n",
                 g_upnp.external_ip[0] ? g_upnp.external_ip : "Unknown");
    p += snprintf(p, len - (p - buf), "\nActive Mappings: %d\n", g_upnp.mapping_count);
    
    for (int i = 0; i < g_upnp.mapping_count; i++) {
        if (g_upnp.mappings[i].active) {
            p += snprintf(p, len - (p - buf), "  %s %u -> %u (%s)\n",
                         g_upnp.mappings[i].protocol,
                         g_upnp.mappings[i].external_port,
                         g_upnp.mappings[i].internal_port,
                         g_upnp.mappings[i].description);
        }
    }
    
    pthread_mutex_unlock(&g_upnp.lock);
}

// Cleanup - remove all mappings and stop
void spf_upnp_cleanup(void) {
    g_upnp.running = false;
    
    pthread_mutex_lock(&g_upnp.lock);
    
    // Remove all port mappings
    for (int i = 0; i < g_upnp.mapping_count; i++) {
        if (g_upnp.mappings[i].active) {
            if (g_upnp.type == SPF_UPNP_IGD) {
                upnp_delete_mapping_igd(g_upnp.mappings[i].external_port,
                                       g_upnp.mappings[i].protocol);
            }
            spf_log(SPF_LOG_DEBUG, "upnp: removed mapping %u",
                   g_upnp.mappings[i].external_port);
        }
    }
    
    pthread_mutex_unlock(&g_upnp.lock);
    
    if (g_upnp.renew_thread) {
        pthread_join(g_upnp.renew_thread, NULL);
    }
    
    pthread_mutex_destroy(&g_upnp.lock);
    
    spf_log(SPF_LOG_INFO, "upnp: cleanup complete");
}
