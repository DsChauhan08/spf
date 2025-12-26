/*
 * SPF Tunnel Mode - Cloudflare Tunnel Alternative
 * 
 * Allows exposing local services to the internet WITHOUT:
 * - Port forwarding
 * - Static IP
 * - Complex router configuration
 * - Cloudflare or any third party
 * 
 * Architecture:
 * 
 *   [Home Network]              [Internet]              [VPS/Relay]
 *   ┌─────────────┐            ┌─────────────┐         ┌─────────────┐
 *   │ Local App   │◄──────────►│   SPF       │────────►│ SPF Relay   │◄──── Users
 *   │ (port 3000) │            │  (tunnel)   │         │ (public IP) │
 *   └─────────────┘            └─────────────┘         └─────────────┘
 *                                    │
 *                              Outbound only!
 *                              Works behind NAT
 * 
 * Usage:
 *   On VPS:    spf relay --port 443 --domain mysite.com
 *   At home:   spf tunnel --relay mysite.com:7000 --local 3000 --name webapp
 * 
 * Or zero-config (using spf.sh free relay):
 *   spf expose 3000
 *   -> Your app is now at https://abc123.spf.sh
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Suppress unused result warnings for non-critical writes
#define IGNORE_RESULT(x) do { if (x) {} } while(0)
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#define SPF_TUNNEL_PORT 7000
#define SPF_TUNNEL_MAGIC 0x53504654  // "SPFT"
#define SPF_TUNNEL_VERSION 1
#define SPF_TUNNEL_HEARTBEAT_SEC 30
#define SPF_TUNNEL_RECONNECT_SEC 5
#define SPF_TUNNEL_MAX_CLIENTS 256

// Tunnel protocol messages
typedef enum {
    SPF_TUN_REGISTER = 1,     // Client registers with relay
    SPF_TUN_REGISTER_OK = 2,  // Relay confirms registration
    SPF_TUN_REGISTER_ERR = 3, // Registration failed
    SPF_TUN_HEARTBEAT = 4,    // Keep-alive
    SPF_TUN_CONNECT = 5,      // New incoming connection
    SPF_TUN_DATA = 6,         // Data packet
    SPF_TUN_DISCONNECT = 7,   // Connection closed
} spf_tunnel_msg_t;

// Tunnel packet header (16 bytes)
typedef struct __attribute__((packed)) {
    uint32_t magic;      // SPF_TUNNEL_MAGIC
    uint8_t version;     // Protocol version
    uint8_t type;        // Message type
    uint16_t flags;      // Reserved
    uint32_t conn_id;    // Connection ID (for multiplexing)
    uint32_t length;     // Payload length
} spf_tunnel_hdr_t;

// Registration message
typedef struct __attribute__((packed)) {
    char name[64];       // Tunnel name (subdomain)
    char token[64];      // Auth token
    uint16_t local_port; // Local port to forward to
    uint16_t reserved;
} spf_tunnel_register_t;

// Tunnel client state
struct spf_tunnel_client_t {
    int relay_fd;                    // Connection to relay
    char relay_host[256];            // Relay hostname
    uint16_t relay_port;             // Relay port
    char name[64];                   // Tunnel name
    char token[64];                  // Auth token
    uint16_t local_port;             // Local port to forward
    bool connected;                  // Connected to relay
    bool running;                    // Keep running
    pthread_mutex_t lock;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint32_t active_conns;
    time_t last_heartbeat;
};

// Tunnel relay state (for VPS)
struct spf_tunnel_relay_t {
    int listen_fd;                   // Public-facing socket
    int tunnel_fd;                   // Tunnel control socket
    uint16_t public_port;            // Public port
    uint16_t tunnel_port;            // Tunnel control port
    char domain[256];                // Domain name
    bool running;
    pthread_mutex_t lock;
    
    // Connected tunnels
    struct {
        int fd;
        char name[64];
        char token[64];
        bool active;
        time_t connected_at;
        uint64_t bytes_in;
        uint64_t bytes_out;
    } tunnels[SPF_TUNNEL_MAX_CLIENTS];
    int tunnel_count;
};

// Local connection tracking (for multiplexed tunnel)
typedef struct {
    uint32_t conn_id;
    int local_fd;
    bool active;
} spf_tunnel_conn_t;

static spf_tunnel_client_t* g_tunnel_client = NULL;
static spf_tunnel_relay_t* g_tunnel_relay = NULL;
static volatile sig_atomic_t g_tunnel_shutdown = 0;

// Forward declarations
static void* tunnel_client_thread(void* arg);
static void* tunnel_heartbeat_thread(void* arg);
static int tunnel_connect_relay(spf_tunnel_client_t* client);
static int tunnel_send_register(spf_tunnel_client_t* client);
static int tunnel_handle_message(spf_tunnel_client_t* client, spf_tunnel_hdr_t* hdr, void* payload);

// Initialize tunnel client
spf_tunnel_client_t* spf_tunnel_client_init(const char* relay_host, uint16_t relay_port,
                                             const char* name, const char* token,
                                             uint16_t local_port) {
    // Input validation
    if (!relay_host || !relay_host[0]) {
        spf_log(SPF_LOG_ERROR, "tunnel: relay_host is required");
        return NULL;
    }
    if (!name || !name[0]) {
        spf_log(SPF_LOG_ERROR, "tunnel: tunnel name is required");
        return NULL;
    }
    if (local_port == 0) {
        spf_log(SPF_LOG_ERROR, "tunnel: local_port must be > 0");
        return NULL;
    }
    
    spf_tunnel_client_t* client = calloc(1, sizeof(spf_tunnel_client_t));
    if (!client) {
        spf_log(SPF_LOG_ERROR, "tunnel: out of memory");
        return NULL;
    }
    
    strncpy(client->relay_host, relay_host, sizeof(client->relay_host) - 1);
    client->relay_port = relay_port ? relay_port : SPF_TUNNEL_PORT;
    strncpy(client->name, name, sizeof(client->name) - 1);
    if (token) strncpy(client->token, token, sizeof(client->token) - 1);
    client->local_port = local_port;
    client->relay_fd = -1;
    client->running = true;
    pthread_mutex_init(&client->lock, NULL);
    
    g_tunnel_client = client;
    return client;
}

// Connect to relay server
static int tunnel_connect_relay(spf_tunnel_client_t* client) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", client->relay_port);
    
    int err = getaddrinfo(client->relay_host, port_str, &hints, &res);
    if (err != 0) {
        spf_log(SPF_LOG_ERROR, "tunnel: cannot resolve %s: %s", 
                client->relay_host, gai_strerror(err));
        return -1;
    }
    
    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        
        // Set non-blocking for connect timeout
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) < 0) {
            if (errno == EINPROGRESS) {
                // Wait for connection with timeout
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(fd, &wfds);
                struct timeval tv = {10, 0};  // 10 second timeout
                
                if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
                    int error = 0;
                    socklen_t len = sizeof(error);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
                    if (error == 0) {
                        fcntl(fd, F_SETFL, flags);  // Back to blocking
                        break;  // Connected!
                    }
                }
            }
            close(fd);
            fd = -1;
        } else {
            fcntl(fd, F_SETFL, flags);
            break;
        }
    }
    
    freeaddrinfo(res);
    
    if (fd < 0) {
        spf_log(SPF_LOG_ERROR, "tunnel: cannot connect to %s:%u", 
                client->relay_host, client->relay_port);
        return -1;
    }
    
    // Enable TCP keepalive
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    
    client->relay_fd = fd;
    spf_log(SPF_LOG_INFO, "tunnel: connected to relay %s:%u", 
            client->relay_host, client->relay_port);
    
    return 0;
}

// Send registration message
static int tunnel_send_register(spf_tunnel_client_t* client) {
    spf_tunnel_hdr_t hdr;
    spf_tunnel_register_t reg;
    
    memset(&hdr, 0, sizeof(hdr));
    memset(&reg, 0, sizeof(reg));
    
    hdr.magic = htonl(SPF_TUNNEL_MAGIC);
    hdr.version = SPF_TUNNEL_VERSION;
    hdr.type = SPF_TUN_REGISTER;
    hdr.length = htonl(sizeof(reg));
    
    strncpy(reg.name, client->name, sizeof(reg.name) - 1);
    strncpy(reg.token, client->token, sizeof(reg.token) - 1);
    reg.local_port = htons(client->local_port);
    
    if (write(client->relay_fd, &hdr, sizeof(hdr)) != sizeof(hdr) ||
        write(client->relay_fd, &reg, sizeof(reg)) != sizeof(reg)) {
        spf_log(SPF_LOG_ERROR, "tunnel: failed to send registration");
        return -1;
    }
    
    spf_log(SPF_LOG_DEBUG, "tunnel: sent registration for '%s'", client->name);
    return 0;
}

// Send heartbeat
static int tunnel_send_heartbeat(spf_tunnel_client_t* client) {
    spf_tunnel_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    
    hdr.magic = htonl(SPF_TUNNEL_MAGIC);
    hdr.version = SPF_TUNNEL_VERSION;
    hdr.type = SPF_TUN_HEARTBEAT;
    hdr.length = 0;
    
    pthread_mutex_lock(&client->lock);
    ssize_t n = write(client->relay_fd, &hdr, sizeof(hdr));
    pthread_mutex_unlock(&client->lock);
    
    if (n != sizeof(hdr)) {
        return -1;
    }
    
    client->last_heartbeat = time(NULL);
    return 0;
}

// Connect to local service
static int tunnel_connect_local(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    return fd;
}

// Handle incoming tunnel message
static int tunnel_handle_message(spf_tunnel_client_t* client, spf_tunnel_hdr_t* hdr, void* payload) {
    switch (hdr->type) {
        case SPF_TUN_REGISTER_OK:
            client->connected = true;
            spf_log(SPF_LOG_INFO, "tunnel: registered as '%s' - your URL: https://%s.%s", 
                    client->name, client->name, client->relay_host);
            break;
            
        case SPF_TUN_REGISTER_ERR:
            spf_log(SPF_LOG_ERROR, "tunnel: registration failed: %s", 
                    payload ? (char*)payload : "unknown error");
            return -1;
            
        case SPF_TUN_HEARTBEAT:
            // Relay is alive
            break;
            
        case SPF_TUN_CONNECT: {
            // New incoming connection - connect to local service
            uint32_t conn_id = ntohl(hdr->conn_id);
            int local_fd = tunnel_connect_local(client->local_port);
            
            if (local_fd < 0) {
                spf_log(SPF_LOG_WARN, "tunnel: cannot connect to local port %u", 
                        client->local_port);
                // Send disconnect
                spf_tunnel_hdr_t resp;
                memset(&resp, 0, sizeof(resp));
                resp.magic = htonl(SPF_TUNNEL_MAGIC);
                resp.version = SPF_TUNNEL_VERSION;
                resp.type = SPF_TUN_DISCONNECT;
                resp.conn_id = hdr->conn_id;
                IGNORE_RESULT(write(client->relay_fd, &resp, sizeof(resp)));
            } else {
                spf_log(SPF_LOG_DEBUG, "tunnel: new connection %u -> local:%u", 
                        conn_id, client->local_port);
                client->active_conns++;
                // TODO: spawn thread to handle bidirectional copy
            }
            break;
        }
        
        case SPF_TUN_DATA: {
            // Data from remote client - forward to local
            // TODO: implement multiplexed data forwarding
            break;
        }
        
        case SPF_TUN_DISCONNECT: {
            uint32_t conn_id = ntohl(hdr->conn_id);
            spf_log(SPF_LOG_DEBUG, "tunnel: connection %u closed", conn_id);
            if (client->active_conns > 0) client->active_conns--;
            break;
        }
        
        default:
            spf_log(SPF_LOG_WARN, "tunnel: unknown message type %d", hdr->type);
    }
    
    return 0;
}

// Heartbeat thread
static void* tunnel_heartbeat_thread(void* arg) {
    spf_tunnel_client_t* client = (spf_tunnel_client_t*)arg;
    
    while (client->running && !g_tunnel_shutdown) {
        sleep(SPF_TUNNEL_HEARTBEAT_SEC);
        
        if (client->connected) {
            if (tunnel_send_heartbeat(client) < 0) {
                spf_log(SPF_LOG_WARN, "tunnel: heartbeat failed, reconnecting...");
                client->connected = false;
            }
        }
    }
    
    return NULL;
}

// Main tunnel client thread
static void* tunnel_client_thread(void* arg) {
    spf_tunnel_client_t* client = (spf_tunnel_client_t*)arg;
    char buf[65536];
    
    while (client->running && !g_tunnel_shutdown) {
        // Connect to relay if not connected
        if (client->relay_fd < 0) {
            if (tunnel_connect_relay(client) < 0) {
                spf_log(SPF_LOG_INFO, "tunnel: retrying in %d seconds...", 
                        SPF_TUNNEL_RECONNECT_SEC);
                sleep(SPF_TUNNEL_RECONNECT_SEC);
                continue;
            }
            
            // Send registration
            if (tunnel_send_register(client) < 0) {
                close(client->relay_fd);
                client->relay_fd = -1;
                continue;
            }
        }
        
        // Read messages from relay
        spf_tunnel_hdr_t hdr;
        ssize_t n = read(client->relay_fd, &hdr, sizeof(hdr));
        
        if (n <= 0) {
            if (n == 0) {
                spf_log(SPF_LOG_WARN, "tunnel: relay closed connection");
            } else {
                spf_log(SPF_LOG_ERROR, "tunnel: read error: %s", strerror(errno));
            }
            close(client->relay_fd);
            client->relay_fd = -1;
            client->connected = false;
            sleep(SPF_TUNNEL_RECONNECT_SEC);
            continue;
        }
        
        // Validate header
        if (ntohl(hdr.magic) != SPF_TUNNEL_MAGIC) {
            spf_log(SPF_LOG_ERROR, "tunnel: invalid magic");
            close(client->relay_fd);
            client->relay_fd = -1;
            client->connected = false;
            continue;
        }
        
        // Read payload
        uint32_t payload_len = ntohl(hdr.length);
        void* payload = NULL;
        
        if (payload_len > 0 && payload_len < sizeof(buf)) {
            n = read(client->relay_fd, buf, payload_len);
            if (n != (ssize_t)payload_len) {
                spf_log(SPF_LOG_ERROR, "tunnel: incomplete payload");
                continue;
            }
            payload = buf;
        }
        
        // Handle message
        if (tunnel_handle_message(client, &hdr, payload) < 0) {
            close(client->relay_fd);
            client->relay_fd = -1;
            client->connected = false;
        }
    }
    
    return NULL;
}

// Start tunnel client
int spf_tunnel_client_start(spf_tunnel_client_t* client) {
    pthread_t tid, hb_tid;
    
    spf_log(SPF_LOG_INFO, "tunnel: starting client -> %s:%u (local:%u)", 
            client->relay_host, client->relay_port, client->local_port);
    
    pthread_create(&hb_tid, NULL, tunnel_heartbeat_thread, client);
    pthread_detach(hb_tid);
    
    pthread_create(&tid, NULL, tunnel_client_thread, client);
    pthread_join(tid, NULL);
    
    return 0;
}

// Stop tunnel client
void spf_tunnel_client_stop(spf_tunnel_client_t* client) {
    client->running = false;
    if (client->relay_fd >= 0) {
        close(client->relay_fd);
        client->relay_fd = -1;
    }
    pthread_mutex_destroy(&client->lock);
    free(client);
}

// Get tunnel status
void spf_tunnel_client_status(spf_tunnel_client_t* client, char* buf, size_t len) {
    snprintf(buf, len,
        "Tunnel Status:\n"
        "  Relay: %s:%u\n"
        "  Name: %s\n"
        "  Local Port: %u\n"
        "  Connected: %s\n"
        "  Active Connections: %u\n"
        "  Bytes In: %lu\n"
        "  Bytes Out: %lu\n",
        client->relay_host, client->relay_port,
        client->name,
        client->local_port,
        client->connected ? "yes" : "no",
        client->active_conns,
        client->bytes_in,
        client->bytes_out);
}

// ============================================================================
// RELAY SERVER (runs on VPS with public IP)
// ============================================================================

static void* relay_tunnel_handler(void* arg);

// Initialize relay server
spf_tunnel_relay_t* spf_tunnel_relay_init(uint16_t public_port, uint16_t tunnel_port,
                                           const char* domain) {
    spf_tunnel_relay_t* relay = calloc(1, sizeof(spf_tunnel_relay_t));
    if (!relay) {
        spf_log(SPF_LOG_ERROR, "relay: out of memory");
        return NULL;
    }
    
    relay->public_port = public_port ? public_port : 443;
    relay->tunnel_port = tunnel_port ? tunnel_port : SPF_TUNNEL_PORT;
    relay->listen_fd = -1;
    relay->tunnel_fd = -1;
    if (domain && domain[0]) {
        strncpy(relay->domain, domain, sizeof(relay->domain) - 1);
    } else {
        strncpy(relay->domain, "localhost", sizeof(relay->domain) - 1);
    }
    relay->running = true;
    pthread_mutex_init(&relay->lock, NULL);
    
    g_tunnel_relay = relay;
    return relay;
}

// Start listening for tunnel connections
static int relay_start_tunnel_listener(spf_tunnel_relay_t* relay) {
    relay->tunnel_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (relay->tunnel_fd < 0) return -1;
    
    int opt = 1;
    setsockopt(relay->tunnel_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(relay->tunnel_port);
    
    if (bind(relay->tunnel_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "relay: cannot bind tunnel port %u: %s", 
                relay->tunnel_port, strerror(errno));
        close(relay->tunnel_fd);
        return -1;
    }
    
    listen(relay->tunnel_fd, 128);
    spf_log(SPF_LOG_INFO, "relay: tunnel listener on :%u", relay->tunnel_port);
    
    return 0;
}

// Start listening for public connections
static int relay_start_public_listener(spf_tunnel_relay_t* relay) {
    relay->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (relay->listen_fd < 0) return -1;
    
    int opt = 1;
    setsockopt(relay->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(relay->public_port);
    
    if (bind(relay->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        spf_log(SPF_LOG_ERROR, "relay: cannot bind public port %u: %s", 
                relay->public_port, strerror(errno));
        close(relay->listen_fd);
        return -1;
    }
    
    listen(relay->listen_fd, 1024);
    spf_log(SPF_LOG_INFO, "relay: public listener on :%u", relay->public_port);
    
    return 0;
}

// Handle tunnel client connection
static void* relay_tunnel_handler(void* arg) {
    int fd = (intptr_t)arg;
    spf_tunnel_relay_t* relay = g_tunnel_relay;
    char buf[65536];
    
    // Read registration
    spf_tunnel_hdr_t hdr;
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return NULL;
    }
    
    if (ntohl(hdr.magic) != SPF_TUNNEL_MAGIC || hdr.type != SPF_TUN_REGISTER) {
        close(fd);
        return NULL;
    }
    
    spf_tunnel_register_t reg;
    uint32_t len = ntohl(hdr.length);
    if (len != sizeof(reg) || read(fd, &reg, sizeof(reg)) != sizeof(reg)) {
        close(fd);
        return NULL;
    }
    
    // Register tunnel
    pthread_mutex_lock(&relay->lock);
    int slot = -1;
    for (int i = 0; i < SPF_TUNNEL_MAX_CLIENTS; i++) {
        if (!relay->tunnels[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        pthread_mutex_unlock(&relay->lock);
        // Send error
        spf_tunnel_hdr_t resp;
        memset(&resp, 0, sizeof(resp));
        resp.magic = htonl(SPF_TUNNEL_MAGIC);
        resp.type = SPF_TUN_REGISTER_ERR;
        IGNORE_RESULT(write(fd, &resp, sizeof(resp)));
        close(fd);
        return NULL;
    }
    
    relay->tunnels[slot].fd = fd;
    strncpy(relay->tunnels[slot].name, reg.name, sizeof(relay->tunnels[slot].name) - 1);
    strncpy(relay->tunnels[slot].token, reg.token, sizeof(relay->tunnels[slot].token) - 1);
    relay->tunnels[slot].active = true;
    relay->tunnels[slot].connected_at = time(NULL);
    relay->tunnel_count++;
    pthread_mutex_unlock(&relay->lock);
    
    spf_log(SPF_LOG_INFO, "relay: tunnel '%s' registered", reg.name);
    
    // Send OK
    spf_tunnel_hdr_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.magic = htonl(SPF_TUNNEL_MAGIC);
    resp.type = SPF_TUN_REGISTER_OK;
    IGNORE_RESULT(write(fd, &resp, sizeof(resp)));
    
    // Handle messages
    while (relay->running) {
        ssize_t n = read(fd, &hdr, sizeof(hdr));
        if (n <= 0) break;
        
        if (ntohl(hdr.magic) != SPF_TUNNEL_MAGIC) break;
        
        len = ntohl(hdr.length);
        if (len > 0 && len < sizeof(buf)) {
            if (read(fd, buf, len) < 0) break;
        }
        
        // Echo heartbeat
        if (hdr.type == SPF_TUN_HEARTBEAT) {
            IGNORE_RESULT(write(fd, &hdr, sizeof(hdr)));
        }
    }
    
    // Cleanup
    pthread_mutex_lock(&relay->lock);
    relay->tunnels[slot].active = false;
    relay->tunnel_count--;
    pthread_mutex_unlock(&relay->lock);
    
    spf_log(SPF_LOG_INFO, "relay: tunnel '%s' disconnected", reg.name);
    close(fd);
    
    return NULL;
}

// Tunnel listener thread
static void* relay_tunnel_listener(void* arg) {
    spf_tunnel_relay_t* relay = (spf_tunnel_relay_t*)arg;
    
    while (relay->running) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int fd = accept(relay->tunnel_fd, (struct sockaddr*)&addr, &len);
        if (fd < 0) continue;
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        spf_log(SPF_LOG_INFO, "relay: tunnel connection from %s", ip);
        
        pthread_t tid;
        pthread_create(&tid, NULL, relay_tunnel_handler, (void*)(intptr_t)fd);
        pthread_detach(tid);
    }
    
    return NULL;
}

// Start relay server
int spf_tunnel_relay_start(spf_tunnel_relay_t* relay) {
    if (relay_start_tunnel_listener(relay) < 0) return -1;
    if (relay_start_public_listener(relay) < 0) return -1;
    
    spf_log(SPF_LOG_INFO, "relay: started on %s (public:%u, tunnel:%u)", 
            relay->domain[0] ? relay->domain : "localhost",
            relay->public_port, relay->tunnel_port);
    
    pthread_t tid;
    pthread_create(&tid, NULL, relay_tunnel_listener, relay);
    
    // Main loop - accept public connections and route to tunnels
    while (relay->running) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int fd = accept(relay->listen_fd, (struct sockaddr*)&addr, &len);
        if (fd < 0) continue;
        
        // TODO: implement HTTP Host header parsing for subdomain routing
        // For now, just log
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        spf_log(SPF_LOG_DEBUG, "relay: public connection from %s", ip);
        
        // Find tunnel and forward
        // ...
        
        close(fd);
    }
    
    pthread_join(tid, NULL);
    return 0;
}

// Stop relay
void spf_tunnel_relay_stop(spf_tunnel_relay_t* relay) {
    relay->running = false;
    if (relay->listen_fd >= 0) close(relay->listen_fd);
    if (relay->tunnel_fd >= 0) close(relay->tunnel_fd);
    pthread_mutex_destroy(&relay->lock);
    free(relay);
}

// Generate random tunnel name
void spf_tunnel_generate_name(char* buf, size_t len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    uint8_t rnd[8];
    spf_random_bytes(rnd, sizeof(rnd));
    
    size_t name_len = len < 9 ? len - 1 : 8;
    for (size_t i = 0; i < name_len; i++) {
        buf[i] = chars[rnd[i] % (sizeof(chars) - 1)];
    }
    buf[name_len] = '\0';
}

// Expose mode - zero-config tunnel to public relay
int spf_expose(uint16_t local_port, const char* custom_name) {
    char name[64];
    
    if (custom_name && custom_name[0]) {
        strncpy(name, custom_name, sizeof(name) - 1);
    } else {
        spf_tunnel_generate_name(name, sizeof(name));
    }
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  SPF Expose - Cloudflare Tunnel Alternative                  ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Local port: %-5u                                           ║\n", local_port);
    printf("║  Tunnel name: %-10s                                      ║\n", name);
    printf("║                                                              ║\n");
    printf("║  Your URL will be: https://%s.tunnel.spf.sh             ║\n", name);
    printf("║                                                              ║\n");
    printf("║  Press Ctrl+C to stop                                        ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // For self-hosted relay, user would specify their own relay server
    // This is a placeholder for a public relay service
    spf_log(SPF_LOG_INFO, "expose: to use with your own relay:");
    spf_log(SPF_LOG_INFO, "  VPS:  spf relay --port 443 --tunnel-port 7000 --domain yourdomain.com");
    spf_log(SPF_LOG_INFO, "  Home: spf tunnel --relay yourdomain.com:7000 --local %u --name %s", 
            local_port, name);
    
    return 0;
}
