/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl - IPv6-first TCP/UDP proxy
 *
 * Minimal header with only what's actually needed.
 * Linux kernel style: simple, focused, no bloat.
 */

#ifndef TUNL_COMMON_H
#define TUNL_COMMON_H

/* Enable POSIX features (if not already set by compiler) */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <pthread.h>

#define TUNL_VERSION "2.0.0"

/* Limits - sized for typical home hosting, not enterprise */
#define TUNL_MAX_RULES		16
#define TUNL_MAX_BACKENDS	4
#define TUNL_MAX_CONNECTIONS	512
#define TUNL_MAX_BLOCKLIST	1024

/* Buffer sizes */
#define TUNL_BUFFER_SIZE	8192
#define TUNL_IP_MAX_LEN		46	/* INET6_ADDRSTRLEN */
#define TUNL_PATH_MAX		256
#define TUNL_TOKEN_MAX		64

/* Default ports */
#define TUNL_CTRL_PORT		8081
#define TUNL_METRICS_PORT	9100

/* Rate limiting defaults */
#define TUNL_RATE_WINDOW_SEC	30
#define TUNL_RATE_THRESHOLD	20
#define TUNL_BLOCK_DURATION_SEC	600

/* Protocol types */
typedef enum {
	TUNL_PROTO_TCP = 0,
	TUNL_PROTO_UDP
} tunl_proto_t;

/* Load balancing algorithms */
typedef enum {
	TUNL_LB_ROUNDROBIN = 0,
	TUNL_LB_LEASTCONN,
	TUNL_LB_IPHASH
} tunl_lb_algo_t;

/* Backend health states */
typedef enum {
	TUNL_BACKEND_UP = 0,
	TUNL_BACKEND_DOWN
} tunl_backend_state_t;

/* Log levels */
typedef enum {
	TUNL_LOG_DEBUG = 0,
	TUNL_LOG_INFO,
	TUNL_LOG_WARN,
	TUNL_LOG_ERROR
} tunl_log_level_t;

/*
 * Backend - single upstream server
 */
struct tunl_backend {
	char			host[TUNL_IP_MAX_LEN];
	uint16_t		port;
	tunl_backend_state_t	state;
	uint32_t		active_conns;
	uint64_t		total_conns;
	bool			healthy;	/* for TUI display */
	uint32_t		last_rtt_ms;
	uint64_t		last_check_ms;
};

/*
 * Rule - forwarding rule mapping port to backends
 */
struct tunl_rule {
	uint32_t		id;
	uint16_t		listen_port;
	tunl_proto_t		protocol;
	tunl_lb_algo_t		lb_algo;
	struct tunl_backend	backends[TUNL_MAX_BACKENDS];
	uint8_t			backend_count;
	uint32_t		rr_index;	/* round-robin counter */
	uint32_t		max_conns;
	uint32_t		active_conns;
	bool			enabled;
	bool			tls;		/* TLS termination */
	pthread_t		listen_thread;
	pthread_mutex_t		lock;
};

/*
 * IP tracker for rate limiting
 */
struct tunl_tracker {
	char		ip[TUNL_IP_MAX_LEN];
	uint32_t	count;
	uint64_t	window_start;
	uint64_t	block_until;
	uint8_t		strikes;
};

/*
 * Global state
 */
struct tunl_state {
	struct tunl_rule	rules[TUNL_MAX_RULES];
	struct tunl_tracker	trackers[TUNL_MAX_BLOCKLIST];
	uint32_t		rule_count;
	uint32_t		tracker_count;
	uint32_t		session_count;	/* active sessions for TUI */
	uint64_t		total_conns;
	uint64_t		bytes_in;	/* live counter for TUI */
	uint64_t		bytes_out;	/* live counter for TUI */
	uint64_t		total_bytes_in;
	uint64_t		total_bytes_out;
	uint64_t		start_time;
	volatile bool		running;
	pthread_mutex_t		lock;

	/* Config */
	char			bind_addr[TUNL_IP_MAX_LEN];
	uint16_t		ctrl_port;
	uint16_t		metrics_port;
	tunl_log_level_t	log_level;
	bool			log_json;
	char			token[TUNL_TOKEN_MAX];
};

#ifdef __cplusplus
extern "C" {
#endif

/* Global state instance */
extern struct tunl_state g_state;

/* Core functions */
void tunl_init(struct tunl_state *state);
void tunl_shutdown(struct tunl_state *state);

/* Rule management */
int tunl_add_rule(struct tunl_state *state, const struct tunl_rule *rule);
int tunl_del_rule(struct tunl_state *state, uint32_t rule_id);
struct tunl_rule *tunl_get_rule(struct tunl_state *state, uint32_t rule_id);

/* Rate limiting */
bool tunl_rate_check(struct tunl_state *state, const char *ip);
void tunl_block_ip(struct tunl_state *state, const char *ip, uint64_t duration);
void tunl_unblock_ip(struct tunl_state *state, const char *ip);
bool tunl_is_blocked(struct tunl_state *state, const char *ip);

/* Load balancing */
int tunl_select_backend(struct tunl_rule *rule, const char *client_ip);
void tunl_backend_conn_start(struct tunl_rule *rule, int idx);
void tunl_backend_conn_end(struct tunl_rule *rule, int idx);

/* Config */
int tunl_load_config(struct tunl_state *state, const char *path);

/* Utilities */
void tunl_log(tunl_log_level_t level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
uint64_t tunl_time_ms(void);
uint64_t tunl_time_sec(void);
uint32_t tunl_hash_ip(const char *ip);
void tunl_random_bytes(uint8_t *buf, size_t len);
bool tunl_verify_token(struct tunl_state *state, const char *token);
void tunl_generate_token(char *buf, size_t len);

/* Health checks */
void *tunl_health_worker(void *arg);

/* DNS dynamic update */
int dns_init(const char *provider, const char *hostname, const char *token);
int dns_update(const char *hostname, const char *ip, int af);
void *dns_monitor_thread(void *arg);
void dns_status(char *buf, size_t len);

/* ACME / Let's Encrypt */
int acme_init(const char *domain, const char *email, int staging);
int acme_ensure_cert(void);
const char *acme_get_cert_path(void);
const char *acme_get_key_path(void);
void *acme_renewal_thread(void *arg);
void acme_status(char *buf, size_t len);

/* Reachability check */
int check_connectivity(const char *hostname, int port);
int check_quick(const char *hostname, int port);

/* TUI */
int tui_run(void);
int tui_standalone(const char *ctrl_path);

/* TLS (optional) */
struct ssl_st;
struct ssl_ctx_st;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

int tunl_tls_init(const char *cert, const char *key);
void tunl_tls_cleanup(void);
SSL *tunl_tls_accept(int fd);
SSL *tunl_tls_connect(int fd, const char *hostname);
ssize_t tunl_tls_read(SSL *ssl, void *buf, size_t len);
ssize_t tunl_tls_write(SSL *ssl, const void *buf, size_t len);
void tunl_tls_close(SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif /* TUNL_COMMON_H */
