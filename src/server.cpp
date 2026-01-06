/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl - IPv6-first TCP proxy and self-hosting toolkit
 *
 * Unified CLI with subcommands:
 *   tunl serve    - Start proxy server
 *   tunl dns      - DNS management and monitoring
 *   tunl cert     - TLS certificate management
 *   tunl check    - Reachability self-test
 *   tunl tui      - Terminal dashboard
 *
 * Linux kernel style: minimal, correct, no bloat.
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <termios.h>

#define LISTEN_BACKLOG	128
#define RECV_TIMEOUT	30
#define CONN_TIMEOUT	5

static volatile sig_atomic_t g_shutdown;
static int g_ctrl_fd = -1;
static void start_rule_workers(struct tunl_rule *rule)
{
	if (!rule || !rule->enabled || rule->backend_count == 0)
		return;

	pthread_t tid;

	if (pthread_create(&tid, NULL, tunl_health_worker, rule) == 0)
		pthread_detach(tid);
	else
		tunl_log(TUNL_LOG_WARN, "health thread start failed for port %u",
			rule->listen_port);
}

/* ============================================================================
 * Socket Helpers
 * ============================================================================ */

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_reuseaddr(int fd)
{
	int opt = 1;

	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static int set_nodelay(int fd)
{
	int opt = 1;

	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

static ssize_t send_all_nb(int fd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;
	int retries = 0;

	while (sent < len) {
		ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);

		if (n > 0) {
			sent += (size_t)n;
			retries = 0;
			continue;
		}

		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			if (retries++ > 5)
				break;
			usleep(1000);
			continue;
		}

		return -1;
	}

	return (ssize_t)sent;
}

static void get_ip_string(const struct sockaddr_storage *addr,
			  char *buf, size_t len)
{
	if (!addr || !buf || len < INET6_ADDRSTRLEN) {
		if (buf && len > 0)
			buf[0] = '\0';
		return;
	}

	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *s6 =
			(const struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &s6->sin6_addr, buf, (socklen_t)len);
	} else if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *s4 =
			(const struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &s4->sin_addr, buf, (socklen_t)len);
	} else {
		snprintf(buf, len, "[af%d]", addr->ss_family);
	}
}

static int create_listen_socket(uint16_t port, const char *bind_addr)
{
	int fd, opt;
	struct sockaddr_in6 addr6;
	struct sockaddr_in addr4;

	/* Try IPv6 dual-stack first */
	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd >= 0) {
		set_reuseaddr(fd);
		opt = 0;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);

		if (bind_addr && bind_addr[0]) {
			if (inet_pton(AF_INET6, bind_addr, &addr6.sin6_addr) != 1) {
				/* Try IPv4-mapped */
				struct in_addr v4;

				if (inet_pton(AF_INET, bind_addr, &v4) == 1) {
					memset(&addr6.sin6_addr, 0, 10);
					memset(((uint8_t *)&addr6.sin6_addr) + 10, 0xff, 2);
					memcpy(((uint8_t *)&addr6.sin6_addr) + 12, &v4, 4);
				}
			}
		} else {
			addr6.sin6_addr = in6addr_any;
		}

		if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0 &&
		    listen(fd, LISTEN_BACKLOG) == 0)
			return fd;
		close(fd);
	}

	/* Fallback to IPv4 */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	set_reuseaddr(fd);

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(port);

	if (bind_addr && bind_addr[0])
		inet_pton(AF_INET, bind_addr, &addr4.sin_addr);
	else
		addr4.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) < 0 ||
	    listen(fd, LISTEN_BACKLOG) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int create_udp_socket(uint16_t port, const char *bind_addr)
{
	int fd;
	struct sockaddr_in6 addr6;
	struct sockaddr_in addr4;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd >= 0) {
		int opt = 0;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		if (bind_addr && bind_addr[0]) {
			if (inet_pton(AF_INET6, bind_addr, &addr6.sin6_addr) != 1) {
				struct in_addr v4;
				if (inet_pton(AF_INET, bind_addr, &v4) == 1) {
					memset(&addr6.sin6_addr, 0, 10);
					memset(((uint8_t *)&addr6.sin6_addr) + 10, 0xff, 2);
					memcpy(((uint8_t *)&addr6.sin6_addr) + 12, &v4, 4);
				}
			}
		} else {
			addr6.sin6_addr = in6addr_any;
		}
		if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0)
			return fd;
		close(fd);
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(port);
	if (bind_addr && bind_addr[0])
		inet_pton(AF_INET, bind_addr, &addr4.sin_addr);
	else
		addr4.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int connect_to_backend(const char *host, uint16_t port, int timeout_sec)
{
	struct addrinfo hints, *res, *rp;
	char port_str[8];
	int fd = -1;

	if (!host || !host[0])
		return -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_str, sizeof(port_str), "%u", port);
	if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
		return -1;

	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;

		set_nonblocking(fd);

		int ret = connect(fd, rp->ai_addr, rp->ai_addrlen);

		if (ret == 0)
			break;

		if (errno != EINPROGRESS) {
			close(fd);
			fd = -1;
			continue;
		}

		/* Wait for connect with timeout */
		fd_set wfds;
		struct timeval tv = {timeout_sec, 0};

		FD_ZERO(&wfds);
		FD_SET(fd, &wfds);

		ret = select(fd + 1, NULL, &wfds, NULL, &tv);
		if (ret <= 0) {
			close(fd);
			fd = -1;
			continue;
		}

		int err = 0;
		socklen_t optlen = sizeof(err);

		getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &optlen);
		if (err != 0) {
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(res);
	return fd;
}

/* ============================================================================
 * Session Management
 * ============================================================================ */

struct session {
	int			client_fd;
	int			backend_fd;
	struct sockaddr_storage	client_addr;
	struct tunl_rule	*rule;
	int			backend_idx;
	uint64_t		bytes_in;
	uint64_t		bytes_out;
	bool			active;
};

static void session_run(struct session *s)
{
	int epfd;
	struct epoll_event ev, events[2];
	uint8_t buf[TUNL_BUFFER_SIZE];

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		return;

	set_nonblocking(s->client_fd);
	set_nonblocking(s->backend_fd);
	set_nodelay(s->client_fd);
	set_nodelay(s->backend_fd);

	ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	ev.data.fd = s->client_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, s->client_fd, &ev) < 0) {
		close(epfd);
		return;
	}

	ev.data.fd = s->backend_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, s->backend_fd, &ev) < 0) {
		close(epfd);
		return;
	}

	while (!g_shutdown && s->active) {
		int nfds = epoll_wait(epfd, events, 2, RECV_TIMEOUT * 1000);

		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (nfds == 0)
			break;

		for (int i = 0; i < nfds; i++) {
			if (events[i].events & (EPOLLHUP | EPOLLERR)) {
				s->active = false;
				break;
			}

			if (events[i].data.fd == s->client_fd) {
				ssize_t n = recv(s->client_fd, buf, sizeof(buf), 0);

				if (n <= 0) {
					s->active = false;
					break;
				}
				if (send_all_nb(s->backend_fd, buf, (size_t)n) != n) {
					s->active = false;
					break;
				}
				s->bytes_in += (uint64_t)n;
			} else if (events[i].data.fd == s->backend_fd) {
				ssize_t n = recv(s->backend_fd, buf, sizeof(buf), 0);

				if (n <= 0) {
					s->active = false;
					break;
				}
				if (send_all_nb(s->client_fd, buf, (size_t)n) != n) {
					s->active = false;
					break;
				}
				s->bytes_out += (uint64_t)n;
			}
		}
	}

	close(epfd);
}

static void *session_thread(void *arg)
{
	struct session *s = (struct session *)arg;

	if (!s)
		return NULL;

	tunl_backend_conn_start(s->rule, s->backend_idx);
	s->active = true;

	pthread_mutex_lock(&g_state.lock);
	g_state.session_count++;
	pthread_mutex_unlock(&g_state.lock);

	session_run(s);

	close(s->client_fd);
	close(s->backend_fd);
	tunl_backend_conn_end(s->rule, s->backend_idx);

	pthread_mutex_lock(&g_state.lock);
	g_state.session_count--;
	g_state.total_bytes_in += s->bytes_in;
	g_state.total_bytes_out += s->bytes_out;
	g_state.bytes_in += s->bytes_in;
	g_state.bytes_out += s->bytes_out;
	pthread_mutex_unlock(&g_state.lock);

	free(s);
	return NULL;
}

/* ============================================================================
 * Listener
 * ============================================================================ */

static void *listener_thread(void *arg)
{
	struct tunl_rule *rule = (struct tunl_rule *)arg;
	char ip[INET6_ADDRSTRLEN];
	int lfd;

	lfd = create_listen_socket(rule->listen_port, g_state.bind_addr);
	if (lfd < 0) {
		tunl_log(TUNL_LOG_ERROR, "bind port %u failed", rule->listen_port);
		return NULL;
	}

	tunl_log(TUNL_LOG_INFO, "listening on [::]:%u", rule->listen_port);

	while (!g_shutdown && g_state.running && rule->enabled) {
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);
		int cfd = accept(lfd, (struct sockaddr *)&addr, &addrlen);

		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		get_ip_string(&addr, ip, sizeof(ip));

		/* Rate limit check */
		if (!tunl_rate_check(&g_state, ip)) {
			close(cfd);
			continue;
		}

		/* Connection limit check */
		pthread_mutex_lock(&rule->lock);
		if (rule->max_conns && rule->active_conns >= rule->max_conns) {
			pthread_mutex_unlock(&rule->lock);
			close(cfd);
			continue;
		}
		pthread_mutex_unlock(&rule->lock);

		/* Select backend */
		int backend_idx = tunl_select_backend(rule, ip);

		if (backend_idx < 0) {
			close(cfd);
			continue;
		}

		/* Connect to backend */
		int bfd = connect_to_backend(rule->backends[backend_idx].host,
					     rule->backends[backend_idx].port,
					     CONN_TIMEOUT);
		if (bfd < 0) {
			close(cfd);
			continue;
		}

		/* Create session */
		struct session *sess = (struct session *)calloc(1, sizeof(*sess));

		if (!sess) {
			close(cfd);
			close(bfd);
			continue;
		}

		sess->client_fd = cfd;
		sess->backend_fd = bfd;
		memcpy(&sess->client_addr, &addr, sizeof(addr));
		sess->rule = rule;
		sess->backend_idx = backend_idx;

		pthread_t tid;

		if (pthread_create(&tid, NULL, session_thread, sess) != 0) {
			close(cfd);
			close(bfd);
			free(sess);
			continue;
		}
		pthread_detach(tid);

		pthread_mutex_lock(&g_state.lock);
		g_state.total_conns++;
		pthread_mutex_unlock(&g_state.lock);
	}

	close(lfd);
	tunl_log(TUNL_LOG_INFO, "listener stopped for port %u", rule->listen_port);
	return NULL;
}

static int udp_send_recv(struct tunl_rule *rule, int backend_idx,
			 const uint8_t *buf, ssize_t len,
			 struct sockaddr_storage *client, socklen_t client_len,
			 int lfd)
{
	struct tunl_backend *be = &rule->backends[backend_idx];
	struct addrinfo hints, *res = NULL;
	char port_str[8];
	int sfd = -1;
	int ret = -1;
	uint8_t rbuf[TUNL_BUFFER_SIZE];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	snprintf(port_str, sizeof(port_str), "%u", be->port);
	if (getaddrinfo(be->host, port_str, &hints, &res) != 0 || !res)
		return -1;

	for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd < 0)
			continue;
		if (sendto(sfd, buf, (size_t)len, 0, rp->ai_addr, rp->ai_addrlen) < 0) {
			close(sfd);
			sfd = -1;
			continue;
		}
		struct timeval tv = {1, 0};
		setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		ssize_t n = recvfrom(sfd, rbuf, sizeof(rbuf), 0, NULL, NULL);
		if (n > 0) {
			if (sendto(lfd, rbuf, (size_t)n, 0,
				   (struct sockaddr *)client, client_len) == n)
				ret = 0;
		}
		close(sfd);
		if (ret == 0)
			break;
	}

	freeaddrinfo(res);
	return ret;
}

static void *udp_listener_thread(void *arg)
{
	struct tunl_rule *rule = (struct tunl_rule *)arg;
	int lfd;

	lfd = create_udp_socket(rule->listen_port, g_state.bind_addr);
	if (lfd < 0) {
		tunl_log(TUNL_LOG_ERROR, "udp bind port %u failed", rule->listen_port);
		return NULL;
	}

	tunl_log(TUNL_LOG_INFO, "udp listening on [%s]:%u",
		 g_state.bind_addr[0] ? g_state.bind_addr : "::",
		 rule->listen_port);

	while (!g_shutdown && g_state.running && rule->enabled) {
		uint8_t buf[TUNL_BUFFER_SIZE];
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);
		ssize_t n = recvfrom(lfd, buf, sizeof(buf), 0,
				(struct sockaddr *)&addr, &addrlen);
		if (n <= 0)
			continue;

		char ip[INET6_ADDRSTRLEN];
		get_ip_string(&addr, ip, sizeof(ip));
		if (!tunl_rate_check(&g_state, ip))
			continue;

		int backend_idx = tunl_select_backend(rule, ip);
		if (backend_idx < 0)
			continue;

		tunl_backend_conn_start(rule, backend_idx);
		udp_send_recv(rule, backend_idx, buf, n, &addr, addrlen, lfd);
		tunl_backend_conn_end(rule, backend_idx);
	}

	close(lfd);
	return NULL;
}

/* ============================================================================
 * Control Interface
 * ============================================================================ */

static void ctrl_send(int fd, const char *msg)
{
	if (msg)
		send(fd, msg, strlen(msg), MSG_NOSIGNAL);
}

static void handle_ctrl(int fd)
{
	char buf[512], resp[2048];
	bool authed = (g_state.token[0] == '\0');

	ctrl_send(fd, "tunl v" TUNL_VERSION "\n");
	if (!authed)
		ctrl_send(fd, "AUTH required\n");
	ctrl_send(fd, "> ");

	while (!g_shutdown) {
		ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);

		if (n <= 0)
			break;
		buf[n] = '\0';

		while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r'))
			buf[--n] = '\0';

		if (n == 0) {
			ctrl_send(fd, "> ");
			continue;
		}

		resp[0] = '\0';

		if (strncmp(buf, "QUIT", 4) == 0) {
			break;
		} else if (strncmp(buf, "AUTH ", 5) == 0) {
			if (tunl_verify_token(&g_state, buf + 5)) {
				authed = true;
				snprintf(resp, sizeof(resp), "OK\n");
			} else {
				snprintf(resp, sizeof(resp), "ERR bad token\n");
			}
		} else if (!authed) {
			snprintf(resp, sizeof(resp), "ERR auth required\n");
		} else if (strcmp(buf, "STATUS") == 0) {
			uint64_t up = tunl_time_sec() - g_state.start_time;

			snprintf(resp, sizeof(resp),
				 "uptime: %luh%lum\n"
				 "conns: %lu total\n"
				 "bytes: %lu in, %lu out\n"
				 "rules: %u\n",
				 (unsigned long)(up / 3600),
				 (unsigned long)((up % 3600) / 60),
				 (unsigned long)g_state.total_conns,
				 (unsigned long)g_state.total_bytes_in,
				 (unsigned long)g_state.total_bytes_out,
				 g_state.rule_count);
		} else if (strcmp(buf, "RULES") == 0) {
			char *p = resp;
			size_t rem = sizeof(resp);

			for (int i = 0; i < TUNL_MAX_RULES && rem > 100; i++) {
				if (!g_state.rules[i].enabled)
					continue;
				int w = snprintf(p, rem, "rule %u: port %u, %u backends\n",
						 g_state.rules[i].id,
						 g_state.rules[i].listen_port,
						 g_state.rules[i].backend_count);
				if (w > 0 && (size_t)w < rem) {
					p += w;
					rem -= (size_t)w;
				}
			}
		} else if (strcmp(buf, "SHUTDOWN") == 0) {
			g_shutdown = 1;
			snprintf(resp, sizeof(resp), "OK\n");
		} else {
			snprintf(resp, sizeof(resp),
				 "commands: STATUS, RULES, QUIT, SHUTDOWN\n");
		}

		ctrl_send(fd, resp);
		ctrl_send(fd, "> ");
	}

	close(fd);
}

static void *ctrl_thread(void *arg)
{
	(void)arg;

	g_ctrl_fd = create_listen_socket(g_state.ctrl_port, g_state.bind_addr);
	if (g_ctrl_fd < 0) {
		tunl_log(TUNL_LOG_ERROR, "ctrl bind failed");
		return NULL;
	}

	tunl_log(TUNL_LOG_INFO, "ctrl on [%s]:%u",
		 g_state.bind_addr[0] ? g_state.bind_addr : "::",
		 g_state.ctrl_port);

	while (!g_shutdown && g_state.running) {
		int cfd = accept(g_ctrl_fd, NULL, NULL);

		if (cfd >= 0)
			handle_ctrl(cfd);
	}

	close(g_ctrl_fd);
	return NULL;
}

/* ============================================================================
 * Metrics Endpoint (Prometheus text format)
 * ============================================================================ */

static void metrics_emit(int fd)
{
	char buf[16384];
	size_t off = 0;

	#define APPEND_FMT(...) do { \
		off += (size_t)snprintf(buf + off, sizeof(buf) - off, __VA_ARGS__); \
	} while (0)
	#define APPEND_STR(str) do { \
		size_t l = strlen(str); \
		if (off + l < sizeof(buf)) { memcpy(buf + off, str, l); off += l; } \
	} while (0)

	pthread_mutex_lock(&g_state.lock);
	APPEND_STR("# HELP tunl_info Build info\n");
	APPEND_STR("# TYPE tunl_info gauge\n");
	APPEND_FMT("tunl_info{version=\"%s\"} 1\n", TUNL_VERSION);
	APPEND_STR("# HELP tunl_sessions_active Active sessions\n");
	APPEND_STR("# TYPE tunl_sessions_active gauge\n");
	APPEND_FMT("tunl_sessions_active %u\n", g_state.session_count);
	APPEND_STR("# HELP tunl_connections_total Total accepted connections\n");
	APPEND_STR("# TYPE tunl_connections_total counter\n");
	APPEND_FMT("tunl_connections_total %lu\n", (unsigned long)g_state.total_conns);
	APPEND_STR("# HELP tunl_bytes_in Total ingress bytes\n");
	APPEND_STR("# TYPE tunl_bytes_in counter\n");
	APPEND_FMT("tunl_bytes_in %lu\n", (unsigned long)g_state.total_bytes_in);
	APPEND_STR("# HELP tunl_bytes_out Total egress bytes\n");
	APPEND_STR("# TYPE tunl_bytes_out counter\n");
	APPEND_FMT("tunl_bytes_out %lu\n", (unsigned long)g_state.total_bytes_out);

	for (int i = 0; i < TUNL_MAX_RULES; i++) {
		if (!g_state.rules[i].enabled)
			continue;
		struct tunl_rule *r = &g_state.rules[i];
		APPEND_STR("# HELP tunl_rule_active_connections Active connections per rule\n");
		APPEND_STR("# TYPE tunl_rule_active_connections gauge\n");
		APPEND_FMT("tunl_rule_active_connections{rule=\"%u\",port=\"%u\",proto=\"%s\"} %u\n",
			r->id, r->listen_port, r->protocol == TUNL_PROTO_UDP ? "udp" : "tcp",
			r->active_conns);
		for (int b = 0; b < r->backend_count; b++) {
			struct tunl_backend *be = &r->backends[b];
			APPEND_STR("# HELP tunl_backend_active_connections Active connections per backend\n");
			APPEND_STR("# TYPE tunl_backend_active_connections gauge\n");
			APPEND_FMT("tunl_backend_active_connections{rule=\"%u\",backend=\"%s:%u\"} %u\n",
				r->id, be->host, be->port, be->active_conns);
			APPEND_STR("# HELP tunl_backend_total_connections Total connections per backend\n");
			APPEND_STR("# TYPE tunl_backend_total_connections counter\n");
			APPEND_FMT("tunl_backend_total_connections{rule=\"%u\",backend=\"%s:%u\"} %lu\n",
				r->id, be->host, be->port, (unsigned long)be->total_conns);
			APPEND_STR("# HELP tunl_backend_health Backend health state (1=up,0=down)\n");
			APPEND_STR("# TYPE tunl_backend_health gauge\n");
			APPEND_FMT("tunl_backend_health{rule=\"%u\",backend=\"%s:%u\"} %d\n",
				r->id, be->host, be->port, be->state == TUNL_BACKEND_UP ? 1 : 0);
			APPEND_STR("# HELP tunl_backend_last_rtt_ms Last health check RTT in ms\n");
			APPEND_STR("# TYPE tunl_backend_last_rtt_ms gauge\n");
			APPEND_FMT("tunl_backend_last_rtt_ms{rule=\"%u\",backend=\"%s:%u\"} %u\n",
				r->id, be->host, be->port, be->last_rtt_ms);
			APPEND_STR("# HELP tunl_backend_last_check_ms Last health check timestamp (ms)\n");
			APPEND_STR("# TYPE tunl_backend_last_check_ms gauge\n");
			APPEND_FMT("tunl_backend_last_check_ms{rule=\"%u\",backend=\"%s:%u\"} %lu\n",
				r->id, be->host, be->port, (unsigned long)be->last_check_ms);
		}
	}
	pthread_mutex_unlock(&g_state.lock);

	const char hdr[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nConnection: close\r\n\r\n";
	send(fd, hdr, strlen(hdr), MSG_NOSIGNAL);
	send(fd, buf, off, MSG_NOSIGNAL);

	#undef APPEND_FMT
	#undef APPEND_STR
}

static void *metrics_thread(void *arg)
{
	(void)arg;

	int mfd = create_listen_socket(g_state.metrics_port, g_state.bind_addr);
	if (mfd < 0) {
		tunl_log(TUNL_LOG_ERROR, "metrics bind failed");
		return NULL;
	}

	tunl_log(TUNL_LOG_INFO, "metrics on [%s]:%u",
		 g_state.bind_addr[0] ? g_state.bind_addr : "::",
		 g_state.metrics_port);

	while (!g_shutdown && g_state.running) {
		int cfd = accept(mfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		metrics_emit(cfd);
		close(cfd);
	}

	close(mfd);
	return NULL;
}

/* ============================================================================
 * Signal Handling & Main
 * ============================================================================ */

static void sig_handler(int sig)
{
	(void)sig;
	g_shutdown = 1;
}

static void daemonize(void)
{
	pid_t pid = fork();

	if (pid < 0)
		exit(1);
	if (pid > 0)
		exit(0);
	if (setsid() < 0)
		exit(1);

	pid = fork();
	if (pid < 0)
		exit(1);
	if (pid > 0)
		exit(0);

	umask(0);
	if (chdir("/") != 0)
		exit(1);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

static void usage(void)
{
	printf("tunl v%s - IPv6-first self-hosting toolkit\n\n", TUNL_VERSION);
	printf("Usage:\n");
	printf("  tunl serve [options]        Start proxy server\n");
	printf("  tunl dns [options]          DNS dynamic updates\n");
	printf("  tunl cert [options]         TLS certificates (ACME)\n");
	printf("  tunl check [options]        Reachability test\n");
	printf("  tunl tui                    Terminal dashboard\n");
	printf("  tunl -f <port:host:port>    Quick forward mode\n\n");
	printf("Serve options:\n");
	printf("  -C, --config <path>    Config file (default: tunl.conf)\n");
	printf("  -d, --daemon           Run as daemon\n\n");
	printf("DNS options:\n");
	printf("  --provider <cf|rfc2136>   DNS provider\n");
	printf("  --hostname <name>         Hostname to update\n");
	printf("  --token <token>           API token\n");
	printf("  --monitor                 Run as background monitor\n\n");
	printf("Cert options:\n");
	printf("  --domain <domain>         Domain for certificate\n");
	printf("  --email <email>           Contact email\n");
	printf("  --staging                 Use staging (test) server\n\n");
	printf("Check options:\n");
	printf("  --hostname <name>         Hostname to check\n");
	printf("  --port <port>             Port to check\n\n");
	printf("Examples:\n");
	printf("  tunl -f 443:localhost:8080\n");
	printf("  tunl serve -C /etc/tunl.conf -d\n");
	printf("  tunl dns --provider cf --hostname my.example.com --token xxx\n");
	printf("  tunl cert --domain my.example.com --email me@example.com\n");
	printf("  tunl check --hostname my.example.com --port 443\n");
	printf("  tunl tui\n");
}

/* ============================================================================
 * Subcommand: serve
 * ============================================================================ */

static int cmd_serve(int argc, char **argv)
{
	static struct option opts[] = {
		{"config", required_argument, 0, 'C'},
		{"daemon", no_argument, 0, 'd'},
		{"forward", required_argument, 0, 'f'},
		{0, 0, 0, 0}
	};

	const char *config_path = "tunl.conf";
	char *forward_spec = NULL;
	bool daemon_mode = false;
	int c;

	optind = 1;  /* Reset getopt */
	while ((c = getopt_long(argc, argv, "C:f:d", opts, NULL)) != -1) {
		switch (c) {
		case 'C':
			config_path = optarg;
			break;
		case 'f':
			forward_spec = optarg;
			break;
		case 'd':
			daemon_mode = true;
			break;
		}
	}

	if (daemon_mode)
		daemonize();

	tunl_init(&g_state);
	tunl_load_config(&g_state, config_path);

	/* One-liner forward mode */
	if (forward_spec) {
		int lport, bport;
		char bhost[128];

		if (sscanf(forward_spec, "%d:%127[^:]:%d", &lport, bhost, &bport) == 3) {
			struct tunl_rule rule;

			memset(&rule, 0, sizeof(rule));
			rule.id = 1;
			rule.listen_port = (uint16_t)lport;
			rule.enabled = true;
			rule.lb_algo = TUNL_LB_ROUNDROBIN;
			rule.max_conns = 512;

			strncpy(rule.backends[0].host, bhost, TUNL_IP_MAX_LEN - 1);
			rule.backends[0].host[TUNL_IP_MAX_LEN - 1] = '\0';
			rule.backends[0].port = (uint16_t)bport;
			rule.backends[0].state = TUNL_BACKEND_UP;
			rule.backends[0].healthy = true;
			rule.backend_count = 1;

			if (tunl_add_rule(&g_state, &rule) == 0) {
				struct tunl_rule *r = tunl_get_rule(&g_state, 1);

				if (r) {
					pthread_t tid;

					void *(*thr)(void *) = listener_thread;
					if (r->protocol == TUNL_PROTO_UDP)
						thr = udp_listener_thread;

					pthread_create(&tid, NULL, thr, r);
					pthread_detach(tid);
					start_rule_workers(r);
				}
			}
		} else {
			fprintf(stderr, "Invalid: use port:host:port\n");
			return 1;
		}
	}

	/* Start listeners for config rules */
	for (int i = 0; i < TUNL_MAX_RULES; i++) {
		if (g_state.rules[i].enabled) {
			if (g_state.rules[i].backend_count == 0) {
				tunl_log(TUNL_LOG_WARN, "rule %u has no backends; skipping listener",
					g_state.rules[i].id);
				continue;
			}
			pthread_t tid;
			void *(*thr)(void *) = listener_thread;
			if (g_state.rules[i].protocol == TUNL_PROTO_UDP)
				thr = udp_listener_thread;

			pthread_create(&tid, NULL, thr, &g_state.rules[i]);
			pthread_detach(tid);
			start_rule_workers(&g_state.rules[i]);
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGPIPE, SIG_IGN);

	pthread_t ctrl_tid;
 	pthread_t metrics_tid;

	pthread_create(&ctrl_tid, NULL, ctrl_thread, NULL);
	pthread_create(&metrics_tid, NULL, metrics_thread, NULL);

	if (!daemon_mode) {
		printf("tunl v%s\n", TUNL_VERSION);
		printf("ctrl: nc %s %d\n", 
		       g_state.bind_addr[0] ? g_state.bind_addr : "localhost",
		       g_state.ctrl_port);
	}

	while (!g_shutdown && g_state.running)
		sleep(1);

	tunl_log(TUNL_LOG_INFO, "shutting down");
	g_state.running = false;

	if (g_ctrl_fd >= 0)
		close(g_ctrl_fd);

	pthread_join(ctrl_tid, NULL);
	pthread_join(metrics_tid, NULL);
	tunl_shutdown(&g_state);

	return 0;
}

/* ============================================================================
 * Subcommand: dns
 * ============================================================================ */

static int cmd_dns(int argc, char **argv)
{
	static struct option opts[] = {
		{"provider", required_argument, 0, 'p'},
		{"hostname", required_argument, 0, 'H'},
		{"token", required_argument, 0, 't'},
		{"monitor", no_argument, 0, 'm'},
		{"status", no_argument, 0, 's'},
		{0, 0, 0, 0}
	};

	const char *provider = "cloudflare";
	const char *hostname = NULL;
	const char *token = NULL;
	bool monitor = false;
	bool status = false;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "p:H:t:ms", opts, NULL)) != -1) {
		switch (c) {
		case 'p':
			provider = optarg;
			break;
		case 'H':
			hostname = optarg;
			break;
		case 't':
			token = optarg;
			break;
		case 'm':
			monitor = true;
			break;
		case 's':
			status = true;
			break;
		}
	}

	if (status) {
		char buf[1024];
		dns_status(buf, sizeof(buf));
		printf("%s", buf);
		return 0;
	}

	if (!hostname) {
		fprintf(stderr, "Error: --hostname required\n");
		return 1;
	}

	if (dns_init(provider, hostname, token) != 0) {
		fprintf(stderr, "Error: DNS init failed\n");
		return 1;
	}

	if (monitor) {
		printf("Starting DNS monitor for %s (provider: %s)\n", hostname, provider);
		signal(SIGINT, sig_handler);
		signal(SIGTERM, sig_handler);
		g_state.running = true;
		dns_monitor_thread(NULL);
	} else {
		/* One-shot update */
		char buf[1024];
		printf("Updating DNS for %s...\n", hostname);
		dns_status(buf, sizeof(buf));
		printf("%s", buf);
	}

	return 0;
}

/* ============================================================================
 * Subcommand: cert
 * ============================================================================ */

static int cmd_cert(int argc, char **argv)
{
	static struct option opts[] = {
		{"domain", required_argument, 0, 'd'},
		{"email", required_argument, 0, 'e'},
		{"staging", no_argument, 0, 's'},
		{"status", no_argument, 0, 'S'},
		{0, 0, 0, 0}
	};

	const char *domain = NULL;
	const char *email = NULL;
	bool staging = false;
	bool status = false;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "d:e:sS", opts, NULL)) != -1) {
		switch (c) {
		case 'd':
			domain = optarg;
			break;
		case 'e':
			email = optarg;
			break;
		case 's':
			staging = true;
			break;
		case 'S':
			status = true;
			break;
		}
	}

	if (status) {
		char buf[1024];
		acme_status(buf, sizeof(buf));
		printf("%s", buf);
		return 0;
	}

	if (!domain) {
		fprintf(stderr, "Error: --domain required\n");
		return 1;
	}

	if (acme_init(domain, email, staging ? 1 : 0) != 0) {
		fprintf(stderr, "Error: ACME init failed\n");
		return 1;
	}

	printf("Requesting certificate for %s...\n", domain);
	printf("Mode: %s\n", staging ? "staging (test)" : "production");

	if (acme_ensure_cert() == 0) {
		printf("Certificate obtained!\n");
		printf("  Cert: %s\n", acme_get_cert_path());
		printf("  Key:  %s\n", acme_get_key_path());
		return 0;
	} else {
		fprintf(stderr, "Certificate request failed\n");
		return 1;
	}
}

/* ============================================================================
 * Subcommand: check
 * ============================================================================ */

static int cmd_check(int argc, char **argv)
{
	static struct option opts[] = {
		{"hostname", required_argument, 0, 'H'},
		{"port", required_argument, 0, 'p'},
		{"quick", no_argument, 0, 'q'},
		{0, 0, 0, 0}
	};

	const char *hostname = NULL;
	int port = 443;
	bool quick = false;
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "H:p:q", opts, NULL)) != -1) {
		switch (c) {
		case 'H':
			hostname = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'q':
			quick = true;
			break;
		}
	}

	if (quick) {
		return check_quick(hostname, port);
	} else {
		return check_connectivity(hostname, port);
	}
}

/* ============================================================================
 * Subcommand: tui
 * ============================================================================ */

static int cmd_tui(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	tunl_init(&g_state);
	g_state.running = true;
	
	return tui_run();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}

	/* Quick forward mode: tunl -f port:host:port */
	if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--forward") == 0) {
		return cmd_serve(argc, argv);
	}

	/* Help */
	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
	    strcmp(argv[1], "help") == 0) {
		usage();
		return 0;
	}

	/* Version */
	if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0 ||
	    strcmp(argv[1], "version") == 0) {
		printf("tunl v%s\n", TUNL_VERSION);
		return 0;
	}

	/* Subcommands */
	if (strcmp(argv[1], "serve") == 0) {
		return cmd_serve(argc - 1, argv + 1);
	} else if (strcmp(argv[1], "dns") == 0) {
		return cmd_dns(argc - 1, argv + 1);
	} else if (strcmp(argv[1], "cert") == 0) {
		return cmd_cert(argc - 1, argv + 1);
	} else if (strcmp(argv[1], "check") == 0) {
		return cmd_check(argc - 1, argv + 1);
	} else if (strcmp(argv[1], "tui") == 0) {
		return cmd_tui(argc - 1, argv + 1);
	} else {
		fprintf(stderr, "Unknown command: %s\n\n", argv[1]);
		usage();
		return 1;
	}
}
