/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl health - backend health checking
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define HEALTH_TIMEOUT_MS	2000
#define HEALTH_INTERVAL_MS	5000
#define HEALTH_FAIL_THRESHOLD	3

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * TCP health check - supports IPv4/IPv6
 */
static int health_tcp_check(const char *host, uint16_t port, int timeout_ms)
{
	struct addrinfo hints, *res, *rp;
	char port_str[8];
	int result = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_str, sizeof(port_str), "%u", port);
	if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
		return -1;

	for (rp = res; rp; rp = rp->ai_next) {
		int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (fd < 0)
			continue;

		set_nonblocking(fd);

		int ret = connect(fd, rp->ai_addr, rp->ai_addrlen);

		if (ret < 0 && errno != EINPROGRESS) {
			close(fd);
			continue;
		}

		/* Wait for connection with timeout */
		fd_set wfds;
		struct timeval tv;

		if (fd >= FD_SETSIZE) {
			close(fd);
			continue;
		}

		FD_ZERO(&wfds);
		FD_SET(fd, &wfds);
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;

		ret = select(fd + 1, NULL, &wfds, NULL, &tv);
		if (ret > 0) {
			int sock_err = 0;
			socklen_t len = sizeof(sock_err);

			getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &len);
			if (sock_err == 0)
				result = 0;
		}

		close(fd);
		if (result == 0)
			break;
	}

	freeaddrinfo(res);
	return result;
}

/*
 * Health worker thread - periodically checks all backends
 */
void *tunl_health_worker(void *arg)
{
	struct tunl_rule *rule = (struct tunl_rule *)arg;
	uint8_t fail_count[TUNL_MAX_BACKENDS];

	memset(fail_count, 0, sizeof(fail_count));

	tunl_log(TUNL_LOG_INFO, "health: started for port %u", rule->listen_port);

	while (g_state.running && rule->enabled) {
		for (int i = 0; i < rule->backend_count; i++) {
			struct tunl_backend *b = &rule->backends[i];
			uint64_t start_ms = tunl_time_ms();
			int ok = health_tcp_check(b->host, b->port, HEALTH_TIMEOUT_MS);
			uint64_t end_ms = tunl_time_ms();

			pthread_mutex_lock(&rule->lock);

			if (ok == 0) {
				if (b->state == TUNL_BACKEND_DOWN) {
					b->state = TUNL_BACKEND_UP;
					tunl_log(TUNL_LOG_INFO, "health: %s:%u UP",
						 b->host, b->port);
				}
				fail_count[i] = 0;
				b->last_rtt_ms = (uint32_t)(end_ms - start_ms);
			} else {
				fail_count[i]++;
				if (fail_count[i] >= HEALTH_FAIL_THRESHOLD &&
				    b->state == TUNL_BACKEND_UP) {
					b->state = TUNL_BACKEND_DOWN;
					tunl_log(TUNL_LOG_WARN, "health: %s:%u DOWN",
						 b->host, b->port);
				}
			}

			b->last_check_ms = end_ms;

			pthread_mutex_unlock(&rule->lock);
		}

		/* Sleep in small intervals for graceful shutdown */
		for (int i = 0; i < HEALTH_INTERVAL_MS / 100 && g_state.running; i++)
			usleep(100000);
	}

	tunl_log(TUNL_LOG_INFO, "health: stopped for port %u", rule->listen_port);
	return NULL;
}
