/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl core - initialization, rule management, rate limiting
 *
 * Linux kernel style: simple, focused, no premature optimization.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>

#ifdef __linux__
#include <sys/random.h>
#endif

/* Global state */
struct tunl_state g_state;

/*
 * Time utilities
 */
uint64_t tunl_time_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

uint64_t tunl_time_sec(void)
{
	return tunl_time_ms() / 1000;
}

/*
 * Random bytes - uses getrandom on Linux, /dev/urandom fallback
 */
void tunl_random_bytes(uint8_t *buf, size_t len)
{
	int fd;
	ssize_t n;

	if (!buf || len == 0)
		return;

#ifdef __linux__
	n = getrandom(buf, len, 0);
	if (n == (ssize_t)len)
		return;
#endif

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = read(fd, buf, len);
		close(fd);
		if (n == (ssize_t)len)
			return;
	}

	/* Fallback - weak but better than nothing */
	for (size_t i = 0; i < len; i++)
		buf[i] = (uint8_t)rand();
}

/*
 * Simple djb2 hash for IP addresses
 */
uint32_t tunl_hash_ip(const char *ip)
{
	uint32_t h = 5381;

	if (!ip)
		return 0;

	while (*ip)
		h = ((h << 5) + h) + (uint8_t)*ip++;

	return h;
}

/*
 * Logging
 */
static const char *log_prefix[] = { "DBG", "INF", "WRN", "ERR" };

void tunl_log(tunl_log_level_t level, const char *fmt, ...)
{
	struct tm tm_buf;
	time_t now;
	va_list args;
	char ts[20];

	if (!fmt || level < TUNL_LOG_DEBUG || level > TUNL_LOG_ERROR)
		return;

	/* Respect configured log level */
	if (level < g_state.log_level)
		return;

	now = time(NULL);
	if (localtime_r(&now, &tm_buf))
		strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
	else
		ts[0] = '\0';

	flockfile(stderr);
	va_start(args, fmt);
	if (g_state.log_json) {
		char msg[512];
		vsnprintf(msg, sizeof(msg), fmt, args);
		fprintf(stderr,
			"{\"ts\":\"%s\",\"level\":\"%s\",\"msg\":\"%s\"}\n",
			ts, log_prefix[level], msg);
	} else {
		fprintf(stderr, "[%s] [%s] ", ts, log_prefix[level]);
		vfprintf(stderr, fmt, args);
		fputc('\n', stderr);
	}
	va_end(args);
	funlockfile(stderr);
}

/*
 * Initialize state
 */
void tunl_init(struct tunl_state *state)
{
	if (!state)
		return;

	memset(state, 0, sizeof(*state));
	state->running = true;
	state->start_time = tunl_time_sec();
	state->ctrl_port = TUNL_CTRL_PORT;
	state->metrics_port = TUNL_METRICS_PORT;
	state->log_level = TUNL_LOG_INFO;
	state->log_json = false;
	memcpy(state->bind_addr, "::1", 4);
	const char *env_json = getenv("TUNL_LOG_JSON");
	if (env_json && env_json[0] && env_json[0] != '0')
		state->log_json = true;

	pthread_mutex_init(&state->lock, NULL);

	tunl_log(TUNL_LOG_INFO, "tunl v%s initialized", TUNL_VERSION);
}

/*
 * Shutdown and cleanup
 */
void tunl_shutdown(struct tunl_state *state)
{
	if (!state)
		return;

	state->running = false;

	/* Destroy rule locks */
	for (int i = 0; i < TUNL_MAX_RULES; i++) {
		if (state->rules[i].enabled)
			pthread_mutex_destroy(&state->rules[i].lock);
	}

	pthread_mutex_destroy(&state->lock);
	tunl_log(TUNL_LOG_INFO, "shutdown complete");
}

/*
 * Add a forwarding rule
 */
int tunl_add_rule(struct tunl_state *state, const struct tunl_rule *rule)
{
	int slot = -1;

	if (!state || !rule)
		return -1;

	pthread_mutex_lock(&state->lock);

	/* Find free slot */
	for (int i = 0; i < TUNL_MAX_RULES; i++) {
		if (!state->rules[i].enabled) {
			slot = i;
			break;
		}
	}

	if (slot < 0) {
		pthread_mutex_unlock(&state->lock);
		tunl_log(TUNL_LOG_ERROR, "rule table full");
		return -1;
	}

	/* Copy rule data */
	memcpy(&state->rules[slot], rule, sizeof(struct tunl_rule));
	state->rules[slot].enabled = true;
	pthread_mutex_init(&state->rules[slot].lock, NULL);
	state->rule_count++;

	pthread_mutex_unlock(&state->lock);

	tunl_log(TUNL_LOG_INFO, "rule %u: port %u -> %u backends",
		 rule->id, rule->listen_port, rule->backend_count);
	return 0;
}

/*
 * Delete a rule by ID
 */
int tunl_del_rule(struct tunl_state *state, uint32_t rule_id)
{
	int found = -1;

	if (!state)
		return -1;

	pthread_mutex_lock(&state->lock);

	for (int i = 0; i < TUNL_MAX_RULES; i++) {
		if (state->rules[i].enabled && state->rules[i].id == rule_id) {
			found = i;
			break;
		}
	}

	if (found < 0) {
		pthread_mutex_unlock(&state->lock);
		return -1;
	}

	pthread_mutex_destroy(&state->rules[found].lock);
	memset(&state->rules[found], 0, sizeof(struct tunl_rule));
	state->rule_count--;

	pthread_mutex_unlock(&state->lock);

	tunl_log(TUNL_LOG_INFO, "rule %u deleted", rule_id);
	return 0;
}

/*
 * Get a rule by ID
 */
struct tunl_rule *tunl_get_rule(struct tunl_state *state, uint32_t rule_id)
{
	struct tunl_rule *rule = NULL;

	if (!state)
		return NULL;

	pthread_mutex_lock(&state->lock);

	for (int i = 0; i < TUNL_MAX_RULES; i++) {
		if (state->rules[i].enabled && state->rules[i].id == rule_id) {
			rule = &state->rules[i];
			break;
		}
	}

	pthread_mutex_unlock(&state->lock);
	return rule;
}

/*
 * Find tracker for IP, return index or -1
 */
static int find_tracker(struct tunl_state *state, const char *ip)
{
	for (int i = 0; i < (int)state->tracker_count; i++) {
		if (strcmp(state->trackers[i].ip, ip) == 0)
			return i;
	}
	return -1;
}

/*
 * Check if IP is currently blocked
 */
bool tunl_is_blocked(struct tunl_state *state, const char *ip)
{
	bool blocked = false;
	uint64_t now;
	int idx;

	if (!state || !ip)
		return true;

	pthread_mutex_lock(&state->lock);

	idx = find_tracker(state, ip);
	if (idx >= 0) {
		now = tunl_time_sec();
		if (state->trackers[idx].block_until > now)
			blocked = true;
		else
			state->trackers[idx].block_until = 0;
	}

	pthread_mutex_unlock(&state->lock);
	return blocked;
}

/*
 * Rate limiting check - returns true if connection allowed
 */
bool tunl_rate_check(struct tunl_state *state, const char *ip)
{
	struct tunl_tracker *t;
	uint64_t now;
	int idx;

	if (!state || !ip)
		return false;

	pthread_mutex_lock(&state->lock);

	now = tunl_time_sec();
	idx = find_tracker(state, ip);

	if (idx < 0) {
		/* New IP - add tracker if space */
		if (state->tracker_count >= TUNL_MAX_BLOCKLIST) {
			/* Evict oldest */
			memmove(&state->trackers[0], &state->trackers[1],
				sizeof(struct tunl_tracker) * (TUNL_MAX_BLOCKLIST - 1));
			idx = TUNL_MAX_BLOCKLIST - 1;
		} else {
			idx = state->tracker_count++;
		}

		t = &state->trackers[idx];
		memset(t, 0, sizeof(*t));
		strncpy(t->ip, ip, TUNL_IP_MAX_LEN - 1);
		t->ip[TUNL_IP_MAX_LEN - 1] = '\0';
		t->count = 1;
		t->window_start = now;

		pthread_mutex_unlock(&state->lock);
		return true;
	}

	t = &state->trackers[idx];

	/* Check if blocked */
	if (t->block_until > now) {
		pthread_mutex_unlock(&state->lock);
		return false;
	}

	/* Reset window if expired */
	if (now - t->window_start > TUNL_RATE_WINDOW_SEC) {
		t->count = 1;
		t->window_start = now;
		pthread_mutex_unlock(&state->lock);
		return true;
	}

	t->count++;

	/* Check threshold */
	if (t->count > TUNL_RATE_THRESHOLD) {
		t->strikes++;
		t->block_until = now + TUNL_BLOCK_DURATION_SEC * t->strikes;
		t->count = 0;

		pthread_mutex_unlock(&state->lock);
		tunl_log(TUNL_LOG_WARN, "blocked %s (strike %u)", ip, t->strikes);
		return false;
	}

	pthread_mutex_unlock(&state->lock);
	return true;
}

/*
 * Manually block an IP
 */
void tunl_block_ip(struct tunl_state *state, const char *ip, uint64_t duration)
{
	struct tunl_tracker *t;
	uint64_t now;
	int idx;

	if (!state || !ip)
		return;

	pthread_mutex_lock(&state->lock);

	now = tunl_time_sec();
	idx = find_tracker(state, ip);

	if (idx < 0) {
		if (state->tracker_count >= TUNL_MAX_BLOCKLIST) {
			pthread_mutex_unlock(&state->lock);
			return;
		}
		idx = state->tracker_count++;
		t = &state->trackers[idx];
		memset(t, 0, sizeof(*t));
		strncpy(t->ip, ip, TUNL_IP_MAX_LEN - 1);
		t->ip[TUNL_IP_MAX_LEN - 1] = '\0';
	} else {
		t = &state->trackers[idx];
	}

	t->block_until = duration ? now + duration : UINT64_MAX;

	pthread_mutex_unlock(&state->lock);
	tunl_log(TUNL_LOG_INFO, "blocked %s", ip);
}

/*
 * Unblock an IP
 */
void tunl_unblock_ip(struct tunl_state *state, const char *ip)
{
	int idx;

	if (!state || !ip)
		return;

	pthread_mutex_lock(&state->lock);

	idx = find_tracker(state, ip);
	if (idx >= 0) {
		state->trackers[idx].block_until = 0;
		state->trackers[idx].strikes = 0;
		state->trackers[idx].count = 0;
	}

	pthread_mutex_unlock(&state->lock);
	tunl_log(TUNL_LOG_INFO, "unblocked %s", ip);
}

/*
 * Select backend using configured algorithm
 */
int tunl_select_backend(struct tunl_rule *rule, const char *client_ip)
{
	int selected = -1;

	if (!rule || rule->backend_count == 0)
		return -1;

	pthread_mutex_lock(&rule->lock);

	switch (rule->lb_algo) {
	case TUNL_LB_ROUNDROBIN: {
		for (int i = 0; i < rule->backend_count; i++) {
			int idx = rule->rr_index % rule->backend_count;
			rule->rr_index++;
			if (rule->backends[idx].state == TUNL_BACKEND_UP) {
				selected = idx;
				break;
			}
		}
		break;
	}

	case TUNL_LB_LEASTCONN: {
		uint32_t min = UINT32_MAX;
		for (int i = 0; i < rule->backend_count; i++) {
			if (rule->backends[i].state == TUNL_BACKEND_UP &&
			    rule->backends[i].active_conns < min) {
				min = rule->backends[i].active_conns;
				selected = i;
			}
		}
		break;
	}

	case TUNL_LB_IPHASH: {
		uint32_t h = tunl_hash_ip(client_ip);
		int start = h % rule->backend_count;
		for (int i = 0; i < rule->backend_count; i++) {
			int idx = (start + i) % rule->backend_count;
			if (rule->backends[idx].state == TUNL_BACKEND_UP) {
				selected = idx;
				break;
			}
		}
		break;
	}
	}

	pthread_mutex_unlock(&rule->lock);
	return selected;
}

/*
 * Track connection start
 */
void tunl_backend_conn_start(struct tunl_rule *rule, int idx)
{
	if (!rule || idx < 0 || idx >= rule->backend_count)
		return;

	pthread_mutex_lock(&rule->lock);
	rule->backends[idx].active_conns++;
	rule->backends[idx].total_conns++;
	rule->active_conns++;
	pthread_mutex_unlock(&rule->lock);
}

/*
 * Track connection end
 */
void tunl_backend_conn_end(struct tunl_rule *rule, int idx)
{
	if (!rule || idx < 0 || idx >= rule->backend_count)
		return;

	pthread_mutex_lock(&rule->lock);
	if (rule->backends[idx].active_conns > 0)
		rule->backends[idx].active_conns--;
	if (rule->active_conns > 0)
		rule->active_conns--;
	pthread_mutex_unlock(&rule->lock);
}

/*
 * Token verification - constant time comparison
 */
bool tunl_verify_token(struct tunl_state *state, const char *token)
{
	volatile uint8_t diff = 0;
	size_t len, i;

	if (!state || !token)
		return false;

	/* No token configured = allow */
	if (state->token[0] == '\0')
		return true;

	len = strlen(state->token);
	if (strlen(token) != len)
		return false;

	for (i = 0; i < len; i++)
		diff |= (uint8_t)(state->token[i] ^ token[i]);

	return diff == 0;
}

/*
 * Generate random token
 */
void tunl_generate_token(char *buf, size_t len)
{
	static const char chars[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789";
	uint8_t rnd[64];
	size_t n;

	if (!buf || len < 2)
		return;

	n = (len - 1 > 63) ? 63 : len - 1;
	tunl_random_bytes(rnd, n);

	for (size_t i = 0; i < n; i++)
		buf[i] = chars[rnd[i] % 62];

	buf[n] = '\0';
}
