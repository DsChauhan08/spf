/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl config parser - simple INI-style config
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char *trim(char *s)
{
	char *e;
	size_t len;

	while (isspace((unsigned char)*s))
		s++;

	len = strlen(s);
	if (len == 0)
		return s;

	e = s + len - 1;
	while (e > s && isspace((unsigned char)*e))
		*e-- = '\0';

	return s;
}

static int parse_backend(const char *str, struct tunl_backend *b)
{
	char host[TUNL_IP_MAX_LEN];
	int port;

	if (sscanf(str, "%45[^:]:%d", host, &port) == 2) {
		strncpy(b->host, host, TUNL_IP_MAX_LEN - 1);
		b->host[TUNL_IP_MAX_LEN - 1] = '\0';
		b->port = (uint16_t)port;
		b->state = TUNL_BACKEND_UP;
		b->healthy = true;
		return 0;
	}
	return -1;
}

int tunl_load_config(struct tunl_state *state, const char *path)
{
	FILE *f;
	char line[512];
	char section[32] = "";
	struct tunl_rule *current_rule = NULL;

	f = fopen(path, "r");
	if (!f) {
		tunl_log(TUNL_LOG_DEBUG, "config: %s not found, using defaults", path);
		return 0;
	}

	while (fgets(line, sizeof(line), f)) {
		char *s = trim(line);
		char *eq, *key, *val;

		if (*s == '\0' || *s == '#')
			continue;

		/* Section header */
		if (*s == '[') {
			char *e = strchr(s, ']');

			if (e) {
				*e = '\0';
				strncpy(section, s + 1, sizeof(section) - 1);
				section[sizeof(section) - 1] = '\0';
				current_rule = NULL;
			}
			continue;
		}

		/* Key = value */
		eq = strchr(s, '=');
		if (!eq)
			continue;

		*eq = '\0';
		key = trim(s);
		val = trim(eq + 1);

		if (strcmp(section, "admin") == 0) {
			if (strcmp(key, "bind") == 0) {
				strncpy(state->bind_addr, val, TUNL_IP_MAX_LEN - 1);
				state->bind_addr[TUNL_IP_MAX_LEN - 1] = '\0';
			} else if (strcmp(key, "port") == 0) {
				int port = atoi(val);

				if (port > 0 && port <= 65535)
					state->ctrl_port = (uint16_t)port;
			} else if (strcmp(key, "token") == 0) {
				strncpy(state->token, val, TUNL_TOKEN_MAX - 1);
				state->token[TUNL_TOKEN_MAX - 1] = '\0';
			}
		} else if (strcmp(section, "metrics") == 0) {
			if (strcmp(key, "port") == 0) {
				int port = atoi(val);

				if (port > 0 && port <= 65535)
					state->metrics_port = (uint16_t)port;
			}
		} else if (strncmp(section, "rule.", 5) == 0) {
			if (strcmp(key, "listen") == 0) {
				struct tunl_rule rule;
				int port;

				memset(&rule, 0, sizeof(rule));
				rule.protocol = TUNL_PROTO_TCP;

				/* Generate rule ID from section name */
				rule.id = (uint32_t)atoi(section + 5);
				if (rule.id == 0)
					rule.id = state->rule_count + 1;

				port = atoi(val);
				if (port > 0 && port <= 65535)
					rule.listen_port = (uint16_t)port;

				rule.enabled = true;
				rule.max_conns = 512;
				rule.lb_algo = TUNL_LB_ROUNDROBIN;

				pthread_mutex_lock(&state->lock);

				for (int i = 0; i < TUNL_MAX_RULES; i++) {
					if (!state->rules[i].enabled) {
						memcpy(&state->rules[i], &rule, sizeof(rule));
						pthread_mutex_init(&state->rules[i].lock, NULL);
						current_rule = &state->rules[i];
						state->rule_count++;
						break;
					}
				}

				pthread_mutex_unlock(&state->lock);
			} else if (strcmp(key, "backend") == 0 && current_rule) {
				if (current_rule->backend_count < TUNL_MAX_BACKENDS) {
					parse_backend(val,
						&current_rule->backends[current_rule->backend_count]);
					current_rule->backend_count++;
				}
			} else if (strcmp(key, "proto") == 0 && current_rule) {
				if (strcmp(val, "udp") == 0)
					current_rule->protocol = TUNL_PROTO_UDP;
				else
					current_rule->protocol = TUNL_PROTO_TCP;
			} else if (strcmp(key, "lb") == 0 && current_rule) {
				if (strcmp(val, "rr") == 0)
					current_rule->lb_algo = TUNL_LB_ROUNDROBIN;
				else if (strcmp(val, "lc") == 0)
					current_rule->lb_algo = TUNL_LB_LEASTCONN;
				else if (strcmp(val, "ip") == 0)
					current_rule->lb_algo = TUNL_LB_IPHASH;
			} else if (strcmp(key, "max_conns") == 0 && current_rule) {
				current_rule->max_conns = (uint32_t)atoi(val);
			}
		}
	}

	fclose(f);
	tunl_log(TUNL_LOG_INFO, "config: loaded %s (%u rules)", path, state->rule_count);
	return 0;
}
