/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl DNS - IPv6 prefix monitoring and dynamic DNS updates
 *
 * Monitors local IPv6 address changes and updates DNS records automatically.
 * Supports: Cloudflare API, RFC2136 (nsupdate)
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* DNS provider types */
typedef enum {
	DNS_PROVIDER_NONE = 0,
	DNS_PROVIDER_CLOUDFLARE,
	DNS_PROVIDER_RFC2136
} dns_provider_t;

/* DNS configuration */
struct dns_config {
	dns_provider_t provider;
	char domain[256];
	char hostname[256];		/* full hostname: myhost.example.com */
	char zone[256];			/* zone: example.com */
	
	/* Cloudflare */
	char cf_token[128];
	char cf_zone_id[64];
	
	/* RFC2136 */
	char rfc_server[256];
	char rfc_key_name[128];
	char rfc_key_secret[256];
	int rfc_key_algo;		/* HMAC-MD5, HMAC-SHA256, etc. */
	
	/* State */
	char current_ipv6[INET6_ADDRSTRLEN];
	char current_ipv4[INET_ADDRSTRLEN];
	time_t last_update;
	int update_interval_sec;
};

static struct dns_config g_dns_config;

/*
 * Get current global IPv6 address
 * Returns 0 on success, -1 if no global IPv6 found
 */
int dns_get_ipv6(char *buf, size_t len)
{
	struct ifaddrs *ifaddr, *ifa;
	int found = -1;

	if (!buf || len < INET6_ADDRSTRLEN)
		return -1;

	if (getifaddrs(&ifaddr) == -1)
		return -1;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;

		/* Skip loopback */
		if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
			continue;

		/* Skip link-local (fe80::) */
		if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr))
			continue;

		/* Skip site-local (deprecated fec0::) */
		if (IN6_IS_ADDR_SITELOCAL(&sa6->sin6_addr))
			continue;

		/* Skip ULA (fc00::/7) - private addresses */
		if ((sa6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc)
			continue;

		/* This is a global unicast address */
		if (inet_ntop(AF_INET6, &sa6->sin6_addr, buf, (socklen_t)len)) {
			found = 0;
			break;
		}
	}

	freeifaddrs(ifaddr);
	return found;
}

/*
 * Get current public IPv4 address (for dual-stack DNS)
 * This requires an external service since NAT hides the public IP
 */
int dns_get_ipv4_public(char *buf, size_t len)
{
	FILE *fp;
	char cmd[256];
	int ret = -1;

	if (!buf || len < INET_ADDRSTRLEN)
		return -1;

	/* Use curl to get public IP - simple and reliable */
	snprintf(cmd, sizeof(cmd), "curl -4 -s --max-time 5 ifconfig.me 2>/dev/null");
	
	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	if (fgets(buf, (int)len, fp)) {
		/* Remove trailing newline */
		size_t l = strlen(buf);
		if (l > 0 && buf[l-1] == '\n')
			buf[l-1] = '\0';
		
		/* Validate it looks like an IP */
		struct in_addr addr;
		if (inet_pton(AF_INET, buf, &addr) == 1)
			ret = 0;
	}

	pclose(fp);
	return ret;
}

/*
 * Update Cloudflare DNS record via API
 */
static int dns_update_cloudflare(const char *hostname, const char *ip, int is_ipv6)
{
	char cmd[2048];
	char record_type[8];
	FILE *fp;
	char response[4096];
	int success = 0;

	if (!g_dns_config.cf_token[0] || !g_dns_config.cf_zone_id[0]) {
		tunl_log(TUNL_LOG_ERROR, "dns: cloudflare token/zone_id not configured");
		return -1;
	}

	snprintf(record_type, sizeof(record_type), "%s", is_ipv6 ? "AAAA" : "A");

	/* First, get the record ID */
	snprintf(cmd, sizeof(cmd),
		"curl -s -X GET "
		"\"https://api.cloudflare.com/client/v4/zones/%s/dns_records"
		"?type=%s&name=%s\" "
		"-H \"Authorization: Bearer %s\" "
		"-H \"Content-Type: application/json\" 2>/dev/null",
		g_dns_config.cf_zone_id, record_type, hostname, g_dns_config.cf_token);

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	size_t total = 0;
	while (fgets(response + total, (int)(sizeof(response) - total), fp)) {
		total = strlen(response);
	}
	pclose(fp);

	/* Parse record ID from JSON response - simple extraction */
	char *id_start = strstr(response, "\"id\":\"");
	char record_id[64] = {0};
	
	if (id_start) {
		id_start += 6;
		char *id_end = strchr(id_start, '"');
		if (id_end && (id_end - id_start) < 64) {
			memcpy(record_id, id_start, (size_t)(id_end - id_start));
		}
	}

	if (record_id[0]) {
		/* Update existing record */
		snprintf(cmd, sizeof(cmd),
			"curl -s -X PUT "
			"\"https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s\" "
			"-H \"Authorization: Bearer %s\" "
			"-H \"Content-Type: application/json\" "
			"--data '{\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":60}' "
			"2>/dev/null",
			g_dns_config.cf_zone_id, record_id, g_dns_config.cf_token,
			record_type, hostname, ip);
	} else {
		/* Create new record */
		snprintf(cmd, sizeof(cmd),
			"curl -s -X POST "
			"\"https://api.cloudflare.com/client/v4/zones/%s/dns_records\" "
			"-H \"Authorization: Bearer %s\" "
			"-H \"Content-Type: application/json\" "
			"--data '{\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":60}' "
			"2>/dev/null",
			g_dns_config.cf_zone_id, g_dns_config.cf_token,
			record_type, hostname, ip);
	}

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	response[0] = '\0';
	while (fgets(response + strlen(response), 
		     (int)(sizeof(response) - strlen(response)), fp)) {
	}
	pclose(fp);

	/* Check for success */
	if (strstr(response, "\"success\":true"))
		success = 1;

	if (success) {
		tunl_log(TUNL_LOG_INFO, "dns: updated %s %s -> %s", 
			 record_type, hostname, ip);
		return 0;
	} else {
		tunl_log(TUNL_LOG_ERROR, "dns: cloudflare update failed");
		return -1;
	}
}

/*
 * Update DNS via RFC2136 (nsupdate)
 */
static int dns_update_rfc2136(const char *hostname, const char *ip, int is_ipv6)
{
	char cmd[1024];
	char tmpfile[64];
	FILE *fp;
	int ret;

	snprintf(tmpfile, sizeof(tmpfile), "/tmp/tunl_nsupdate.%d", getpid());

	fp = fopen(tmpfile, "w");
	if (!fp)
		return -1;

	fprintf(fp, "server %s\n", g_dns_config.rfc_server);
	fprintf(fp, "zone %s\n", g_dns_config.zone);
	fprintf(fp, "update delete %s %s\n", hostname, is_ipv6 ? "AAAA" : "A");
	fprintf(fp, "update add %s 60 %s %s\n", hostname, is_ipv6 ? "AAAA" : "A", ip);
	fprintf(fp, "send\n");
	fclose(fp);

	if (g_dns_config.rfc_key_name[0] && g_dns_config.rfc_key_secret[0]) {
		snprintf(cmd, sizeof(cmd), 
			 "nsupdate -y hmac-sha256:%s:%s %s 2>&1",
			 g_dns_config.rfc_key_name, 
			 g_dns_config.rfc_key_secret,
			 tmpfile);
	} else {
		snprintf(cmd, sizeof(cmd), "nsupdate %s 2>&1", tmpfile);
	}

	ret = system(cmd);
	unlink(tmpfile);

	if (ret == 0) {
		tunl_log(TUNL_LOG_INFO, "dns: updated %s %s -> %s (rfc2136)",
			 is_ipv6 ? "AAAA" : "A", hostname, ip);
		return 0;
	} else {
		tunl_log(TUNL_LOG_ERROR, "dns: nsupdate failed (exit %d)", ret);
		return -1;
	}
}

/*
 * Update DNS record (wrapper - uses configured hostname)
 */
int dns_update(const char *hostname, const char *ip, int af)
{
	int is_ipv6 = (af == AF_INET6);
	const char *host = hostname;

	if (!host || !host[0])
		host = g_dns_config.hostname;
	
	if (!ip || !ip[0])
		return -1;

	switch (g_dns_config.provider) {
	case DNS_PROVIDER_CLOUDFLARE:
		return dns_update_cloudflare(host, ip, is_ipv6);
	case DNS_PROVIDER_RFC2136:
		return dns_update_rfc2136(host, ip, is_ipv6);
	default:
		return -1;
	}
}

/*
 * Check if IPv6 address changed and update DNS
 */
int dns_check_and_update(void)
{
	char ipv6[INET6_ADDRSTRLEN] = {0};
	int updated = 0;

	if (dns_get_ipv6(ipv6, sizeof(ipv6)) == 0) {
		if (strcmp(ipv6, g_dns_config.current_ipv6) != 0) {
			tunl_log(TUNL_LOG_INFO, "dns: IPv6 changed: %s -> %s",
				 g_dns_config.current_ipv6[0] ? g_dns_config.current_ipv6 : "(none)",
				 ipv6);
			
			if (g_dns_config.provider != DNS_PROVIDER_NONE) {
				if (dns_update(NULL, ipv6, AF_INET6) == 0) {
					strncpy(g_dns_config.current_ipv6, ipv6, 
						sizeof(g_dns_config.current_ipv6) - 1);
					g_dns_config.last_update = time(NULL);
					updated = 1;
				}
			} else {
				strncpy(g_dns_config.current_ipv6, ipv6,
					sizeof(g_dns_config.current_ipv6) - 1);
			}
		}
	}

	return updated;
}

/*
 * DNS monitor thread
 */
void *dns_monitor_thread(void *arg)
{
	(void)arg;
	int interval = g_dns_config.update_interval_sec;

	if (interval <= 0)
		interval = 60;

	tunl_log(TUNL_LOG_INFO, "dns: monitor started (interval %ds)", interval);

	/* Initial check */
	dns_check_and_update();

	while (g_state.running) {
		sleep((unsigned)interval);
		if (!g_state.running)
			break;
		dns_check_and_update();
	}

	tunl_log(TUNL_LOG_INFO, "dns: monitor stopped");
	return NULL;
}

/*
 * Initialize DNS module
 */
int dns_init(const char *provider, const char *hostname, const char *token)
{
	memset(&g_dns_config, 0, sizeof(g_dns_config));
	g_dns_config.update_interval_sec = 60;

	if (!provider || !hostname)
		return -1;

	strncpy(g_dns_config.hostname, hostname, sizeof(g_dns_config.hostname) - 1);

	/* Extract zone from hostname */
	const char *dot = strchr(hostname, '.');
	if (dot) {
		strncpy(g_dns_config.zone, dot + 1, sizeof(g_dns_config.zone) - 1);
	}

	if (strcmp(provider, "cloudflare") == 0 || strcmp(provider, "cf") == 0) {
		g_dns_config.provider = DNS_PROVIDER_CLOUDFLARE;
		
		/* Token format: "token:zone_id" */
		if (token) {
			const char *sep = strchr(token, ':');
			if (sep) {
				size_t token_len = (size_t)(sep - token);
				if (token_len < sizeof(g_dns_config.cf_token)) {
					memcpy(g_dns_config.cf_token, token, token_len);
				}
				strncpy(g_dns_config.cf_zone_id, sep + 1,
					sizeof(g_dns_config.cf_zone_id) - 1);
			}
		}
	} else if (strcmp(provider, "rfc2136") == 0) {
		g_dns_config.provider = DNS_PROVIDER_RFC2136;
		
		/* Token format: "server:keyname:secret" */
		if (token) {
			char tmp[512];
			strncpy(tmp, token, sizeof(tmp) - 1);
			
			char *server = tmp;
			char *keyname = strchr(server, ':');
			if (keyname) {
				*keyname++ = '\0';
				char *secret = strchr(keyname, ':');
				if (secret) {
					*secret++ = '\0';
					strncpy(g_dns_config.rfc_key_secret, secret,
						sizeof(g_dns_config.rfc_key_secret) - 1);
				}
				strncpy(g_dns_config.rfc_key_name, keyname,
					sizeof(g_dns_config.rfc_key_name) - 1);
			}
			strncpy(g_dns_config.rfc_server, server,
				sizeof(g_dns_config.rfc_server) - 1);
		}
	} else {
		tunl_log(TUNL_LOG_ERROR, "dns: unknown provider '%s'", provider);
		return -1;
	}

	/* Get initial IP */
	dns_get_ipv6(g_dns_config.current_ipv6, sizeof(g_dns_config.current_ipv6));

	tunl_log(TUNL_LOG_INFO, "dns: initialized (provider=%s, host=%s, ipv6=%s)",
		 provider, hostname, 
		 g_dns_config.current_ipv6[0] ? g_dns_config.current_ipv6 : "none");

	return 0;
}

/*
 * Print current DNS status
 */
void dns_status(char *buf, size_t len)
{
	char ipv6[INET6_ADDRSTRLEN] = {0};
	
	dns_get_ipv6(ipv6, sizeof(ipv6));

	snprintf(buf, len,
		 "DNS Status:\n"
		 "  Provider: %s\n"
		 "  Hostname: %s\n"
		 "  Current IPv6: %s\n"
		 "  Last update: %s",
		 g_dns_config.provider == DNS_PROVIDER_CLOUDFLARE ? "cloudflare" :
		 g_dns_config.provider == DNS_PROVIDER_RFC2136 ? "rfc2136" : "none",
		 g_dns_config.hostname[0] ? g_dns_config.hostname : "(not set)",
		 ipv6[0] ? ipv6 : "(none)",
		 g_dns_config.last_update ? ctime(&g_dns_config.last_update) : "never\n");
}
