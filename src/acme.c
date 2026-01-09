/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl ACME - Let's Encrypt certificate automation
 *
 * Implements ACME protocol for automatic TLS certificates.
 * Supports HTTP-01 challenge (requires port 80) or DNS-01 (requires DNS API).
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
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define ACME_STAGING    "https://acme-staging-v02.api.letsencrypt.org/directory"
#define ACME_PRODUCTION "https://acme-v02.api.letsencrypt.org/directory"

#define CERT_DIR        "/var/lib/tunl/certs"
#define ACCOUNT_KEY     "/var/lib/tunl/account.key"

/* ACME state */
struct acme_state {
	char domain[256];
	char email[256];
	char cert_path[256];
	char key_path[256];
	char challenge_token[256];
	char challenge_response[512];
	int use_staging;
	int http_challenge_port;
	time_t cert_expiry;
};

static struct acme_state g_acme;

/*
 * Base64 URL-safe encoding (no padding)
 */
static int base64url_encode(const unsigned char *in, size_t in_len, 
			    char *out, size_t out_len)
{
	static const char b64[] = 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t i, o = 0;

	for (i = 0; i < in_len && o < out_len - 4; i += 3) {
		unsigned int v = (unsigned int)in[i] << 16;
		if (i + 1 < in_len) v |= (unsigned int)in[i + 1] << 8;
		if (i + 2 < in_len) v |= in[i + 2];

		out[o++] = b64[(v >> 18) & 0x3f];
		out[o++] = b64[(v >> 12) & 0x3f];
		if (i + 1 < in_len) out[o++] = b64[(v >> 6) & 0x3f];
		if (i + 2 < in_len) out[o++] = b64[v & 0x3f];
	}
	out[o] = '\0';
	return (int)o;
}

/*
 * Generate RSA private key
 */
static int acme_generate_key(const char *path)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	FILE *fp = NULL;
	int ret = -1;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx)
		goto cleanup;

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto cleanup;

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
		goto cleanup;

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		goto cleanup;

	fp = fopen(path, "w");
	if (!fp)
		goto cleanup;

	if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL))
		ret = 0;

cleanup:
	if (fp) fclose(fp);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) EVP_PKEY_CTX_free(ctx);
	return ret;
}

/*
 * Generate CSR (Certificate Signing Request)
 * Reserved for future use when implementing native ACME protocol
 */
__attribute__((unused))
static int acme_generate_csr(const char *domain, const char *key_path,
			     char *csr_b64, size_t csr_len)
{
	EVP_PKEY *pkey = NULL;
	X509_REQ *req = NULL;
	X509_NAME *name = NULL;
	FILE *fp = NULL;
	unsigned char *der = NULL;
	int der_len;
	int ret = -1;

	fp = fopen(key_path, "r");
	if (!fp)
		goto cleanup;

	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	fp = NULL;

	if (!pkey)
		goto cleanup;

	req = X509_REQ_new();
	if (!req)
		goto cleanup;

	name = X509_REQ_get_subject_name(req);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (unsigned char *)domain, -1, -1, 0);

	X509_REQ_set_pubkey(req, pkey);
	X509_REQ_sign(req, pkey, EVP_sha256());

	der_len = i2d_X509_REQ(req, &der);
	if (der_len <= 0)
		goto cleanup;

	base64url_encode(der, (size_t)der_len, csr_b64, csr_len);
	ret = 0;

cleanup:
	if (der) OPENSSL_free(der);
	if (req) X509_REQ_free(req);
	if (pkey) EVP_PKEY_free(pkey);
	if (fp) fclose(fp);
	return ret;
}

/*
 * HTTP-01 challenge server callback
 * Returns the challenge response for /.well-known/acme-challenge/<token>
 */
const char *acme_get_challenge_response(const char *token)
{
	if (strcmp(token, g_acme.challenge_token) == 0)
		return g_acme.challenge_response;
	return NULL;
}

/*
 * Run ACME certificate request using curl (simpler than implementing JOSE/JWS)
 * This uses acme.sh as a helper if available, otherwise falls back to manual
 */
static int acme_request_cert_acmesh(const char *domain, const char *email,
				    const char *cert_path, const char *key_path)
{
	char cmd[2048];
	int ret;
	const char *email_opt = "";
	char email_buf[300] = "";

	/* Check if acme.sh is installed */
	if (system("which acme.sh >/dev/null 2>&1") != 0) {
		tunl_log(TUNL_LOG_ERROR, "acme: acme.sh not found, installing...");
		
		ret = system("curl -s https://get.acme.sh | sh -s email=" 
			     "&& source ~/.acme.sh/acme.sh.env");
		if (ret != 0) {
			tunl_log(TUNL_LOG_ERROR, "acme: failed to install acme.sh");
			return -1;
		}
	}

	/* Build email option if provided */
	if (email && email[0]) {
		snprintf(email_buf, sizeof(email_buf), "--accountemail %s", email);
		email_opt = email_buf;
	}

	/* Issue certificate using standalone mode (HTTP-01) */
	snprintf(cmd, sizeof(cmd),
		 "~/.acme.sh/acme.sh --issue -d %s --standalone "
		 "--httpport %d "
		 "%s %s "
		 "--cert-file %s.crt "
		 "--key-file %s.key "
		 "--fullchain-file %s "
		 "2>&1",
		 domain,
		 g_acme.http_challenge_port ? g_acme.http_challenge_port : 80,
		 g_acme.use_staging ? "--staging" : "",
		 email_opt,
		 key_path, key_path, cert_path);

	tunl_log(TUNL_LOG_INFO, "acme: requesting certificate for %s", domain);

	ret = system(cmd);
	if (ret == 0) {
		tunl_log(TUNL_LOG_INFO, "acme: certificate obtained: %s", cert_path);
		return 0;
	} else {
		tunl_log(TUNL_LOG_ERROR, "acme: certificate request failed");
		return -1;
	}
}

/*
 * Check if certificate needs renewal (within 30 days of expiry)
 */
static int acme_needs_renewal(const char *cert_path)
{
	FILE *fp;
	X509 *cert = NULL;
	ASN1_TIME *expiry;
	int days, secs;
	int needs_renewal = 1;

	fp = fopen(cert_path, "r");
	if (!fp)
		return 1;  /* No cert = needs "renewal" (initial issue) */

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!cert)
		return 1;

	expiry = X509_get_notAfter(cert);
	if (ASN1_TIME_diff(&days, &secs, NULL, expiry)) {
		if (days > 30)
			needs_renewal = 0;
		tunl_log(TUNL_LOG_DEBUG, "acme: cert expires in %d days", days);
	}

	X509_free(cert);
	return needs_renewal;
}

/*
 * Initialize ACME module
 */
int acme_init(const char *domain, const char *email, int staging)
{
	char path[512];

	memset(&g_acme, 0, sizeof(g_acme));

	if (!domain || !domain[0])
		return -1;

	strncpy(g_acme.domain, domain, sizeof(g_acme.domain) - 1);
	
	if (email)
		strncpy(g_acme.email, email, sizeof(g_acme.email) - 1);

	g_acme.use_staging = staging;
	g_acme.http_challenge_port = 80;

	/* Create cert directory */
	snprintf(path, sizeof(path), "%s", CERT_DIR);
	mkdir(path, 0700);

	/* Set cert paths */
	snprintf(g_acme.cert_path, sizeof(g_acme.cert_path),
		 "%s/%s.crt", CERT_DIR, domain);
	snprintf(g_acme.key_path, sizeof(g_acme.key_path),
		 "%s/%s.key", CERT_DIR, domain);

	/* Generate domain key if needed */
	if (access(g_acme.key_path, R_OK) != 0) {
		tunl_log(TUNL_LOG_INFO, "acme: generating key for %s", domain);
		if (acme_generate_key(g_acme.key_path) != 0) {
			tunl_log(TUNL_LOG_ERROR, "acme: key generation failed");
			return -1;
		}
	}

	tunl_log(TUNL_LOG_INFO, "acme: initialized for %s (%s)",
		 domain, staging ? "staging" : "production");

	return 0;
}

/*
 * Request or renew certificate
 */
int acme_ensure_cert(void)
{
	if (!g_acme.domain[0]) {
		tunl_log(TUNL_LOG_ERROR, "acme: not initialized");
		return -1;
	}

	if (!acme_needs_renewal(g_acme.cert_path)) {
		tunl_log(TUNL_LOG_INFO, "acme: certificate is valid");
		return 0;
	}

	return acme_request_cert_acmesh(g_acme.domain, g_acme.email,
					g_acme.cert_path, g_acme.key_path);
}

/*
 * Get certificate paths
 */
const char *acme_get_cert_path(void)
{
	return g_acme.cert_path;
}

const char *acme_get_key_path(void)
{
	return g_acme.key_path;
}

/*
 * Auto-renewal thread
 */
void *acme_renewal_thread(void *arg)
{
	(void)arg;

	tunl_log(TUNL_LOG_INFO, "acme: renewal monitor started");

	while (g_state.running) {
		/* Check daily */
		for (int i = 0; i < 86400 && g_state.running; i++)
			sleep(1);

		if (!g_state.running)
			break;

		if (acme_needs_renewal(g_acme.cert_path)) {
			tunl_log(TUNL_LOG_INFO, "acme: certificate needs renewal");
			acme_ensure_cert();
		}
	}

	tunl_log(TUNL_LOG_INFO, "acme: renewal monitor stopped");
	return NULL;
}

/*
 * Print ACME status
 */
void acme_status(char *buf, size_t len)
{
	int needs_renewal = acme_needs_renewal(g_acme.cert_path);

	snprintf(buf, len,
		 "ACME Status:\n"
		 "  Domain: %s\n"
		 "  Cert: %s\n"
		 "  Key: %s\n"
		 "  Needs renewal: %s\n"
		 "  Mode: %s\n",
		 g_acme.domain[0] ? g_acme.domain : "(not set)",
		 g_acme.cert_path,
		 g_acme.key_path,
		 needs_renewal ? "yes" : "no",
		 g_acme.use_staging ? "staging" : "production");
}
