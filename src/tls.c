#include "common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

static SSL_CTX* g_server_ctx = NULL;
static SSL_CTX* g_client_ctx = NULL;

int tls_init(const char* cert, const char* key) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_server_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_server_ctx) {
        spf_log(SPF_LOG_ERROR, "tls: failed to create server ctx");
        return -1;
    }
    
    SSL_CTX_set_min_proto_version(g_server_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_server_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    SSL_CTX_set_cipher_list(g_server_ctx, 
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256");
    
    if (cert && key) {
        if (access(cert, R_OK) != 0) {
            spf_log(SPF_LOG_ERROR, "tls: cert not readable: %s", cert);
            return -1;
        }
        if (access(key, R_OK) != 0) {
            spf_log(SPF_LOG_ERROR, "tls: key not readable: %s", key);
            return -1;
        }
        
        if (SSL_CTX_use_certificate_file(g_server_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
            spf_log(SPF_LOG_ERROR, "tls: failed to load cert");
            return -1;
        }
        if (SSL_CTX_use_PrivateKey_file(g_server_ctx, key, SSL_FILETYPE_PEM) <= 0) {
            spf_log(SPF_LOG_ERROR, "tls: failed to load key");
            return -1;
        }
        if (!SSL_CTX_check_private_key(g_server_ctx)) {
            spf_log(SPF_LOG_ERROR, "tls: key doesn't match cert");
            return -1;
        }
    }
    
    g_client_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_client_ctx) {
        spf_log(SPF_LOG_ERROR, "tls: failed to create client ctx");
        return -1;
    }
    SSL_CTX_set_min_proto_version(g_client_ctx, TLS1_2_VERSION);
    
    spf_log(SPF_LOG_INFO, "tls: initialized");
    return 0;
}

void tls_cleanup(void) {
    if (g_server_ctx) {
        SSL_CTX_free(g_server_ctx);
        g_server_ctx = NULL;
    }
    if (g_client_ctx) {
        SSL_CTX_free(g_client_ctx);
        g_client_ctx = NULL;
    }
    EVP_cleanup();
    ERR_free_strings();
}

SSL_CTX* tls_get_server_ctx(void) {
    return g_server_ctx;
}

SSL_CTX* tls_get_client_ctx(void) {
    return g_client_ctx;
}

SSL* tls_accept(int fd) {
    if (!g_server_ctx) return NULL;
    
    SSL* ssl = SSL_new(g_server_ctx);
    if (!ssl) return NULL;
    
    SSL_set_fd(ssl, fd);
    
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

SSL* tls_connect(int fd, const char* hostname) {
    if (!g_client_ctx) return NULL;
    
    SSL* ssl = SSL_new(g_client_ctx);
    if (!ssl) return NULL;
    
    SSL_set_fd(ssl, fd);
    
    if (hostname) {
        SSL_set_tlsext_host_name(ssl, hostname);
    }
    
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

/**
 * tls_read - Read data from TLS connection
 * @ssl: SSL connection handle
 * @buf: destination buffer
 * @len: maximum bytes to read
 *
 * Returns bytes read, 0 for EAGAIN, -1 on error.
 */
ssize_t tls_read(SSL *ssl, void *buf, size_t len)
{
	int n, err;

	if (!ssl || !buf)
		return -1;

	/* Clamp to INT_MAX to prevent overflow in SSL_read */
	if (len > INT_MAX)
		len = INT_MAX;

	n = SSL_read(ssl, buf, (int)len);
	if (n <= 0) {
		err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0;
		return -1;
	}
	return (ssize_t)n;
}

/**
 * tls_write - Write data to TLS connection
 * @ssl: SSL connection handle
 * @buf: source buffer
 * @len: bytes to write
 *
 * Returns bytes written, 0 for EAGAIN, -1 on error.
 */
ssize_t tls_write(SSL *ssl, const void *buf, size_t len)
{
	int n, err;

	if (!ssl || !buf)
		return -1;

	/* Clamp to INT_MAX to prevent overflow in SSL_write */
	if (len > INT_MAX)
		len = INT_MAX;

	n = SSL_write(ssl, buf, (int)len);
	if (n <= 0) {
		err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0;
		return -1;
	}
	return (ssize_t)n;
}

void tls_close(SSL* ssl) {
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int tls_set_client_cert(const char* cert, const char* key) {
    if (!g_client_ctx) return -1;
    
    if (SSL_CTX_use_certificate_file(g_client_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(g_client_ctx, key, SSL_FILETYPE_PEM) <= 0) {
        return -1;
    }
    
    spf_log(SPF_LOG_INFO, "tls: client cert loaded for mtls");
    return 0;
}

int tls_require_client_cert(void) {
    if (!g_server_ctx) return -1;
    SSL_CTX_set_verify(g_server_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    spf_log(SPF_LOG_INFO, "tls: mtls enabled");
    return 0;
}

const char* tls_get_cipher(SSL* ssl) {
    if (!ssl) return "none";
    return SSL_get_cipher(ssl);
}

const char* tls_get_version(SSL* ssl) {
    if (!ssl) return "none";
    return SSL_get_version(ssl);
}
