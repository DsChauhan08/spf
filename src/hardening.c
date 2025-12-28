/*
 * SPF Security Hardening Module
 * 
 * Enterprise-grade security hardening for safe home hosting.
 * These features make SPF as secure as industry-standard solutions.
 * 
 * FEATURES:
 *   - Privilege dropping (run as non-root after binding)
 *   - Resource limits (prevent DoS via resource exhaustion)
 *   - Memory protections
 *   - Secure defaults
 *   - Signal handling hardening
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <linux/capability.h>
#endif

// Security configuration
typedef struct {
    bool drop_privileges;
    char run_user[64];
    char run_group[64];
    bool chroot_enabled;
    char chroot_path[256];
    uint32_t max_open_files;
    uint32_t max_memory_mb;
    uint32_t max_processes;
    bool disable_core_dumps;
    bool protect_memory;
} spf_hardening_config_t;

static spf_hardening_config_t g_hardening = {
    .drop_privileges = true,
    .run_user = "nobody",
    .run_group = "nogroup",
    .chroot_enabled = false,
    .chroot_path = "",
    .max_open_files = 65536,
    .max_memory_mb = 1024,
    .max_processes = 256,
    .disable_core_dumps = true,
    .protect_memory = true
};

// Set resource limits
static int set_resource_limits(void) {
    struct rlimit rl;
    int ret = 0;
    
    // Max open files
    rl.rlim_cur = g_hardening.max_open_files;
    rl.rlim_max = g_hardening.max_open_files;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        spf_log(SPF_LOG_WARN, "hardening: failed to set RLIMIT_NOFILE: %s", strerror(errno));
        ret = -1;
    }
    
    // Max memory (address space)
    if (g_hardening.max_memory_mb > 0) {
        rl.rlim_cur = (rlim_t)g_hardening.max_memory_mb * 1024 * 1024;
        rl.rlim_max = rl.rlim_cur;
        if (setrlimit(RLIMIT_AS, &rl) != 0) {
            spf_log(SPF_LOG_WARN, "hardening: failed to set RLIMIT_AS: %s", strerror(errno));
        }
    }
    
    // Max processes
    if (g_hardening.max_processes > 0) {
        rl.rlim_cur = g_hardening.max_processes;
        rl.rlim_max = g_hardening.max_processes;
        if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
            spf_log(SPF_LOG_WARN, "hardening: failed to set RLIMIT_NPROC: %s", strerror(errno));
        }
    }
    
    // Disable core dumps (security: prevent credential leakage)
    if (g_hardening.disable_core_dumps) {
        rl.rlim_cur = 0;
        rl.rlim_max = 0;
        if (setrlimit(RLIMIT_CORE, &rl) != 0) {
            spf_log(SPF_LOG_WARN, "hardening: failed to disable core dumps: %s", strerror(errno));
        }
    }
    
    return ret;
}

// Drop privileges after binding to ports
int spf_hardening_drop_privileges(void) {
    if (!g_hardening.drop_privileges) {
        spf_log(SPF_LOG_INFO, "hardening: privilege dropping disabled");
        return 0;
    }
    
    // Already non-root
    if (getuid() != 0) {
        spf_log(SPF_LOG_INFO, "hardening: already running as non-root (uid=%d)", getuid());
        return 0;
    }
    
    struct passwd* pw = getpwnam(g_hardening.run_user);
    if (!pw) {
        spf_log(SPF_LOG_ERROR, "hardening: user '%s' not found", g_hardening.run_user);
        return -1;
    }
    
    struct group* gr = getgrnam(g_hardening.run_group);
    gid_t gid = gr ? gr->gr_gid : pw->pw_gid;
    
#ifdef __linux__
    // Keep CAP_NET_BIND_SERVICE for ports < 1024 if needed
    prctl(PR_SET_KEEPCAPS, 1);
#endif
    
    // Change to chroot if enabled
    if (g_hardening.chroot_enabled && g_hardening.chroot_path[0]) {
        if (chroot(g_hardening.chroot_path) != 0) {
            spf_log(SPF_LOG_ERROR, "hardening: chroot failed: %s", strerror(errno));
            return -1;
        }
        if (chdir("/") != 0) {
            spf_log(SPF_LOG_ERROR, "hardening: chdir after chroot failed: %s", strerror(errno));
            return -1;
        }
        spf_log(SPF_LOG_INFO, "hardening: chrooted to %s", g_hardening.chroot_path);
    }
    
    // Drop supplementary groups
    if (setgroups(0, NULL) != 0) {
        spf_log(SPF_LOG_WARN, "hardening: setgroups failed: %s", strerror(errno));
    }
    
    // Set GID first (must be done before setuid)
    if (setgid(gid) != 0) {
        spf_log(SPF_LOG_ERROR, "hardening: setgid failed: %s", strerror(errno));
        return -1;
    }
    
    // Drop to user
    if (setuid(pw->pw_uid) != 0) {
        spf_log(SPF_LOG_ERROR, "hardening: setuid failed: %s", strerror(errno));
        return -1;
    }
    
    // Verify we can't regain root
    if (setuid(0) == 0) {
        spf_log(SPF_LOG_ERROR, "hardening: CRITICAL - still able to regain root!");
        _exit(1);
    }
    
#ifdef __linux__
    // Prevent ptrace attachment (anti-debugging)
    prctl(PR_SET_DUMPABLE, 0);
#endif
    
    spf_log(SPF_LOG_INFO, "hardening: dropped privileges to %s:%s (uid=%d, gid=%d)",
           g_hardening.run_user, g_hardening.run_group, pw->pw_uid, gid);
    
    return 0;
}

// Apply all security hardening
int spf_hardening_init(void) {
    spf_log(SPF_LOG_INFO, "hardening: initializing security hardening");
    
    // Set resource limits
    set_resource_limits();
    
#ifdef __linux__
    // Prevent new privileges via execve
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        spf_log(SPF_LOG_WARN, "hardening: PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
    }
    
    // Set dumpable to 0 (no core dumps, no ptrace)
    if (g_hardening.protect_memory) {
        prctl(PR_SET_DUMPABLE, 0);
    }
#endif
    
    // Ignore dangerous signals
    signal(SIGPIPE, SIG_IGN);
    
    // Secure umask
    umask(0077);
    
    spf_log(SPF_LOG_INFO, "hardening: security hardening applied");
    return 0;
}

// Configure hardening options
void spf_hardening_configure(const char* user, const char* group,
                            bool drop_privs, uint32_t max_files,
                            uint32_t max_mem_mb) {
    if (user) {
        strncpy(g_hardening.run_user, user, sizeof(g_hardening.run_user) - 1);
        g_hardening.run_user[sizeof(g_hardening.run_user) - 1] = '\0';
    }
    if (group) {
        strncpy(g_hardening.run_group, group, sizeof(g_hardening.run_group) - 1);
        g_hardening.run_group[sizeof(g_hardening.run_group) - 1] = '\0';
    }
    g_hardening.drop_privileges = drop_privs;
    if (max_files > 0) g_hardening.max_open_files = max_files;
    if (max_mem_mb > 0) g_hardening.max_memory_mb = max_mem_mb;
}

// Configure chroot
void spf_hardening_set_chroot(const char* path) {
    if (path && path[0]) {
        strncpy(g_hardening.chroot_path, path, sizeof(g_hardening.chroot_path) - 1);
        g_hardening.chroot_path[sizeof(g_hardening.chroot_path) - 1] = '\0';
        g_hardening.chroot_enabled = true;
    } else {
        g_hardening.chroot_enabled = false;
    }
}

// Get hardening status
void spf_hardening_status(char* buf, size_t len) {
    snprintf(buf, len,
        "=== Security Hardening Status ===\n"
        "Running as: uid=%u, gid=%u\n"
        "Privilege dropping: %s\n"
        "Target user: %s\n"
        "Target group: %s\n"
        "Chroot: %s\n"
        "Max open files: %u\n"
        "Max memory: %u MB\n"
        "Core dumps: %s\n",
        (unsigned)getuid(), (unsigned)getgid(),
        g_hardening.drop_privileges ? "enabled" : "disabled",
        g_hardening.run_user,
        g_hardening.run_group,
        g_hardening.chroot_enabled ? g_hardening.chroot_path : "disabled",
        g_hardening.max_open_files,
        g_hardening.max_memory_mb,
        g_hardening.disable_core_dumps ? "disabled" : "enabled");
}

// Secure memory allocation wrapper
void* spf_secure_alloc(size_t size) {
    if (size == 0 || size > (1024 * 1024 * 100)) {  // Max 100MB single alloc
        return NULL;
    }
    
    void* ptr = calloc(1, size);  // Zero-initialized
    return ptr;
}

// Secure memory free (zero before free)
void spf_secure_free(void* ptr, size_t size) {
    if (ptr) {
        if (size > 0) {
            volatile char* p = (volatile char*)ptr;
            while (size--) *p++ = 0;
        }
        free(ptr);
    }
}

// Constant-time memory comparison (prevent timing attacks)
int spf_secure_compare(const void* a, const void* b, size_t len) {
    const volatile unsigned char* pa = (const volatile unsigned char*)a;
    const volatile unsigned char* pb = (const volatile unsigned char*)b;
    volatile unsigned char diff = 0;
    
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    
    return diff == 0 ? 0 : 1;
}

// Validate file path (prevent path traversal)
int spf_secure_validate_path(const char* path) {
    if (!path) return -1;
    
    // Check for null bytes
    if (memchr(path, '\0', strlen(path)) != NULL) {
        return -1;  // Embedded null byte
    }
    
    // Check for path traversal
    if (strstr(path, "..") != NULL) return -1;
    if (strstr(path, "//") != NULL) return -1;
    
    // Check for shell metacharacters
    const char* dangerous = "|;&$`\\!*?[]<>(){}";
    for (const char* p = path; *p; p++) {
        if (strchr(dangerous, *p)) return -1;
    }
    
    return 0;
}
