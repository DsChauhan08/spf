# SPF Detailed Usage Guide

This guide gives step-by-step instructions to deploy SPF for port forwarding and self-hosted tunnels. It replaces the long-form README usage sections.

## 1. Installation

### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev pkg-config
make
sudo make install
```

### Red Hat / CentOS
```bash
sudo yum install -y gcc gcc-c++ make openssl-devel pkgconfig
make
sudo make install
```

### macOS
```bash
brew install openssl@3
make LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib" \
     CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
sudo make install
```

### Windows (MSYS2)
```bash
pacman -S --noconfirm mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make
make CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ LIBS="-lssl -lcrypto -lws2_32" TARGET=spf.exe
```

### OpenBSD
```bash
pkg_add gmake gcc openssl
gmake CC=gcc CXX=g++ LIBS="-lssl -lcrypto"
```

## 2. Quick Start (no config file)

- Forward like socat:
  ```bash
  spf -f 8080:backend:80
  ```
- Expose local port with a relay:
  ```bash
  spf expose 3000 --relay myrelay.com --name app
  ```
- Run your own relay (VPS):
  ```bash
  spf relay mydomain.com --cert cert.pem --key key.pem
  ```

## 3. Tunnel Mode (Cloudflare/Ngrok alternative)

### On the VPS (relay)
1) Point DNS `*.yourdomain.com` to the VPS IP.
2) Run the relay:
   ```bash
   spf relay yourdomain.com --port 443 --tunnel-port 7000 \
     --cert /path/fullchain.pem --key /path/privkey.pem
   ```

### At home (client)
```bash
spf expose 3000 --relay yourdomain.com --name myapp
# Now reachable at: https://myapp.yourdomain.com
```

Notes:
- The tunnel is outbound from home, so NAT/CGNAT is not a blocker.
- If `--name` is omitted, the relay generates a random subdomain.

## 4. Relay Mode Details

- `--port`: public HTTPS port for users (default 443).
- `--tunnel-port`: control/data plane (default 7000).
- TLS is recommended; use Let’s Encrypt certs on the VPS.
- Run as a non-root user if you bind high ports (e.g., 8443 for public).

## 5. One-Liner Forwarding (L4 proxy)

Syntax: `spf -f listen:target:port`

Examples:
```bash
# HTTP
spf -f 8080:app.internal:80
# TLS termination with provided cert/key
spf -f 443:10.0.0.1:8080 -c cert.pem -k key.pem
# Custom access log
spf -f 9000:api:9000 -A /var/log/spf/access.log
```

## 6. Using a Config File

Minimal `spf.conf` example:
```ini
[rule.10001]
listen = 8080
lb = rr
backend = 10.0.0.1:8080:1
backend = 10.0.0.2:8080:1
max_conns = 512
accept_rate = 150
```
Run with:
```bash
spf --config spf.conf --token changeme
```

## 7. Control Socket (live changes)

Default control port: 8081 (loopback only). Example session:
```bash
nc 127.0.0.1 8081
AUTH changeme
ADD 8443 10.0.0.10:8443 lc 512 150
STATUS
QUIT
```

## 8. Load Balancing Algorithms
- `rr`: round-robin (default)
- `lc`: least connections
- `ip`: IP hash (sticky)
- `w`: weighted (use backend weights)

## 9. Rate Limits and Caps
- `max_conns`: concurrent connection cap per rule.
- `accept_rate`: max new connections per second per rule (token bucket at accept).

## 10. Health Checks
- Automatic backend health checks run per rule.
- Failed backends are skipped until they recover.

## 11. Access Logging
Enable JSON access logs:
```bash
spf -f 8080:backend:80 -A /var/log/spf/access.log
```
Log fields: timestamp, client_ip, client_port, rule_id, backend, bytes_in, bytes_out, duration_ms, status_code.

## 12. Custom Security Hooks
Place executables in a hooks directory (e.g., `/etc/spf/hooks.d`). Environment variables:
- `SPF_CLIENT_IP`, `SPF_CLIENT_PORT`
- `SPF_RULE_ID`, `SPF_BACKEND_IP`, `SPF_BACKEND_PORT`
- `SPF_TIMESTAMP`, `SPF_EVENT_TYPE`

Exit codes: `0` allow, `1` block, `2` rate-limit.

Example allow/block hook (bash):
```bash
#!/bin/bash
[ "$SPF_CLIENT_IP" = "1.2.3.4" ] && exit 1
exit 0
```

## 13. TLS
- For forward mode, supply `-c` and `-k` to terminate TLS locally.
- For relay mode, TLS secures user traffic; the tunnel control channel also uses TLS via OpenSSL.
- Keep OpenSSL up to date on all hosts.

## 14. Daemon and Service
- `spf --daemon` to fork to background.
- Systemd: `sudo make install-service` (creates /etc/systemd/system/spf.service). Edit token before enabling.

## 15. Signals
- `SIGHUP`: reload config.
- `SIGINT`/`SIGTERM`: graceful shutdown.

## 16. Troubleshooting
- "cannot bind": port in use or privilege required (try high port or sudo).
- "cannot resolve relay": check DNS for relay host.
- No traffic reaching backend: verify local server is listening (spf warns if local port is closed in tunnel/expose mode).
- TLS errors: confirm cert/key paths and file permissions.

## 17. Release Artifacts (CI)
On tagged pushes (`v*`), GitHub Actions builds:
- Linux binary + `.deb` + `.rpm`
- Windows `.exe`
- macOS binary
- OpenBSD binary tarball

Download from the GitHub Release for that tag.
