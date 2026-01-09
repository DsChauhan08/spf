# tunl User Guide

## Overview

tunl is a minimal TCP proxy for home hosting with IPv6.

## Installation

```bash
make
sudo make install
```

## Basic Usage

### Quick Forward

Forward a port to a backend:

```bash
tunl -f 8080:localhost:3000
```

This listens on port 8080 (IPv6 dual-stack) and forwards to localhost:3000.

### Daemon Mode

Run in background:

```bash
tunl -f 8080:localhost:3000 -d
```

## Configuration

### Config File

```ini
# tunl.conf

[admin]
bind = ::1
port = 8081
token = your-secret-token

[rule.1]
listen = 8080
backend = localhost:3000
lb = rr
max_conns = 512

[rule.2]
listen = 9000
backend = 192.168.1.10:80
backend = 192.168.1.11:80
lb = lc
```

### Load Balancing

- `rr` - Round-robin (default)
- `lc` - Least connections
- `ip` - IP hash (sticky sessions)

## Control Interface

Connect to the control port:

```bash
nc localhost 8081
```

### Commands

| Command | Description |
|---------|-------------|
| `STATUS` | Show uptime, connections, bytes |
| `RULES` | List active rules |
| `HEALTH` | Show backend health status |
| `SHUTDOWN` | Stop the server |
| `QUIT` | Disconnect |
| `AUTH <token>` | Authenticate (if token set) |

## IPv6 Notes

tunl creates dual-stack sockets that accept both IPv4 and IPv6.

Check your IPv6 address:

```bash
ip -6 addr show scope global
curl -6 ifconfig.me
```

## Security

1. **Firewall**: Use ip6tables to restrict access
2. **Token**: Set an auth token for the control interface
3. **Bind address**: Bind control to localhost only

```ini
[admin]
bind = ::1
token = $(openssl rand -hex 16)
```
