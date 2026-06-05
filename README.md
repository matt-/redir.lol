# redir

A self-contained redirect and DNS rebinding tool for security testing — SSRF, open redirect, and DNS rebind attack simulation.

## Features

- **HTTP redirects** — 301, 302, 303, 307, 308 with configurable status code
- **Meta-refresh and JavaScript redirects** — useful when targets filter `Location` headers
- **Proxy mode** — fetch-on-behalf: the server fetches the target URL and pipes the response back, confirming SSRF reachability
- **DNS rebinding** — authoritative DNS server that flips the A record after a configurable number of queries (TTL=1)
- **SSRF presets** — one-click targets for AWS, GCP, Azure IMDS, Kubernetes API, Docker daemon, and localhost variants
- **Hit log** — records every redirect trigger with IP and User-Agent, stored in SQLite
- **Multi-user** — email/password accounts, each user sees only their own rules
- **Admin panel** — paginated view of all rules across all users, with delete

## Quickstart

```bash
go build -o redir .
./redir
```

Open `http://localhost:8080`. Register an account and start creating redirect rules.

The binary has no runtime dependencies — the web UI is embedded and the database is created automatically.

## Files

| Path | Purpose |
|---|---|
| `~/.redir/config.yaml` | Config file — created with defaults on first run |
| `~/.redir/redir.db` | SQLite database — rules, users, sessions, hit log |

Both paths can be overridden; see **Configuration** below.

## Configuration

On first run `~/.redir/config.yaml` is created automatically with defaults. Edit it to set your domain, admin emails, and other options. See `config.example.yaml` for a template.

| Field | Default | Description |
|---|---|---|
| `port` | `9999` | HTTP port for the web UI, API, and redirect engine |
| `dns_port` | `5300` | UDP port for the DNS server |
| `domain` | `redir.local` | Base domain for DNS rebind hostnames |
| `proxy_domain` | *(empty)* | Domain to serve proxy responses from (e.g. `proxy.yourdomain.com`). When set, proxy rules redirect the browser to this domain so proxied content is isolated from the main app origin. If unset, proxy responses are served inline (fine for local use, XSS risk in production). |
| `db` | `~/.redir/redir.db` | Path to the SQLite database |
| `public_ip` | *(auto-detected)* | Public IP advertised as the rebind first-hop. Auto-detected from outbound interface if empty |
| `bind` | `0.0.0.0` | Network interface to bind on |
| `admin_emails` | `[]` | List of email addresses that have admin access |

Any setting can be overridden at runtime with a CLI flag:

```bash
./redir -port 80 -dns-port 53 -domain rebind.yourdomain.com -public-ip 1.2.3.4
```

CLI flags take precedence over the config file. The config file is not rewritten when flags are used.

To point to a different config file:

```bash
./redir -config /etc/redir/config.yaml
```

## DNS Rebinding

Port 53 requires root or a port-forward. The startup banner prints the exact command for your platform.

**macOS** (redirect 53 → dns_port without root):
```bash
echo "rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port 5300" | sudo pfctl -ef -
```

**Linux** (redirect 53 → dns_port without root):
```bash
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
```

**Run directly on port 53:**
```bash
sudo ./redir -dns-port 53
```

For rebinding to work in a real browser, `domain` must be a domain you control with NS records pointing to this machine. `redir.local` works for local testing with `/etc/hosts` overrides or mDNS.

### DNS records

For a setup with `domain: rebind.yourdomain.com` and `proxy_domain: proxy.yourdomain.com`:

| Type | Name | Value | Purpose |
|---|---|---|---|
| `A` | `yourdomain.com` | server IP | Main app |
| `A` | `ns1.yourdomain.com` | server IP | Glue record for NS delegation |
| `NS` | `rebind.yourdomain.com` | `ns1.yourdomain.com` | Delegates rebind subdomain to this server |
| `A` | `proxy.yourdomain.com` | server IP | Isolated proxy origin |

The `NS` + glue `A` pair is what allows the built-in DNS server to answer queries for `*.rebind.yourdomain.com` with TTL=1 for rebinding. The `proxy.yourdomain.com` record isolates proxied content from the main app origin to prevent XSS from affecting your session.

## Admin

Users whose email is listed in `admin_emails` in the config file get an **Admin** tab after login. The admin tab shows all redirect rules across all accounts with the owner's email, hit count, and a delete button. Rules are paginated at 25 per page.

## Building

```bash
# macOS / current platform
make build

# Linux (cross-compile from macOS)
make build-linux
```

## API

All API routes except `/api/auth/*` require a valid session cookie.

### Auth
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | `{ email, password }` → creates account, sets session cookie |
| `POST` | `/api/auth/login` | `{ email, password }` → sets session cookie |
| `POST` | `/api/auth/logout` | Clears session cookie |
| `GET` | `/api/auth/me` | Returns `{ id, email, is_admin }` |

### Redirect Rules
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/rules` | List your rules |
| `POST` | `/api/rules` | Create a rule |
| `PUT` | `/api/rules/:id` | Update a rule |
| `DELETE` | `/api/rules/:id` | Delete a rule |

Rule fields: `label` (optional slug), `target_url`, `type` (`http`/`meta`/`js`/`proxy`), `status_code` (for `http` type: 301/302/303/307/308).

### DNS Rebind Rules
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/rebind` | List your rebind rules (includes live query count) |
| `POST` | `/api/rebind` | Create a rebind rule |
| `DELETE` | `/api/rebind/:id` | Delete a rebind rule |
| `POST` | `/api/rebind/:id/reset` | Reset the query counter |

Rebind rule fields: `label`, `first_ip`, `second_ip`, `threshold` (queries before flip, default 1).

### Admin (admin accounts only)
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/rules?page=1&per_page=25` | All rules across all users |
| `DELETE` | `/api/admin/rules/:id` | Delete any rule |

### Other
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/presets` | List of SSRF preset target URLs |
| `GET` | `/api/config` | Server configuration (ports, domain, public IP) |
| `GET` | `/api/hits` | Last 100 hits for your rules |

### Redirect Engine (public, no auth)
```
GET /r/<label-or-id>
```
Triggers the configured redirect. No session required — share these URLs with targets freely.
