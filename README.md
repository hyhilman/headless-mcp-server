# headless-mcp

A standalone, programmatically-configured MCP hub. Register downstream
MCP servers via a single config file. The hub manages their lifecycle,
aggregates their tools with namespace prefixes, and exposes everything
through a single MCP endpoint. Agents connect once.

## Why

You have N MCP servers (Slack, Linear, Jira, Notion, Postgres,
filesystem, internal APIs…). Every agent needs to be configured with
every single one. Add a new MCP? Edit every agent config. Rotate a
token? Edit every agent config. N agents × M MCPs = auth/config sprawl.

**headless-mcp** is one MCP endpoint that fronts all of them. Register
backends once in the hub. Every agent points to the hub. Done.

## Quick start

### Install

```bash
# From source
git clone https://github.com/hyhilman/headless-mcp-server
cd headless-mcp-server
cargo build --release
cp target/release/headless-mcp ~/.local/bin/

# Or via Docker
docker pull ghcr.io/hyhilman/headless-mcp-server:latest
```

### Create config

Create `~/.config/headless-mcp/config.toml` (or `./headless-mcp.toml`):

```toml
# A local stdio MCP server
[backends.everything]
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-everything"]
namespace = "test"

# A remote HTTP MCP server with a bearer token
[backends.slack]
transport = "http"
url = "https://mcp.slack.com/mcp"
namespace = "slack"
bearer_token = "{{env:SLACK_BOT_TOKEN}}"

# Atlassian Jira with automatic OAuth2
[backends.atlassian]
transport = "http"
url = "https://mcp.atlassian.com/v1/mcp"
namespace = "jira"

[backends.atlassian.oauth2]
grant_type = "authorization_code"
# Discovery + dynamic client registration is automatic
```

### Auth once

```bash
# Set up OAuth2 backends (one-time, interactive)
headless-mcp auth atlassian

# List all backends that need auth
headless-mcp auth

# Auth all of them
headless-mcp auth --all
```

### Verify

```bash
headless-mcp --dry-run
# → test.echo
# → test.get-sum
# → slack.send_message
# → slack.list_channels
# → jira.searchIssuesUsingJql
# → ...
```

### Run

```bash
# Stdio mode (Claude Desktop, local agents)
headless-mcp

# HTTP mode (remote agents, multiple clients)
export HEADLESS_MCP_TOKEN=your-secret-token
headless-mcp serve --http
```

### Connect

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "headless-mcp": {
      "command": "headless-mcp",
      "args": []
    }
  }
}
```

**HTTP clients**:
```bash
curl -X POST http://localhost:9797/mcp \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## How it works

```
                    ┌─────────────────┐
                    │   headless-mcp  │
                    │                 │
  Agent A ─────────→│  BackendRegistry│──→ slack (stdio)
  Agent B ─────────→│  (aggregates    │──→ linear (stdio)
  Script  ─────────→│   all tools)    │──→ postgres (stdio)
                    │                 │──→ atlassian (http)
                    │  Whitelist      │──→ notion (http)
                    │  (per-consumer) │
                    └─────────────────┘
```

Two modes, same binary, same config:

- **Hub mode** (`headless-mcp` or `headless-mcp serve --http`): long-lived
  aggregator. Backends stay connected between calls.
- **One-shot mode** (`headless-mcp call <tool> --arg ...`): no daemon.
  Connects to the backend that owns the tool, calls it, prints the result,
  exits.

## Authentication

### Static bearer tokens (simplest)

Get a token from the provider, set it as an env var:

```toml
[backends.notion]
transport = "http"
url = "https://mcp.notion.com/mcp"
bearer_token = "{{env:NOTION_API_KEY}}"
```

### OAuth2 automatic flow

No manual app registration needed for Atlassian. For Notion/Slack, create
an OAuth app first and add `client_id` + `client_secret`:

```toml
[backends.notion.oauth2]
grant_type = "authorization_code"
client_id = "{{env:NOTION_CLIENT_ID}}"
client_secret = "{{env:NOTION_CLIENT_SECRET}}"
```

On first run:

```bash
headless-mcp auth notion
```

The hub discovers the OAuth2 endpoints automatically (RFC 9728 + RFC 8414),
registers a client if the provider supports dynamic registration (RFC 7591),
opens your browser for consent, captures the callback on `localhost:9798`,
exchanges the code for tokens, and persists the `refresh_token` encrypted
to disk.

After that one-time auth, the hub auto-refreshes the token before expiry —
you never interact with it again, even across restarts.

To persist tokens across restarts, set `HEADLESS_MCP_MASTER_KEY` to a
64-character hex string (32 bytes for AES-256-GCM):

```bash
export HEADLESS_MCP_MASTER_KEY=$(openssl rand -hex 32)
headless-mcp auth atlassian
```

### VPN login (NetBird and similar)

Some backends are only reachable over a VPN whose SSO login expires
(NetBird defaults to 24h). Describe the VPN with three fixed commands:

```toml
[vpn.netbird]
health = ["netbird", "status"]                 # run every check_interval_secs
healthy_if = ["Management: Connected"]         # output substrings = connected
needs_login_if = ["NeedsLogin", "SessionExpired", "LoginFailed"]
expiry = ["/usr/local/bin/netbird-expiry"]     # optional; first output line is reported
login = ["netbird", "up"]                      # must print the SSO link, then wait

[backends.internal-db]
transport = "stdio"
command = "internal-db-mcp"
requires_vpn = ["netbird"]                     # calls are blocked while netbird is down
```

Check the output strings against your NetBird version (`netbird status`).

- **Agents only pick a VPN by name.** Commands come from the config file only.
  `hub.vpn_status` and `hub.vpn_login` accept `{"vpn": "<name>"}` and nothing else.
- **`hub.vpn_login`** runs `login`, returns the link (and any device code)
  as soon as it is printed, and keeps the command running in the background
  until you finish signing in (`login_timeout_secs`, default 600). A second call
  while a login is waiting returns the same link instead of starting another.
- **Blocked calls** to a backend with `requires_vpn`:
  - Clients on MCP 2026-07-28 that support URL elicitation get the login link
    shown to the user directly (not to the model). Their retry waits up to 20s
    for the login, then runs the tool.
  - Other clients get a `VPN_REQUIRED` error telling the agent to call
    `hub.vpn_login`, show you the link, and retry once connected.
- **When the VPN comes back**, backends that require it reconnect automatically.
- **Expose blocks** only get the `hub.vpn_*` tools if they list the VPN:
  `vpn = ["netbird"]` under `[[expose]]`. Without expose blocks, all VPNs are exposed.
- **From a terminal:** `headless-mcp vpn status` and `headless-mcp vpn login netbird`.
- **Watch for changes:** the state is readable as the resource `hub://vpn/<name>`.
  MCP 2026-07-28 clients can `subscriptions/listen` to it and to
  `toolsListChanged` (sent after backends reconnect).

The `hub.` tool namespace is reserved for these tools.

**Login redirects to `localhost`.** If the login sends the browser to
`http://localhost:<port>/...` and the hub runs elsewhere, that page fails to
load. List the ports, then paste the address from the browser's address bar
into `headless-mcp vpn login netbird`, or have the agent pass it to
`hub.vpn_login_complete`:

```toml
[vpn.netbird]
callback_ports = [53000, 54000]   # only http://localhost on these ports, only while a login is waiting
```

**Alerts.** Get told when a VPN needs login, goes down, or comes back:

```toml
[[notify]]
kind = "slack"                     # or "webhook" (JSON) or "ntfy"
url = "{{env:SLACK_WEBHOOK_URL}}"
on = ["needs_login", "down", "connected"]   # default: all three

[vpn.netbird]
auto_login = true                  # start the login right away; the alert carries the link
```

**MCP Events** (as used by ChatGPT): clients can subscribe to
`vpn.state_changed` and receive signed webhooks
([Standard Webhooks](https://www.standardwebhooks.com/)).

```toml
[events]
enabled = true
# include_login_url = false        # put the pending login link in payloads
# default_ttl_secs = 86400
# max_ttl_secs = 604800
# allow_insecure_callbacks = false # testing only: allow http:// and private addresses
```

Callbacks must be HTTPS to a public address (checked at connect time, no
redirects) and pass a signed challenge before any event is sent.
Subscriptions are saved to `$HEADLESS_MCP_DATA_DIR/events.json` (mode 0600;
it contains the signing secrets).

**AWS SSO and other CLI logins** work the same way. A `[vpn.<name>]` section is
just "a session with health and login commands":

```toml
[vpn.aws-prod]
health = ["aws", "sts", "get-caller-identity", "--profile", "prod"]
needs_login_if = ["Token has expired", "SSO session", "expired"]
login = ["aws", "sso", "login", "--profile", "prod", "--use-device-code", "--no-browser"]

[backends.aws]
transport = "stdio"
command = "uvx"
args = ["mcp-proxy-for-aws==1.6.2", "https://aws-mcp.us-east-1.api.aws/mcp", "--profile", "prod"]
requires_vpn = ["aws-prod"]
pin_args = { profile = "prod" }    # agents can't switch profile
deny_args = ["account_id"]         # calls passing this are rejected
```

### Protocol versions

The hub speaks MCP 2026-07-28 (`server/discover`, version in every request's
`_meta`, `resultType`, `subscriptions/listen`, multi round-trip requests)
alongside older versions (`initialize` handshake). Over HTTP, modern requests
must send a matching `MCP-Protocol-Version` header.

## Config reference

### Config file discovery

```
--config <path>                ← explicit, takes priority
./headless-mcp.toml            ← current working directory
~/.config/headless-mcp/config.toml  ← user-level fallback
```

### Backend options

| Field | Description |
|---|---|
| `transport` | `"stdio"` (spawn process) or `"http"` (remote URL) |
| `command` | For stdio: the executable to spawn |
| `args` | For stdio: command-line arguments |
| `env` | For stdio: extra environment variables |
| `cwd` | For stdio: working directory |
| `url` | For HTTP: the MCP endpoint URL |
| `bearer_token` | For HTTP: static bearer token. Supports `{{env:VAR}}` and `{{secret:NAME}}` |
| `namespace` | Prefix for all tools from this backend (`slack.` → `slack.send_message`) |
| `connection_mode` | `"eager"` (startup), `"lazy"` (first use), `"per_call"` (stateless) |
| `connect_timeout_secs` | Timeout for the initialize handshake (default: 10) |
| `call_timeout_secs` | Timeout for each tool call (default: 30) |
| `stderr_mode` | `"log-on-error"`, `"silent"`, `"passthrough"`, `"log-always"` |
| `requires_vpn` | VPN names (`[vpn.<name>]`) that must be connected before calls are forwarded |
| `pin_args` | Table of tool arguments always set by the hub (caller values are overwritten; hidden from schemas) |
| `deny_args` | Tool arguments callers may not send (calls are rejected; hidden from schemas) |

### VPN options

Under `[vpn.<name>]` (unknown keys are rejected):

| Field | Description |
|---|---|
| `health` | Command (argv list). Exit 0 + `healthy_if` match = connected |
| `healthy_if` | Output substrings meaning connected (empty = exit code only) |
| `needs_login_if` | Output substrings meaning login required (checked first) |
| `expiry` | Optional command; first output line reported as `expires_at` |
| `login` | Command that prints the SSO link and waits for the user |
| `url_prefixes` | How to spot the link in login output (default `["https://"]`) |
| `check_interval_secs` | Health check interval (default 60) |
| `command_timeout_secs` | Timeout for `health`/`expiry` (default 15) |
| `url_wait_secs` | How long to wait for the link to appear (default 30) |
| `login_timeout_secs` | How long the login may wait for the user (default 600) |
| `callback_ports` | Ports for pasting back a `http://localhost` redirect (empty = off) |
| `auto_login` | Start the login as soon as it is needed; alerts carry the link |

### OAuth2 options

Under `[backends.<id>.oauth2]`:

| Field | Description |
|---|---|
| `grant_type` | `"client_credentials"` (M2M) or `"authorization_code"` (interactive) |
| `token_endpoint` | Optional: override auto-discovered endpoint |
| `client_id` | OAuth2 client ID |
| `client_secret` | OAuth2 client secret |
| `scopes` | Space-separated scopes (default: `"mcp"`) |

## CLI

```
headless-mcp

COMMANDS:
  auth [<backend>]    One-time OAuth2 authorization (interactive)
  call <tool> [...]   One-shot: call a tool and print the result
  tools               List all aggregated tools from all backends
  config              Print the resolved config
  vpn [status [<name>] | login <name>]
                      Check VPN state, or print the SSO link and wait for login
                      (paste a localhost redirect address while waiting)
  serve               Start the hub daemon

  serve OPTIONS:
    --http            Serve over HTTP (default: stdio)
    --port <PORT>     HTTP port (default: 9797)
    --bind <ADDR>     Bind address (default: 127.0.0.1)

  call OPTIONS:
    -a, --arg k=v     Tool arguments (repeatable)
    --json '{"k":"v"}' JSON arguments
    -f, --format      pretty | json | table

OPTIONS:
  -c, --config <PATH> Config file path
  -v, --verbose       Debug logging
  --dry-run           Validate config + connectivity, print tools, exit
```

## Docker

```bash
# docker-compose (recommended)
echo "HEADLESS_MCP_TOKEN=your-secret" > .env
docker compose up -d

# Or plain docker
docker run -d \
  -p 127.0.0.1:9797:9797 \
  -v ./headless-mcp.toml:/home/headless-mcp/.config/headless-mcp/config.toml:ro \
  -v headless-mcp-data:/data \
  -e HEADLESS_MCP_TOKEN=your-secret \
  ghcr.io/hyhilman/headless-mcp-server:latest
```

The image is published to `ghcr.io/hyhilman/headless-mcp-server` on every
version bump in `Cargo.toml`. See `.github/workflows/release.yml`.

## Architecture

```
headless-mcp/
├── crates/
│   ├── mcp-wire/            JSON-RPC 2.0 + SSE codec
│   ├── core/                McpBackend trait, BackendDef, error types
│   ├── secrets/             AES-256-GCM encrypted credential store
│   ├── backends/
│   │   ├── backend-stdio/   Spawn process, JSON-RPC over stdin/stdout
│   │   └── backend-http/    HTTP+SSE transport with OAuth2 auto-discovery
│   ├── registry/            Backend registry, namespacing, health checks
│   ├── mcp-server/          Transport-agnostic session + dispatch
│   ├── transport-stdio/     Serve hub over newline-delimited JSON-RPC
│   ├── transport-http/      Serve hub over HTTP with auth + rate limiting
│   └── server/              Binary: CLI, config loading, one-shot calls
```

## Guardrails

1. Never panic on malformed input — always return a typed error.
2. Backend credentials never appear in logs, error messages, or tool results.
3. Tool execution failures → `isError: true` in the result, not JSON-RPC error.
4. Adding a new transport must not change existing backends or the trait.
5. Collision in tool names → startup error with conflicting backends listed.
6. A hung backend must not hang the hub — timeouts are always enforced.
7. In HTTP mode, every request must carry a valid bearer token.
