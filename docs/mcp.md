# headless-mcp

Aggregate multiple MCP servers behind one endpoint.

**Currently supports**: Slack (19 tools), Atlassian Jira+Confluence (31 tools)

## Quick Start

```bash
# 1. Build
cargo build --release

# 2. Set encryption key (do this once, keep it safe)
export HEADLESS_MCP_MASTER_KEY=$(openssl rand -hex 32)

# 3. Create config
cat > headless-mcp.toml << 'EOF'
[backends.slack]
transport = "http"
url = "https://mcp.slack.com/mcp"
namespace = "slack"

[backends.slack.oauth2]
grant_type = "authorization_code"
client_id = "1601185624273.8899143856786"
callback_port = 3118

[backends.atlassian]
transport = "http"
url = "https://mcp.atlassian.com/v1/mcp"
namespace = "jira"

[backends.atlassian.oauth2]
grant_type = "authorization_code"
callback_port = 9798
EOF

# 4. Authenticate (one-time, opens browser)
headless-mcp auth --all

# 5. Verify
headless-mcp tools
```

## CLI Usage

### Daemon mode (default)

Uses only persisted tokens. Never opens a browser. Safe for background/automated use.

```bash
# Start the hub (stdio)
headless-mcp

# Start as HTTP server
headless-mcp serve --http --port 9797

# List tools
headless-mcp tools

# Dry run: connect + list tools, then exit
headless-mcp --dry-run

# One-shot call
headless-mcp call jira.atlassianUserInfo
headless-mcp call jira.searchJiraIssuesUsingJql --json '{"jql":"assignee = currentUser() ORDER BY updated DESC","cloudId":"...","maxResults":5,"fields":["summary","status"]}'
headless-mcp call slack.slack_send_message --json '{"channel_id":"C...","message":"hello"}'
```

### Non-daemon mode (`--no-daemon`)

Allows interactive OAuth2 if no valid persisted token exists. Useful for one-off calls or re-authentication.

```bash
headless-mcp --no-daemon tools
headless-mcp --no-daemon call slack.slack_read_channel --json '{"channel_id":"C..."}'
headless-mcp --no-daemon --dry-run
```

### auth (always non-daemon)

```bash
headless-mcp auth slack       # authenticate one backend
headless-mcp auth atlassian   # authenticate one backend
headless-mcp auth --all       # authenticate all OAuth2 backends
```

## Connecting Claude Desktop

### stdio transport (recommended — daemon mode)

```json
{
  "mcpServers": {
    "headless-mcp": {
      "command": "/path/to/headless-mcp",
      "env": {
        "HEADLESS_MCP_MASTER_KEY": "your-32-byte-hex-key"
      }
    }
  }
}
```

Claude starts `headless-mcp`, it loads persisted tokens from `secrets.json`, connects to all backends, and exposes 50+ tools via stdio. No browser, no interaction.

### HTTP transport

```json
{
  "mcpServers": {
    "headless-mcp": {
      "url": "http://localhost:9797",
      "headers": {
        "Authorization": "Bearer your-hub-token"
      }
    }
  }
}
```

Start the HTTP server first:
```bash
headless-mcp serve --http --port 9797
```

## Daemon vs Non-Daemon

| | Daemon (default) | Non-daemon (`--no-daemon`) |
|---|---|---|
| Token source | Persisted file only | File + interactive OAuth2 |
| Opens browser | Never | If no valid token |
| Use case | `serve`, `tools`, cron | `call`, re-auth, debugging |
| Safe for automation | ✅ Yes | ❌ No (blocking browser) |

## Configuration

### Headless MCP Config (`headless-mcp.toml`)

```toml
# Optional: protect the hub itself with a bearer token
[auth]
hub_token = "{{env:HEADLESS_MCP_TOKEN}}"
rate_limit = 120     # requests/minute per IP

# Backend: Slack MCP
[backends.slack]
transport = "http"
url = "https://mcp.slack.com/mcp"
namespace = "slack"          # tools prefixed as slack.*

[backends.slack.oauth2]
grant_type = "authorization_code"
client_id = "1601185624273.8899143856786"
callback_port = 3118

# Backend: Atlassian MCP (Jira + Confluence)
[backends.atlassian]
transport = "http"
url = "https://mcp.atlassian.com/v1/mcp"
namespace = "jira"           # tools prefixed as jira.*

[backends.atlassian.oauth2]
grant_type = "authorization_code"
callback_port = 9798
# No client_id — auto-registered via dynamic client registration

# Backend: any stdio MCP server
[backends.my-server]
transport = "stdio"
command = "npx"
namespace = "my"
[backends.my-server.args]
args = ["-y", "@my/mcp-server"]

# Backend: HTTP with static bearer token
[backends.notion]
transport = "http"
url = "https://mcp.notion.com/mcp"
namespace = "notion"
bearer_token = "{{env:NOTION_TOKEN}}"
```

### Transport types

| Type | Config | Auth |
|------|--------|------|
| `http` | `url` + optional `oauth2` | OAuth2 auto-discovery, or `bearer_token` |
| `stdio` | `command` + optional `args` | None (child process) |

### Secret interpolation

Use `{{env:VAR}}` for environment variables or `{{secret:NAME}}` for the secret store:

```toml
bearer_token = "{{env:SLACK_BOT_TOKEN}}"
```

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `HEADLESS_MCP_MASTER_KEY` | For persistence | 32-byte hex key to encrypt `secrets.json` |
| `HEADLESS_MCP_TOKEN` | For HTTP transport | Bearer token to protect the hub API |
| `HEADLESS_MCP_DATA_DIR` | No | Where to store `secrets.json` (default: `.`) |

## Adding a New MCP Provider

See [docs/mcp/](docs/mcp/) for provider-specific guides:

- [Slack](docs/mcp/slack.md) — 19 tools, OAuth2 with public client
- [Atlassian](docs/mcp/atlassian.md) — 31 tools, OAuth2 + dynamic registration + SSE

### Pattern for new providers

1. **Test discovery**:
   ```bash
   curl -s -X POST "https://mcp.provider.com/mcp" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
     -D - | head -20
   ```

2. **Check 401 response for WWW-Authenticate header** with `resource_metadata` URL

3. **If no WWW-Authenticate, try** `.well-known/oauth-authorization-server`

4. **Configure** in `headless-mcp.toml`

5. **Authenticate**: `headless-mcp auth <namespace>`

6. **Verify**: `headless-mcp tools`
