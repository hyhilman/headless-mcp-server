# Notion MCP

## Provider Details
- **URL**: `https://mcp.notion.com/mcp`
- **Auth**: OAuth2 authorization_code with PKCE + Dynamic Client Registration (RFC 7591)
- **Discovery**: Full RFC 9728 chain (`resource_metadata` in 401 `WWW-Authenticate` header)
- **Resource**: `Notion MCP (Beta)`

## Configuration
```toml
[backends.notion]
transport = "http"
url = "https://mcp.notion.com/mcp"
namespace = "notion"
connection_mode = "eager"

[backends.notion.oauth2]
grant_type = "authorization_code"
callback_port = 9799
# No client_id — auto-registered via RFC 7591
```

## Setup
```bash
export HEADLESS_MCP_MASTER_KEY=$(openssl rand -hex 32)
headless-mcp auth notion
# Browser opens → Click Allow → ✅ 27 tools
```

## Auto-Discovery Chain
1. **401** from `POST /mcp` → `WWW-Authenticate: Bearer resource_metadata="https://mcp.notion.com/.well-known/oauth-protected-resource/mcp"`
2. **Resource Metadata** (RFC 9728): `authorization_servers: ["https://mcp.notion.com"]`
3. **Auth Server Metadata** (RFC 8414): `https://mcp.notion.com/.well-known/oauth-authorization-server`
   - `token_endpoint`: `https://mcp.notion.com/token`
   - `registration_endpoint`: `https://mcp.notion.com/register`
   - `grant_types`: `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:jwt-bearer`
   - `scopes_supported`: `["default"]`
4. **Dynamic Registration**: POST to `/register` → `client_id`
5. **PKCE S256**: browser authorization with `scope=default`
6. **Token Exchange**: POST to `/token` → access_token + refresh_token
7. **Initialize**: Standard JSON-RPC (no SSE, no sessions)

## Tools (27)

| Tool | Description |
|------|-------------|
| `notion.notion-search` | Search Notion |
| `notion.notion-fetch` | Fetch Notion content |
| `notion.notion-create-pages` | Create pages |
| `notion.notion-update-page` | Update a page |
| `notion.notion-move-pages` | Move pages |
| `notion.notion-duplicate-page` | Duplicate a page |
| `notion.notion-create-database` | Create a database |
| `notion.notion-create-folder` | Create a folder |
| `notion.notion-create-comment` | Create a comment |
| `notion.notion-get-comments` | Get comments |
| `notion.notion-create-attachment` | Create an attachment |
| `notion.notion-create-file-upload` | Create a file upload |
| `notion.notion-download-attachment` | Download an attachment |
| `notion.notion-update-data-source` | Update a data source |
| `notion.notion-query-data-sources` | Query data sources |
| `notion.notion-query-database-view` | Query a database view |
| `notion.notion-query-meeting-notes` | Query meeting notes |
| `notion.notion-get-teams` | Get teams |
| `notion.notion-get-users` | Get users |
| `notion.notion-get-async-task` | Get async task result |
| `notion.notion-list-private-pages` | List private pages |
| `notion.notion-list-shared-pages` | List shared pages |
| `notion.notion-list-favorite-pages` | List favorite pages |
| `notion.notion-list-recent-pages` | List recent pages |
| `notion.notion-search-agents` | Search AI agents |
| `notion.notion-create-view` | Create a view |
| `notion.notion-update-view` | Update a view |

## Notes
- **No client_id needed** — dynamic registration via RFC 7591
- **No SSE or session headers** — standard JSON-RPC over HTTP
- **Full RFC 9728 chain**: `resource_metadata` in 401 → auth server → token
- **Single scope**: `default` (auto-populated from discovery)
