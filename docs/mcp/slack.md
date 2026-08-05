# Slack MCP

## Provider Details
- **URL**: `https://mcp.slack.com/mcp`
- **Auth**: OAuth2 authorization_code with PKCE
- **Client ID**: `1601185624273.8899143856786` (Claude's public client)
- **No `client_secret` required** — Slack accepts `none` auth for this client

## Configuration
```toml
[backends.slack]
transport = "http"
url = "https://mcp.slack.com/mcp"
namespace = "slack"
connection_mode = "eager"

[backends.slack.oauth2]
grant_type = "authorization_code"
client_id = "1601185624273.8899143856786"
callback_port = 3118
```

## Setup
```bash
export HEADLESS_MCP_MASTER_KEY=$(openssl rand -hex 32)
headless-mcp auth slack
# Browser opens → Click Allow → ✅ 19 tools
```

## Tools (19)
| Tool | Description |
|------|-------------|
| `slack.slack_send_message` | Send a message to a channel or user |
| `slack.slack_read_channel` | Read channel messages (newest first) |
| `slack.slack_read_thread` | Read thread replies |
| `slack.slack_read_user_profile` | Get user profile details |
| `slack.slack_search_public` | Search public channels |
| `slack.slack_search_public_and_private` | Search all channels (requires consent) |
| `slack.slack_search_channels` | Find channels by name |
| `slack.slack_search_users` | Find users by name/email |
| `slack.slack_search_emojis` | Search custom emojis |
| `slack.slack_list_channel_members` | List channel members |
| `slack.slack_add_reaction` | Add emoji reaction |
| `slack.slack_get_reactions` | Get reactions on a message |
| `slack.slack_create_conversation` | Create channel, DM, or group DM |
| `slack.slack_schedule_message` | Schedule a message for later |
| `slack.slack_send_message_draft` | Create a draft message |
| `slack.slack_create_canvas` | Create a Canvas document |
| `slack.slack_update_canvas` | Update a Canvas document |
| `slack.slack_read_canvas` | Read a Canvas document |
| `slack.slack_read_file` | Read file content |

## Notes
- OAuth2 discovery via RFC 9728 resource metadata → RFC 8414 auth server metadata
- Callback on `localhost:3118` (configurable via `callback_port`)
- Scopes auto-populated from discovery metadata
- Token persisted encrypted with `HEADLESS_MCP_MASTER_KEY`
- No `client_secret` needed — this client_id accepts `none` auth method
