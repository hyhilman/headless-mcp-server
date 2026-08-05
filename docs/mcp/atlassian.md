# Atlassian MCP (Jira + Confluence)

## Provider Details
- **URL**: `https://mcp.atlassian.com/v1/mcp`
- **Auth**: OAuth2 authorization_code with PKCE + Dynamic Client Registration (RFC 7591)
- **Transport**: SSE (Server-Sent Events) over HTTP POST
- **Sessions**: Yes — `Mcp-Session-Id` header required for requests after initialize

## Configuration
```toml
[backends.atlassian]
transport = "http"
url = "https://mcp.atlassian.com/v1/mcp"
namespace = "jira"
connection_mode = "eager"

[backends.atlassian.oauth2]
grant_type = "authorization_code"
callback_port = 9798
# No client_id — auto-registered via RFC 7591
```

## Setup
```bash
export HEADLESS_MCP_MASTER_KEY=$(openssl rand -hex 32)
headless-mcp auth atlassian
# Browser opens → Click Allow → ✅ 31 tools
```

## Auto-Discovery Chain
1. **401** from `POST /v1/mcp` → no `WWW-Authenticate` header
2. **Fallback**: `.well-known/oauth-authorization-server` at `mcp.atlassian.com`
3. **Discovery response** includes:
   - `authorization_endpoint`: `https://mcp.atlassian.com/v1/authorize`
   - `token_endpoint`: `https://cf.mcp.atlassian.com/v1/token`
   - `registration_endpoint`: `https://cf.mcp.atlassian.com/v1/register`
   - `token_endpoint_auth_methods_supported`: `["client_secret_basic", "client_secret_post", "none"]`
4. **Dynamic Registration**: POST to `/v1/register` → `client_id` + `client_secret`
5. **PKCE S256**: code_challenge generated, browser opened
6. **Callback**: `localhost:9798` captures authorization code
7. **Token Exchange**: POST to `/v1/token` → access_token + refresh_token
8. **Initialize**: POST to `/v1/mcp` with Bearer token → SSE response with `Mcp-Session-Id`
9. **Session**: All subsequent requests include `Mcp-Session-Id` header

## Tools (31)

### Jira
| Tool | Description |
|------|-------------|
| `jira.atlassianUserInfo` | Get current user info |
| `jira.getJiraIssue` | Get issue details |
| `jira.createJiraIssue` | Create a Jira issue |
| `jira.editJiraIssue` | Update an issue |
| `jira.addCommentToJiraIssue` | Add/update a comment |
| `jira.addWorklogToJiraIssue` | Add/update a worklog |
| `jira.searchJiraIssuesUsingJql` | Search issues with JQL |
| `jira.getVisibleJiraProjects` | Get projects |
| `jira.getJiraProjectIssueTypesMetadata` | Get issue types |
| `jira.getJiraIssueTypeMetaWithFields` | Get field metadata |
| `jira.getTransitionsForJiraIssue` | Get transitions |
| `jira.transitionJiraIssue` | Transition issue status |
| `jira.createIssueLink` | Create issue link |
| `jira.getIssueLinkTypes` | Get link types |
| `jira.getJiraIssueRemoteIssueLinks` | Get remote links |
| `jira.lookupJiraAccountId` | Lookup user IDs |
| `jira.getAccessibleAtlassianResources` | Get cloudId for multi-site |
| `jira.fetch` | Get issue/page by ARI |

### Confluence
| Tool | Description |
|------|-------------|
| `jira.getConfluencePage` | Get page/blog post |
| `jira.createConfluencePage` | Create page/blog post |
| `jira.updateConfluencePage` | Update page/blog post |
| `jira.getConfluenceSpaces` | Get spaces |
| `jira.getPagesInConfluenceSpace` | Get pages in a space |
| `jira.getConfluencePageDescendants` | Get child pages |
| `jira.getConfluencePageFooterComments` | Get footer comments |
| `jira.getConfluencePageInlineComments` | Get inline comments |
| `jira.createConfluenceFooterComment` | Create footer comment |
| `jira.createConfluenceInlineComment` | Create inline comment |
| `jira.getConfluenceCommentChildren` | Get comment replies |

### Search
| Tool | Description |
|------|-------------|
| `jira.search` | Rovo Search (Jira + Confluence) |
| `jira.searchConfluenceUsingCql` | Confluence CQL search |

## Notes
- **No client_id or client_secret needed** — auto-registered per session
- **SSE responses**: Atlassian wraps JSON-RPC in SSE `event: message\ndata: {...}` format
- **Session IDs**: `Mcp-Session-Id` header required after initialize; sent automatically
- **URL-decoding**: Authorization codes may contain `%3A` (colon) — automatically decoded
- **Notifications**: `notifications/initialized` is rejected by Atlassian (non-fatal)
