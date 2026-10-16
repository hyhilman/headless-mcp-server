# Login, VPN and events plan

Goal: backends behind SSO (NetBird VPN, AWS SSO, OAuth providers) keep
working unattended, and when a login expires the right person gets the link
without the agent being able to change what the hub runs.

| # | What | Status |
|---|---|---|
| 1 | `[vpn.<name>]`: fixed health / expiry / login commands, `requires_vpn` | Done (PR #4) |
| 2 | Actionable "VPN_REQUIRED" tool errors, `hub.vpn_status`, `hub.vpn_login` | Done (PR #4) |
| 3 | `pin_args` / `deny_args`: agents can't pick profile, account, region | Done |
| 4 | Paste-back for logins that redirect to `localhost` | Done |
| 5 | `[[notify]]` alerts (webhook / Slack / ntfy), optional `auto_login` | Done |
| 6 | MCP 2026-07-28 alongside older versions (`server/discover`, per-request `_meta`) | Done |
| 7 | Login state as resources (`hub://vpn/<name>`), `subscriptions/listen` | Done |
| 8 | Login prompt via URL elicitation (multi round-trip), link shown to the user directly | Done |
| 9 | MCP Events (`events/list`, `events/subscribe`, signed webhooks) | Done |
| 10 | AWS SSO via the same fixed-command mechanism | Documented (no code needed) |
| 11 | Tasks extension, MCP Apps login card | Later: no major client supports Tasks yet |

## Decisions

- **Commands come from the config only.** Agents pick a VPN by name; the only
  other agent-supplied value is the paste-back callback address, which must
  be `http://localhost:<allowed port>/...` while a login is pending.
- **Tools behind a down VPN stay listed.** Hiding them would stop the agent
  from triggering the login prompt; calls return the prompt or a clear error.
- **The login link goes straight to the provider** (NetBird device page).
  A hub-hosted `/connect/<id>` page is a possible later step.
- **`requestState` is HMAC-signed** with a per-process key and expires.
- **Event callbacks** must be HTTPS to public addresses (resolved and pinned),
  with Standard Webhooks signatures.
