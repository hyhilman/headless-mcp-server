//! `[[notify]]` alerts for VPN state changes (generic webhook, Slack, ntfy).
//!
//! Alerts go only to destinations in the config file, so this is the safe
//! place to send a login link: with `auto_login = true` on a VPN, the hub
//! starts the login as soon as it notices the expiry and includes the link.

use std::sync::Arc;
use std::time::Duration;

use headless_mcp_vpn::{LoginOutcome, VpnEvent, VpnManager, VpnState};
use serde::Deserialize;

const ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyKind {
    Webhook,
    Slack,
    Ntfy,
}

#[derive(Debug, Clone)]
pub struct NotifyTarget {
    pub kind: NotifyKind,
    pub url: String,
    /// States that trigger this alert (`needs_login`, `down`, `connected`).
    pub on: Vec<String>,
}

/// One alert, rendered per destination.
#[derive(Debug, Clone)]
pub struct Alert {
    pub vpn: String,
    pub from: VpnState,
    pub to: VpnState,
    pub login_url: Option<String>,
    pub login_message: Option<String>,
}

impl Alert {
    pub fn text(&self) -> String {
        let mut text = match self.to {
            VpnState::NeedsLogin => format!("VPN '{}' needs login.", self.vpn),
            VpnState::Down => format!("VPN '{}' is down.", self.vpn),
            VpnState::Connected => format!("VPN '{}' is connected again.", self.vpn),
            VpnState::Unknown => format!("VPN '{}' state is unknown.", self.vpn),
        };
        match (&self.login_url, self.to) {
            (Some(url), _) => {
                text.push_str(&format!("\nSign in: {url}"));
                if let Some(msg) = &self.login_message {
                    text.push_str(&format!("\n\n{msg}"));
                }
            }
            (None, VpnState::NeedsLogin) => text.push_str(&format!(
                "\nRun 'headless-mcp vpn login {}' or ask an agent to call hub.vpn_login.",
                self.vpn
            )),
            _ => {}
        }
        text
    }
}

/// Watch VPN events: auto-start logins where configured, and send alerts.
pub fn spawn_notifier(vpn: Arc<VpnManager>, targets: Vec<NotifyTarget>, auto_login: Vec<String>) {
    if vpn.is_empty() || (targets.is_empty() && auto_login.is_empty()) {
        return;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");
    let mut events = vpn.subscribe();
    tokio::spawn(async move {
        loop {
            let VpnEvent::StateChanged { name, from, to } = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            // Startup check of a healthy VPN is not news.
            if from == VpnState::Unknown && to == VpnState::Connected {
                continue;
            }
            let mut alert = Alert { vpn: name.clone(), from, to, login_url: None, login_message: None };
            if to == VpnState::NeedsLogin && auto_login.contains(&name) {
                match vpn.start_login(&name).await {
                    Ok(LoginOutcome::Pending { login }) => {
                        alert.login_url = Some(login.url);
                        alert.login_message = Some(login.message);
                    }
                    Ok(LoginOutcome::AlreadyConnected { .. }) => continue,
                    Err(e) => tracing::warn!(vpn = %name, %e, "auto login failed"),
                }
            }
            for target in targets.iter().filter(|t| t.on.iter().any(|s| s == &to.to_string())) {
                send(&client, target, &alert).await;
            }
        }
    });
}

async fn send(client: &reqwest::Client, target: &NotifyTarget, alert: &Alert) {
    for attempt in 1..=ATTEMPTS {
        match build(client, target, alert).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(vpn = %alert.vpn, kind = ?target.kind, "alert sent");
                return;
            }
            Ok(resp) => tracing::warn!(vpn = %alert.vpn, status = %resp.status(), attempt, "alert rejected"),
            Err(e) => tracing::warn!(vpn = %alert.vpn, error = %e.without_url(), attempt, "alert failed"),
        }
        tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
    }
}

fn build(client: &reqwest::Client, target: &NotifyTarget, alert: &Alert) -> reqwest::RequestBuilder {
    let text = alert.text();
    match target.kind {
        NotifyKind::Webhook => client.post(&target.url).json(&serde_json::json!({
            "vpn": alert.vpn,
            "from": alert.from,
            "to": alert.to,
            "login_url": alert.login_url,
            "message": text,
        })),
        NotifyKind::Slack => client.post(&target.url).json(&serde_json::json!({ "text": text })),
        NotifyKind::Ntfy => {
            let mut req = client
                .post(&target.url)
                .header("Title", format!("headless-mcp: {} {}", alert.vpn, alert.to))
                .header(
                    "Tags",
                    if alert.to == VpnState::Connected { "white_check_mark" } else { "warning" },
                )
                .body(text);
            if let Some(url) = &alert.login_url {
                req = req.header("Click", url);
            }
            req
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn alert(url: Option<&str>) -> Alert {
        Alert {
            vpn: "netbird".into(),
            from: VpnState::Connected,
            to: VpnState::NeedsLogin,
            login_url: url.map(String::from),
            login_message: url.map(|u| format!("use this URL to log in: {u}\nCode: ABCD")),
        }
    }

    #[test]
    fn text_includes_link_or_instructions() {
        assert!(alert(None).text().contains("headless-mcp vpn login netbird"));
        let with_link = alert(Some("https://idp.example/device")).text();
        assert!(with_link.contains("Sign in: https://idp.example/device"));
        assert!(with_link.contains("Code: ABCD"));
    }

    #[tokio::test]
    async fn webhook_posts_json() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let target = NotifyTarget {
            kind: NotifyKind::Webhook,
            url: format!("http://{addr}/hook"),
            on: vec!["needs_login".into()],
        };
        let client = reqwest::Client::new();
        send(&client, &target, &alert(Some("https://idp.example/device"))).await;
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /hook"));
        assert!(request.contains("\"to\":\"needs_login\""));
        assert!(request.contains("\"login_url\":\"https://idp.example/device\""));
    }
}
