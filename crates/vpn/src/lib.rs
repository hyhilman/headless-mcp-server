#![forbid(unsafe_code)]

//! VPN session manager.
//!
//! Each VPN is described by a [`VpnDef`] with three fixed commands taken
//! from the config file: `health`, `expiry` (optional) and `login`. The
//! hub never builds a command from caller input — callers can only pick a
//! VPN by name, so an agent has no way to change what gets executed.
//!
//! `login` is expected to print an SSO link (device-code or browser flow)
//! and then block until the user finishes signing in. [`VpnManager::start_login`]
//! returns as soon as the link appears; the process keeps running in the
//! background, and when it exits the VPN is re-checked.

use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, mpsc};
use tokio::time::MissedTickBehavior;

/// Max lines of login output kept for the message shown to the user.
const LOGIN_OUTPUT_LINES: usize = 10;
/// Max characters kept per output line.
const MAX_LINE_CHARS: usize = 300;

/// One VPN, as configured. All commands are argv vectors (no shell).
#[derive(Debug, Clone)]
pub struct VpnDef {
    pub name: String,
    /// Health check command. Exit 0 (plus `healthy_if`, if set) = connected.
    pub health: Vec<String>,
    /// Output substrings meaning "connected". Empty = exit code 0 is enough.
    pub healthy_if: Vec<String>,
    /// Output substrings meaning "login required". Checked first.
    pub needs_login_if: Vec<String>,
    /// Optional command whose first output line is reported as `expires_at`.
    pub expiry: Option<Vec<String>>,
    /// Login command. Must print the SSO link, then wait for the user.
    pub login: Vec<String>,
    /// Prefixes that mark the login link in the login output.
    pub url_prefixes: Vec<String>,
    pub check_interval_secs: u64,
    pub command_timeout_secs: u64,
    /// How long to wait for the login link to appear.
    pub url_wait_secs: u64,
    /// How long the login process may wait for the user before it is killed.
    pub login_timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnState {
    /// Not checked yet.
    Unknown,
    Connected,
    NeedsLogin,
    /// Health check failed for another reason.
    Down,
}

impl std::fmt::Display for VpnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            VpnState::Unknown => "unknown",
            VpnState::Connected => "connected",
            VpnState::NeedsLogin => "needs_login",
            VpnState::Down => "down",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VpnStatus {
    pub name: String,
    pub state: VpnState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<PendingLogin>,
}

/// A login that is waiting for the user to finish SSO.
#[derive(Debug, Clone, Serialize)]
pub struct PendingLogin {
    pub url: String,
    /// Last lines of the login output (may contain a device code).
    pub message: String,
    pub started_at_unix: u64,
    pub timeout_at_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum LoginOutcome {
    AlreadyConnected { status: VpnStatus },
    Pending { login: PendingLogin },
}

#[derive(Debug, Clone)]
pub enum VpnEvent {
    StateChanged {
        name: String,
        from: VpnState,
        to: VpnState,
    },
}

#[derive(Debug, Clone)]
pub struct VpnError(pub String);

impl std::fmt::Display for VpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VpnError {}

struct Entry {
    def: VpnDef,
    status: Mutex<VpnStatus>,
    /// Serializes login starts so only one login process runs per VPN.
    login_lock: tokio::sync::Mutex<()>,
}

pub struct VpnManager {
    entries: HashMap<String, Arc<Entry>>,
    events: broadcast::Sender<VpnEvent>,
}

impl VpnManager {
    pub fn new(defs: Vec<VpnDef>) -> Arc<Self> {
        let entries = defs
            .into_iter()
            .map(|def| {
                let status = VpnStatus {
                    name: def.name.clone(),
                    state: VpnState::Unknown,
                    detail: None,
                    expires_at: None,
                    checked_at_unix: None,
                    login: None,
                };
                let entry = Entry {
                    def,
                    status: Mutex::new(status),
                    login_lock: tokio::sync::Mutex::new(()),
                };
                (entry.def.name.clone(), Arc::new(entry))
            })
            .collect();
        let (events, _) = broadcast::channel(16);
        Arc::new(Self { entries, events })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Configured VPN names, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        names
    }

    /// Last known status (no command is run).
    pub fn status(&self, name: &str) -> Option<VpnStatus> {
        self.entries
            .get(name)
            .map(|e| e.status.lock().unwrap().clone())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<VpnEvent> {
        self.events.subscribe()
    }

    /// Run the health (and expiry) commands now and update the status.
    pub async fn refresh(&self, name: &str) -> Result<VpnStatus, VpnError> {
        let entry = self.entry(name)?;
        let def = &entry.def;
        let timeout = Duration::from_secs(def.command_timeout_secs);

        let (state, detail) = match run_capture(&def.health, timeout).await {
            Ok((success, output)) => classify(def, success, &output),
            Err(e) => (VpnState::Down, Some(e.0)),
        };

        let expires_at = match &def.expiry {
            Some(cmd) => match run_capture(cmd, timeout).await {
                Ok((true, output)) => output
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .map(|l| truncate(l, 200)),
                _ => None,
            },
            None => None,
        };

        let (from, status) = {
            let mut status = entry.status.lock().unwrap();
            let from = status.state;
            status.state = state;
            status.detail = detail;
            status.expires_at = expires_at;
            status.checked_at_unix = Some(now_unix());
            (from, status.clone())
        };

        if from != state {
            tracing::info!(vpn = %name, %from, to = %state, "VPN state changed");
            let _ = self.events.send(VpnEvent::StateChanged {
                name: name.to_string(),
                from,
                to: state,
            });
        }
        Ok(status)
    }

    /// Re-check every VPN on its `check_interval_secs`, starting now.
    pub fn start_watchers(self: &Arc<Self>) {
        for (name, entry) in &self.entries {
            let manager = Arc::clone(self);
            let name = name.clone();
            let period = Duration::from_secs(entry.def.check_interval_secs.max(5));
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(period);
                interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    if let Err(e) = manager.refresh(&name).await {
                        tracing::warn!(vpn = %name, %e, "VPN check failed");
                    }
                }
            });
        }
    }

    /// Start the login command and return its SSO link.
    ///
    /// If a login is already waiting for the user, its link is returned
    /// instead of starting a second process. If the VPN is already
    /// connected, nothing is run.
    pub async fn start_login(self: &Arc<Self>, name: &str) -> Result<LoginOutcome, VpnError> {
        let entry = self.entry(name)?;
        let _guard = entry.login_lock.lock().await;

        if let Some(login) = entry.status.lock().unwrap().login.clone() {
            if login.timeout_at_unix > now_unix() {
                return Ok(LoginOutcome::Pending { login });
            }
        }

        let status = self.refresh(name).await?;
        if status.state == VpnState::Connected {
            return Ok(LoginOutcome::AlreadyConnected { status });
        }

        let def = &entry.def;
        let mut child = spawn_piped(&def.login)?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        forward_lines(child.stdout.take(), tx.clone());
        forward_lines(child.stderr.take(), tx);

        let mut tail: Vec<String> = Vec::new();
        let url_wait = tokio::time::sleep(Duration::from_secs(def.url_wait_secs));
        tokio::pin!(url_wait);

        let url = loop {
            tokio::select! {
                line = rx.recv() => match line {
                    Some(line) => {
                        push_tail(&mut tail, &line);
                        if let Some(url) = extract_url(&line, &def.url_prefixes) {
                            break url;
                        }
                    }
                    None => {
                        // Output closed before any link: the command finished.
                        let _ = child.wait().await;
                        let status = self.refresh(name).await?;
                        if status.state == VpnState::Connected {
                            return Ok(LoginOutcome::AlreadyConnected { status });
                        }
                        return Err(VpnError(format!(
                            "login command for '{name}' exited without printing a login link. Output:\n{}",
                            tail.join("\n")
                        )));
                    }
                },
                _ = &mut url_wait => {
                    let _ = child.kill().await;
                    return Err(VpnError(format!(
                        "no login link from '{name}' within {}s. Output:\n{}",
                        def.url_wait_secs,
                        tail.join("\n")
                    )));
                }
            }
        };

        // Keep a few more lines that arrive right after the link (device codes
        // are often printed on the next line).
        while let Ok(Some(line)) =
            tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
        {
            push_tail(&mut tail, &line);
        }

        let started = now_unix();
        let login = PendingLogin {
            url,
            message: tail.join("\n"),
            started_at_unix: started,
            timeout_at_unix: started + def.login_timeout_secs,
        };
        entry.status.lock().unwrap().login = Some(login.clone());
        tracing::info!(vpn = %name, url = %login.url, "VPN login link issued; waiting for user");

        let manager = Arc::clone(self);
        let name = name.to_string();
        let login_timeout = Duration::from_secs(def.login_timeout_secs);
        tokio::spawn(async move {
            let finished = tokio::time::timeout(login_timeout, async {
                while rx.recv().await.is_some() {}
                child.wait().await
            })
            .await;
            match finished {
                Ok(Ok(exit)) => tracing::info!(vpn = %name, %exit, "VPN login command finished"),
                Ok(Err(e)) => tracing::warn!(vpn = %name, %e, "VPN login command failed"),
                Err(_) => {
                    tracing::warn!(vpn = %name, "VPN login timed out; stopping login command");
                    let _ = child.kill().await;
                }
            }
            if let Ok(entry) = manager.entry(&name) {
                entry.status.lock().unwrap().login = None;
            }
            if let Err(e) = manager.refresh(&name).await {
                tracing::warn!(vpn = %name, %e, "VPN check after login failed");
            }
        });

        Ok(LoginOutcome::Pending { login })
    }

    fn entry(&self, name: &str) -> Result<Arc<Entry>, VpnError> {
        self.entries
            .get(name)
            .cloned()
            .ok_or_else(|| VpnError(format!("unknown VPN '{name}'")))
    }
}

fn classify(def: &VpnDef, success: bool, output: &str) -> (VpnState, Option<String>) {
    let last_line = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .last()
        .map(|l| truncate(l, MAX_LINE_CHARS));

    if let Some(hit) = def.needs_login_if.iter().find(|p| output.contains(p.as_str())) {
        return (VpnState::NeedsLogin, Some(format!("output contains '{hit}'")));
    }
    let healthy = success
        && (def.healthy_if.is_empty() || def.healthy_if.iter().any(|p| output.contains(p.as_str())));
    if healthy {
        (VpnState::Connected, None)
    } else {
        (VpnState::Down, last_line)
    }
}

/// First token starting with one of `prefixes`, with trailing punctuation removed.
fn extract_url(line: &str, prefixes: &[String]) -> Option<String> {
    let start = prefixes.iter().filter_map(|p| line.find(p.as_str())).min()?;
    let rest = &line[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>')
        .unwrap_or(rest.len());
    let url = rest[..end].trim_end_matches(['.', ',', ')', ']', ';']);
    (!url.is_empty()).then(|| url.to_string())
}

fn spawn_piped(argv: &[String]) -> Result<tokio::process::Child, VpnError> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| VpnError("empty command".into()))?;
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| VpnError(format!("failed to run '{program}': {e}")))
}

/// Run a command to completion; returns (exit success, stdout + stderr).
async fn run_capture(argv: &[String], timeout: Duration) -> Result<(bool, String), VpnError> {
    let child = spawn_piped(argv)?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| VpnError(format!("'{}' timed out after {}s", argv[0], timeout.as_secs())))?
        .map_err(|e| VpnError(format!("'{}' failed: {e}", argv[0])))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), text))
}

fn forward_lines<R>(reader: Option<R>, tx: mpsc::UnboundedSender<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let Some(reader) = reader else { return };
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

fn push_tail(tail: &mut Vec<String>, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    tail.push(truncate(line, MAX_LINE_CHARS));
    if tail.len() > LOGIN_OUTPUT_LINES {
        tail.remove(0);
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script.into()]
    }

    fn def(health: &str, login: &str) -> VpnDef {
        VpnDef {
            name: "netbird".into(),
            health: sh(health),
            healthy_if: vec!["Management: Connected".into()],
            needs_login_if: vec!["NeedsLogin".into()],
            expiry: None,
            login: sh(login),
            url_prefixes: vec!["https://".into()],
            check_interval_secs: 60,
            command_timeout_secs: 5,
            url_wait_secs: 5,
            login_timeout_secs: 5,
        }
    }

    #[test]
    fn extract_url_strips_trailing_punctuation() {
        let prefixes = vec!["https://".to_string()];
        assert_eq!(
            extract_url("use this URL to log in: https://idp.example/device?code=AB-CD.", &prefixes),
            Some("https://idp.example/device?code=AB-CD".into())
        );
        assert_eq!(extract_url("no link here", &prefixes), None);
    }

    #[tokio::test]
    async fn refresh_classifies_states() {
        let m = VpnManager::new(vec![def("echo 'Management: Connected'", "true")]);
        assert_eq!(m.refresh("netbird").await.unwrap().state, VpnState::Connected);

        let m = VpnManager::new(vec![def("echo 'Daemon status: NeedsLogin'; exit 1", "true")]);
        assert_eq!(m.refresh("netbird").await.unwrap().state, VpnState::NeedsLogin);

        let m = VpnManager::new(vec![def("echo 'Management: Disconnected'", "true")]);
        assert_eq!(m.refresh("netbird").await.unwrap().state, VpnState::Down);
    }

    #[tokio::test]
    async fn login_returns_link_then_reconnects_in_background() {
        let dir = std::env::temp_dir().join(format!("hmcp-vpn-{}", now_unix_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let flag = dir.join("logged-in");
        let flag = flag.display();

        let m = VpnManager::new(vec![def(
            &format!("test -f {flag} && echo 'Management: Connected' || echo NeedsLogin"),
            &format!("echo 'Please log in: https://idp.example/device'; echo 'Code: ABCD-1234'; sleep 1; touch {flag}"),
        )]);
        let mut events = m.subscribe();

        let LoginOutcome::Pending { login } = m.start_login("netbird").await.unwrap() else {
            panic!("expected pending login");
        };
        assert_eq!(login.url, "https://idp.example/device");
        assert!(login.message.contains("ABCD-1234"));

        // A second call reuses the pending login instead of spawning again.
        let LoginOutcome::Pending { login: again } = m.start_login("netbird").await.unwrap() else {
            panic!("expected pending login");
        };
        assert_eq!(again.url, login.url);

        let event = loop {
            let VpnEvent::StateChanged { to, .. } =
                tokio::time::timeout(Duration::from_secs(5), events.recv()).await.unwrap().unwrap();
            if to == VpnState::Connected {
                break to;
            }
        };
        assert_eq!(event, VpnState::Connected);
        assert!(m.status("netbird").unwrap().login.is_none());
    }

    #[tokio::test]
    async fn login_skipped_when_already_connected() {
        let m = VpnManager::new(vec![def("echo 'Management: Connected'", "exit 1")]);
        assert!(matches!(
            m.start_login("netbird").await.unwrap(),
            LoginOutcome::AlreadyConnected { .. }
        ));
    }

    #[tokio::test]
    async fn unknown_vpn_is_rejected() {
        let m = VpnManager::new(vec![def("true", "true")]);
        assert!(m.start_login("other").await.is_err());
    }

    fn now_unix_nanos() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }
}
