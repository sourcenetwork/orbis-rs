use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use super::patterns::NamedPattern;

/// Events emitted by parsing node log output.
#[derive(Clone, Debug)]
pub enum LogEvent {
    /// Node-specific ready signal (e.g. "Server is ready").
    Ready,
    /// An error line was detected.
    Error(String),
    /// A named pattern matched.
    Pattern { name: String, line: String },
}

type SeenPatterns = Arc<Mutex<HashMap<String, String>>>;

/// Tails a node's stdout.log and emits structured events.
///
/// Spawns a background tokio task that continuously reads the log file
/// (tail -f behavior). Matched patterns are stored for later retrieval.
pub struct LogTracker {
    tx: broadcast::Sender<LogEvent>,
    seen: SeenPatterns,
    task: JoinHandle<()>,
}

impl LogTracker {
    /// Start tailing `log_path`, matching named patterns.
    pub fn start(log_path: PathBuf, named_patterns: Vec<NamedPattern>) -> Self {
        let (tx, _) = broadcast::channel(64);
        let tx_clone = tx.clone();
        let seen: SeenPatterns = Arc::new(Mutex::new(HashMap::new()));
        let seen_clone = seen.clone();

        let task = tokio::spawn(async move {
            if let Err(e) = tail_loop(log_path, tx_clone, named_patterns, seen_clone).await {
                tracing::warn!("log tracker stopped: {}", e);
            }
        });

        Self { tx, seen, task }
    }

    /// Subscribe to log events.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEvent> {
        self.tx.subscribe()
    }

    /// Wait for a named pattern to match, returning the matched line.
    ///
    /// If the pattern was already matched before this call, returns immediately.
    pub async fn wait_for_pattern(&self, name: &str, timeout: Duration) -> eyre::Result<String> {
        // Check if already seen
        if let Some(line) = self.seen.lock().unwrap().get(name) {
            return Ok(line.clone());
        }

        let mut rx = self.tx.subscribe();
        let name_owned = name.to_string();
        let seen = self.seen.clone();

        let result = tokio::time::timeout(timeout, async move {
            loop {
                // Re-check seen map in case of race
                if let Some(line) = seen.lock().unwrap().get(&name_owned) {
                    return Ok(line.clone());
                }

                match rx.recv().await {
                    Ok(LogEvent::Pattern {
                        name: ref n,
                        ref line,
                    }) if *n == name_owned => {
                        return Ok(line.clone());
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if let Some(line) = seen.lock().unwrap().get(&name_owned) {
                            return Ok(line.clone());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(eyre::eyre!("log tracker closed"));
                    }
                }
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(eyre::eyre!("timed out waiting for pattern '{}'", name)),
        }
    }

    /// Get all matched patterns so far.
    pub fn seen_patterns(&self) -> HashMap<String, String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for LogTracker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn tail_loop(
    log_path: PathBuf,
    tx: broadcast::Sender<LogEvent>,
    named_patterns: Vec<NamedPattern>,
    seen: SeenPatterns,
) -> eyre::Result<()> {
    // Wait for the log file to appear
    loop {
        if log_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let file = tokio::fs::File::open(&log_path).await?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF — sleep and retry (tail -f behavior)
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(_) => {
                if line.contains("ERROR") {
                    let _ = tx.send(LogEvent::Error(line.trim().to_string()));
                }
                for pattern in &named_patterns {
                    if pattern.regex.is_match(&line) {
                        let trimmed = line.trim().to_string();
                        seen.lock()
                            .unwrap()
                            .entry(pattern.name.to_string())
                            .or_insert_with(|| trimmed.clone());
                        let _ = tx.send(LogEvent::Pattern {
                            name: pattern.name.to_string(),
                            line: trimmed,
                        });
                    }
                }
            }
            Err(e) => {
                return Err(eyre::eyre!("error reading log: {}", e));
            }
        }
    }
}
