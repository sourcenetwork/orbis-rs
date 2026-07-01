use crate::reporting::v0::error::{ReportingError, Result};
use crate::reporting::v0::registry::ReportRegistry;
use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

const MAX_IN_FLIGHT_REPORTS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InFlightReportKey {
    pub report_type: &'static str,
    pub ring_id: String,
    pub subject_key: String,
}

pub struct ReportingState {
    pub registry: Arc<ReportRegistry>,
    in_flight: Mutex<HashSet<InFlightReportKey>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

// Removes the key and decrements the metric when dropped, whether the task
// completes normally, panics, or is cancelled.
struct InFlightGuard {
    state: Arc<ReportingState>,
    key: InFlightReportKey,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.state
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
        crate::metrics::REPORT_IN_FLIGHT.dec();
    }
}

impl ReportingState {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(ReportRegistry::with_defaults()),
            in_flight: Mutex::new(HashSet::new()),
            tasks: Mutex::new(Vec::new()),
        }
    }

    pub async fn spawn<F>(self: &Arc<Self>, key: InFlightReportKey, future: F) -> Result<bool>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        {
            let mut in_flight = self.in_flight.lock().unwrap();
            if in_flight.contains(&key) {
                return Ok(false);
            }
            if in_flight.len() >= MAX_IN_FLIGHT_REPORTS {
                return Err(ReportingError::CapacityReached);
            }
            in_flight.insert(key.clone());
            crate::metrics::REPORT_IN_FLIGHT.inc();
        }

        let state = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let _guard = InFlightGuard { state, key };
            future.await;
        });

        let mut tasks = self.tasks.lock().unwrap();
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
        Ok(true)
    }

    #[cfg(test)]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.lock().unwrap().len()
    }

    pub async fn shutdown(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            let _ = task.await;
        }
    }
}

impl Default for ReportingState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::v0::types::NODE_OFFLINE_REPORT_TYPE;
    use std::time::Duration;

    fn key() -> InFlightReportKey {
        InFlightReportKey {
            report_type: NODE_OFFLINE_REPORT_TYPE,
            ring_id: "ring".to_string(),
            subject_key: "accused".to_string(),
        }
    }

    #[tokio::test]
    async fn concurrent_duplicate_is_rejected_and_cleanup_runs() {
        let state = Arc::new(ReportingState::new());
        let (tx, rx) = tokio::sync::oneshot::channel();
        assert!(state
            .spawn(key(), async move {
                let _ = rx.await;
            })
            .await
            .unwrap());
        assert!(!state.spawn(key(), async {}).await.unwrap());
        assert_eq!(state.in_flight_count(), 1);
        let _ = tx.send(());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(state.in_flight_count(), 0);
        assert!(state.spawn(key(), async {}).await.unwrap());
        state.shutdown().await;
    }
}
