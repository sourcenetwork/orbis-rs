use crate::reporting::error::{ReportingError, Result};
use crate::reporting::types::InFlightReportKey;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const MAX_IN_FLIGHT_REPORTS: usize = 128;

pub struct ReportingState {
    in_flight: Mutex<HashSet<InFlightReportKey>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl ReportingState {
    pub fn new() -> Self {
        Self {
            in_flight: Mutex::new(HashSet::new()),
            tasks: Mutex::new(Vec::new()),
        }
    }

    pub async fn spawn<F>(self: &Arc<Self>, key: InFlightReportKey, future: F) -> Result<bool>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        {
            let mut in_flight = self.in_flight.lock().await;
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
            future.await;
            state.in_flight.lock().await.remove(&key);
            crate::metrics::REPORT_IN_FLIGHT.dec();
        });

        let mut tasks = self.tasks.lock().await;
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
        Ok(true)
    }

    #[cfg(test)]
    pub async fn in_flight_count(&self) -> usize {
        self.in_flight.lock().await.len()
    }

    pub async fn shutdown(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().await);
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
    use crate::reporting::types::NODE_OFFLINE_REPORT_TYPE;
    use std::time::Duration;

    fn key() -> InFlightReportKey {
        InFlightReportKey {
            report_type: NODE_OFFLINE_REPORT_TYPE,
            ring_id: "ring".to_string(),
            accused_node_key: "accused".to_string(),
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
        assert_eq!(state.in_flight_count().await, 1);
        let _ = tx.send(());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(state.in_flight_count().await, 0);
        assert!(state.spawn(key(), async {}).await.unwrap());
        state.shutdown().await;
    }
}
