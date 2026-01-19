use crate::dkg::session_state::SessionStateManager;
use crate::pre::response_state::PreResponseManager;
use authz::r#trait::Authz;
use bulletin::r#trait::Bulletin;
use crypto::r#trait::Dkg;
use local_storage::LocalStorageImpl;
use network::Network;
use std::sync::Arc;

/// Shared application state accessible by all gRPC endpoints
#[derive(Clone)]
pub struct AppState<D>
where
    D: Dkg + Clone,
{
    /// Server configuration
    pub config: ServerConfig,
    /// Network for node-to-node communication
    pub network: Arc<dyn Network>,
    /// Local Storage implementation for storing items locally
    pub local_storage: LocalStorageImpl,
    /// DKG session state manager - handles both crypto state and protocol tracking
    pub dkg_session_state: Arc<SessionStateManager<D>>,
    /// PRE response state manager - handles PRE response collection
    pub pre_response_state: Arc<PreResponseManager>,
    /// Authz implementation
    pub authz: Arc<dyn Authz + Send + Sync>,
    /// Bulletin implementation
    pub bulletin: Arc<dyn Bulletin + Send + Sync>,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
}

impl<D> AppState<D>
where
    D: Dkg + Clone,
{
    /// Create a new AppState instance
    pub fn new(
        bind_address: String,
        network: Arc<dyn Network>,
        local_storage: LocalStorageImpl,
        authz: Arc<dyn Authz + Send + Sync>,
        bulletin: Arc<dyn Bulletin + Send + Sync>,
    ) -> Self {
        Self {
            config: ServerConfig { bind_address },
            network,
            local_storage,
            dkg_session_state: Arc::new(SessionStateManager::new()),
            pre_response_state: Arc::new(PreResponseManager::new()),
            authz,
            bulletin,
        }
    }
}

impl<D> std::fmt::Debug for AppState<D>
where
    D: Dkg + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .field("network", &"<Network>")
            .field("dkg_session_state", &"<SessionStateManager>")
            .field("pre_response_state", &"<PreResponseManager>")
            .finish()
    }
}
