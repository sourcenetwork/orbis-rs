use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    LocalStorageImpl,
};
use proto::unsafe_testing::{
    unsafe_testing_service_server::UnsafeTestingService, DeleteLocalStorageRequest,
    DeleteLocalStorageResponse, GetLocalStorageRequest, GetLocalStorageResponse,
    LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetLocalStorageRequest,
    SetLocalStorageResponse,
};
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct UnsafeTestingServiceImpl {
    local_storage: LocalStorageImpl,
}

impl UnsafeTestingServiceImpl {
    pub fn new(local_storage: LocalStorageImpl) -> Self {
        Self { local_storage }
    }
}

fn parse_key(key: Option<LocalStorageKey>) -> Result<LocalStorageKeys, Status> {
    let key = key.ok_or_else(|| Status::invalid_argument("local storage key is required"))?;
    let key_type = LocalStorageKeyType::try_from(key.key_type)
        .map_err(|_| Status::invalid_argument("unknown local storage key type"))?;

    match key_type {
        LocalStorageKeyType::RingIndex => {
            reject_ring_key_value(&key.ring_key)?;
            Ok(LocalStorageKeys::RingIndex)
        }
        LocalStorageKeyType::RingKey => {
            if key.ring_key.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "ring_key is required for RING_KEY",
                ));
            }
            Ok(LocalStorageKeys::RingKey(key.ring_key))
        }
        LocalStorageKeyType::NodeSecretKey => {
            reject_ring_key_value(&key.ring_key)?;
            Ok(LocalStorageKeys::NodeSecretKey)
        }
        LocalStorageKeyType::NodeSigningKey => {
            reject_ring_key_value(&key.ring_key)?;
            Ok(LocalStorageKeys::NodeSigningKey)
        }
        LocalStorageKeyType::Unspecified => Err(Status::invalid_argument(
            "local storage key type must be specified",
        )),
    }
}

fn reject_ring_key_value(ring_key: &str) -> Result<(), Status> {
    if ring_key.is_empty() {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "ring_key is only valid for RING_KEY",
        ))
    }
}

fn parse_access_mode(value: i32) -> Result<LocalStorageAccessMode, Status> {
    match LocalStorageAccessMode::try_from(value)
        .map_err(|_| Status::invalid_argument("unknown local storage access mode"))?
    {
        LocalStorageAccessMode::Plain => Ok(LocalStorageAccessMode::Plain),
        LocalStorageAccessMode::Encrypted => Ok(LocalStorageAccessMode::Encrypted),
        LocalStorageAccessMode::Unspecified => Err(Status::invalid_argument(
            "local storage access mode must be specified",
        )),
    }
}

fn storage_error(operation: &str, error: impl std::fmt::Display) -> Status {
    Status::internal(format!("failed to {operation} local storage: {error}"))
}

#[tonic::async_trait]
impl UnsafeTestingService for UnsafeTestingServiceImpl {
    async fn get_local_storage(
        &self,
        request: Request<GetLocalStorageRequest>,
    ) -> Result<Response<GetLocalStorageResponse>, Status> {
        let request = request.into_inner();
        let key = parse_key(request.key)?;
        let value = match parse_access_mode(request.access_mode)? {
            LocalStorageAccessMode::Plain => self
                .local_storage
                .get(key)
                .map_err(|error| storage_error("get", error))?,
            LocalStorageAccessMode::Encrypted => self
                .local_storage
                .get_encrypted(key)
                .map_err(|error| storage_error("get encrypted", error))?
                .map(|value| value.to_vec()),
            LocalStorageAccessMode::Unspecified => unreachable!(),
        };

        Ok(Response::new(GetLocalStorageResponse {
            found: value.is_some(),
            value: value.unwrap_or_default(),
        }))
    }

    async fn set_local_storage(
        &self,
        request: Request<SetLocalStorageRequest>,
    ) -> Result<Response<SetLocalStorageResponse>, Status> {
        let request = request.into_inner();
        let key = parse_key(request.key)?;
        match parse_access_mode(request.access_mode)? {
            LocalStorageAccessMode::Plain => self
                .local_storage
                .set(key, request.value)
                .map_err(|error| storage_error("set", error))?,
            LocalStorageAccessMode::Encrypted => self
                .local_storage
                .set_encrypted(key, Zeroizing::new(request.value))
                .map_err(|error| storage_error("set encrypted", error))?,
            LocalStorageAccessMode::Unspecified => unreachable!(),
        }

        Ok(Response::new(SetLocalStorageResponse {}))
    }

    async fn delete_local_storage(
        &self,
        request: Request<DeleteLocalStorageRequest>,
    ) -> Result<Response<DeleteLocalStorageResponse>, Status> {
        let key = parse_key(request.into_inner().key)?;
        let existed = self
            .local_storage
            .contains(key.clone())
            .map_err(|error| storage_error("check", error))?;
        self.local_storage
            .delete(key)
            .map_err(|error| storage_error("delete", error))?;

        Ok(Response::new(DeleteLocalStorageResponse { existed }))
    }
}
