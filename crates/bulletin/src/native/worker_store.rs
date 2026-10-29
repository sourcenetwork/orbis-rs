//! Ownership of the native worker-key namespace: the only place in the
//! repository that translates `NativeWorker`'s read/write callbacks into a
//! `local-storage` operation. `NativeVeraClient::open` (this crate) and
//! `vera-admin` (cli-tool) both call [`open_native_worker`] instead of each
//! repeating the translation and key naming.
//!
//! `local-storage` sees only an opaque namespace, an opaque name, and
//! encrypted bytes — never that this is specifically a "native worker" key,
//! so a future second backend's own worker-key (or anything else) can use
//! the same primitive without `local-storage` growing another backend-named
//! variant.
//!
//! ## Backup and restore
//!
//! The worker key and the durable worker journal (the directory passed to
//! [`open_native_worker`]) are one unit, not two independently-restorable
//! pieces — the journal's sequence and pending-request guarantees only hold
//! if its key is exactly the one it was created with:
//!
//! - Stop the node (or `vera-admin`) before taking a backup.
//! - Back up the encrypted database, the worker journal directory, and the
//!   password/secret-management configuration together, as one unit.
//! - Restore the database and journal together — never one without the
//!   other.
//! - Copying only the journal, or only the encrypted database, is
//!   unsupported and must fail closed: [`open_native_worker`] returns an
//!   error rather than generating a replacement key when a journal exists
//!   but its key doesn't (or decodes incorrectly).
//! - Never point `vera-admin` at a running node's worker directory — the
//!   journal lock intentionally prevents concurrent ownership.

use local_storage::r#trait::{EncryptedStorageKey, LocalStorage, LocalStorageKeys};
use std::path::Path;
use vera_client::{ClientError, NativeWorker};
use zeroize::Zeroizing;

/// Namespace for every native worker key. Versioned so a future wire-format
/// change can introduce a new namespace without colliding with existing
/// slots, rather than needing an in-place migration.
const WORKER_NAMESPACE: &str = "bulletin/native-worker/v1";

/// Sanity bound on the opaque name `NativeWorker` hands back, before it's
/// woven into a storage key — not a cryptographic control, just a guard
/// against an unexpectedly large name.
const MAX_WORKER_KEY_NAME_LEN: usize = 256;

/// Scopes worker-key storage to one deployment, so two deployments that
/// happen to reuse the same numeric ID (or, implausibly, the same
/// `NativeWorker`-generated name) can never resolve or overwrite each
/// other's key. Read/write are the only operations exposed — normal code
/// has no reason to delete a worker key.
struct NativeWorkerKeyStore<'a, S: LocalStorage + ?Sized> {
    storage: &'a S,
    deployment_root: [u8; 32],
    deployment_id: u64,
}

/// Scope `name` to one deployment and wrap it in the worker-key namespace.
/// A free function (not a method) because it needs none of
/// `NativeWorkerKeyStore`'s storage handle — only the deployment identity —
/// which lets tests derive the exact slot without constructing a store.
fn scoped_key(
    deployment_root: [u8; 32],
    deployment_id: u64,
    name: &str,
) -> Result<LocalStorageKeys, String> {
    if name.is_empty() || name.len() > MAX_WORKER_KEY_NAME_LEN {
        return Err("invalid native worker key name".to_owned());
    }
    Ok(LocalStorageKeys::NamespacedSecret(EncryptedStorageKey {
        namespace: WORKER_NAMESPACE.to_owned(),
        name: format!("{}/{deployment_id}/{name}", hex::encode(deployment_root)),
    }))
}

impl<S: LocalStorage + ?Sized> NativeWorkerKeyStore<'_, S> {
    fn key(&self, name: &str) -> Result<LocalStorageKeys, String> {
        scoped_key(self.deployment_root, self.deployment_id, name)
    }

    fn read(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        self.storage
            .get_encrypted(self.key(name)?)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "native worker key is missing".to_owned())
    }

    fn write(&self, name: &str, value: &[u8]) -> Result<(), String> {
        self.storage
            .set_encrypted(self.key(name)?, Zeroizing::new(value.to_vec()))
            .map_err(|e| e.to_string())
    }
}

/// Open (or create) the durable native worker journal at `directory`,
/// resolving its signing key through `storage` under this deployment's
/// namespace. Fails closed on a missing or corrupt key — it never rotates
/// or recreates one while a journal already references it.
pub fn open_native_worker(
    storage: &(impl LocalStorage + ?Sized),
    directory: &Path,
    deployment_root: [u8; 32],
    deployment_id: u64,
) -> Result<NativeWorker, ClientError> {
    let store = NativeWorkerKeyStore {
        storage,
        deployment_root,
        deployment_id,
    };
    NativeWorker::open(
        directory,
        deployment_id,
        |name| store.read(name),
        |name, bytes| store.write(name, bytes),
    )
}

#[cfg(test)]
pub(crate) fn test_key(
    deployment_root: [u8; 32],
    deployment_id: u64,
    name: &str,
) -> LocalStorageKeys {
    scoped_key(deployment_root, deployment_id, name).expect("valid worker key name")
}
