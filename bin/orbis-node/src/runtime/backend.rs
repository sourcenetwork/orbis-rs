//! Thin, backend-agnostic wrapper around `bulletin::startup::ServicesFactory`.
//! Selecting an implementation happens entirely through Cargo features in
//! `authz`/`bulletin`'s own `lib.rs` (`AuthzFactoryImpl`/`BulletinFactoryImpl`)
//! — this module never branches on which backend was compiled in.

use crate::helpers::launch::Args;
use authz::{startup::AuthzFactory, AuthzFactoryImpl};
use bulletin::{
    startup::{
        BulletinFactory, NodeServicesStartupError, PreparedNodeServices, ServicesFactory,
        ValidatedNodeServicesConfig,
    },
    BulletinFactoryImpl,
};
use common::startup::PrepareContext;
use local_storage::LocalStorageImpl;
use std::path::Path;

pub(super) type Error = NodeServicesStartupError;
type Factory = ServicesFactory<AuthzFactoryImpl, BulletinFactoryImpl>;
pub(super) type Config = ValidatedNodeServicesConfig<
    <AuthzFactoryImpl as AuthzFactory>::ValidatedConfig,
    <BulletinFactoryImpl as BulletinFactory>::ValidatedConfig,
>;
pub(super) type Prepared = PreparedNodeServices<
    <AuthzFactoryImpl as AuthzFactory>::Prepared,
    <BulletinFactoryImpl as BulletinFactory>::Prepared,
>;

pub(super) const NAMES: (&str, &str) = (
    <AuthzFactoryImpl as AuthzFactory>::NAME,
    <BulletinFactoryImpl as BulletinFactory>::NAME,
);

pub(super) fn load(args: &Args) -> Result<Config, Error> {
    Factory::load_and_validate(args.services_config.as_deref())
}

pub(super) fn prepare(
    config: Config,
    storage: &LocalStorageImpl,
    base: &Path,
) -> Result<Prepared, Error> {
    Factory::prepare(
        config,
        PrepareContext {
            storage,
            runtime_base_path: base,
        },
    )
}
