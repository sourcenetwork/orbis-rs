//! A stopped node's store keeps the production Argon2id header.
//!
//! The header is read after the process has exited, from the database it
//! created at startup. An integration image that lowers the KDF cost for
//! startup time leaves this scenario ignored.

use super::TestEnvironmentImpl;
use test_support::fixture::{
    FixtureId, NetworkTestDriver, NodeFixture, NodeRole, PersistedKdfParams, ScenarioFixture,
    TestEnvironment,
};

const PRODUCTION: PersistedKdfParams = PersistedKdfParams {
    m_cost_kib: 262_144,
    t_cost: 3,
    p_cost: 1,
    version: 0x13,
};

#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    all(feature = "integration-test", feature = "cosmos"),
    ignore = "this integration image provisions the reduced Argon2id test cost"
)]
async fn test_stopped_store_keeps_production_kdf_header() {
    assert!(
        TestEnvironmentImpl::checks_production_kdf_header(),
        "production KDF header check ran against a reduced-cost store"
    );

    let fixture = ScenarioFixture {
        nodes: vec![NodeFixture {
            id: FixtureId::new("node"),
            role: NodeRole::Running,
        }],
        ..Default::default()
    };
    let environment = TestEnvironmentImpl::provision(fixture).await;
    assert_eq!(environment.nodes().len(), 1);
    environment.stop_node(0).await;

    let persisted = environment
        .persisted_kdf_params(0)
        .expect("stopped store must expose its KDF header");
    assert_eq!(
        persisted, PRODUCTION,
        "stopped store must retain production KDF parameters"
    );
}
