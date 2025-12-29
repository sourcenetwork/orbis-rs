use common::SourceHubTestContainer;

#[test]
fn test_sourcehub_container_starts() {
    let container = SourceHubTestContainer::new();

    // Verify the container is running and healthy
    assert!(container.is_healthy());

    println!("SourceHub RPC: {}", container.rpc_url());
    println!("SourceHub API: {}", container.api_url());

    // Container is automatically stopped when `container` goes out of scope
}
