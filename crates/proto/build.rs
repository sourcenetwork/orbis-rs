fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut protos = vec![
        "proto/orbis/v0/dkg/dkg_service.proto",
        "proto/orbis/v0/pre/pre_service.proto",
        "proto/orbis/v0/info_service/info_service.proto",
        "proto/orbis/v0/store_secret/store_secret_service.proto",
        "proto/orbis/v0/sign/sign_service.proto",
    ];

    if std::env::var_os("CARGO_FEATURE_UNSAFE_TESTING").is_some() {
        protos.push("proto/orbis/unsafe_testing/unsafe_testing_service.proto");
    }

    tonic_prost_build::configure().compile_protos(&protos, &["proto"])?;

    Ok(())
}
