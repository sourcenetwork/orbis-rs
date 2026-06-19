fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/v0/dkg_service.proto",
        "proto/v0/pre_service.proto",
        "proto/v0/info_service.proto",
        "proto/v0/store_secret_service.proto",
        "proto/v0/sign_service.proto",
        "proto/unsafe_testing_service.proto",
    ];

    for proto in &protos {
        tonic_prost_build::compile_protos(proto)?;
    }

    Ok(())
}
