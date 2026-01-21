fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/dkg_service.proto",
        "proto/pre_service.proto",
        "proto/info_service.proto",
        "proto/store_secret_service.proto",
    ];

    for proto in &protos {
        tonic_prost_build::compile_protos(proto)?;
    }

    Ok(())
}
