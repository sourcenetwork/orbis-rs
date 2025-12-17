fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = ["proto/pre_service.proto", "proto/dkg_service.proto"];

    for proto in &protos {
        tonic_prost_build::compile_protos(proto)?;
    }

    Ok(())
}
