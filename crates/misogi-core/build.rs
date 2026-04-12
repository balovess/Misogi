fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &["proto/v1/misogi.proto", "proto/v2/misogi.proto"],
            &["proto/"],
        )?;
    Ok(())
}
