/// Build script for misogi-core — conditionally compiles protobuf definitions.
///
/// When the "runtime" feature is enabled (default for native targets), this script
/// invokes `tonic_build` to generate Rust code from `.proto` files. When compiling
/// for WASM/browser target (runtime disabled), protobuf generation is skipped since
/// gRPC networking is unavailable in browser sandboxes.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only compile protobuf when "runtime" feature is enabled (tonic-build available).
    // Cargo sets CARGO_FEATURE_<FEATURE_NAME> env var for each enabled feature.
    if std::env::var("CARGO_FEATURE_RUNTIME").is_ok() {
        tonic_build::configure()
            .protoc_arg("--experimental_allow_proto3_optional")
            .compile_protos(
                &["proto/v1/misogi.proto", "proto/v2/misogi.proto"],
                &["proto/"],
            )?;
        println!("cargo:rerun-if-changed=proto/v1/misogi.proto");
        println!("cargo:rerun-if-changed=proto/v2/misogi.proto");
    } else {
        println!("cargo:warning=Skipping protobuf compilation (runtime feature disabled)");
    }

    Ok(())
}
