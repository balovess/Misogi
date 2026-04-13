//! E2E: Pluggable TransferDriver Dispatch
//!
//! Verifies that [`TransferDriverInstance`](misogi_sender::driver_instance::TransferDriverInstance)
//! enum correctly forwards calls to concrete driver implementations.

use misogi_sender::driver_instance::TransferDriverInstance;

#[tokio::test]
async fn e2e_direct_tcp_metadata() {
    let instance = TransferDriverInstance::direct_tcp(
        "127.0.0.1:9000".into(),
        "e2e-node".into(),
    );

    assert_eq!(
        instance.name(),
        "direct-tcp-driver",
        "DirectTcp variant must report correct name"
    );
    assert_eq!(
        instance.type_id(),
        "direct_tcp",
        "DirectTcp variant must report correct type_id"
    );
}

#[tokio::test]
async fn e2e_storage_relay_factory() {
    let instance = TransferDriverInstance::storage_relay(
        "/tmp/e2e_relay/out".into(),
        "/tmp/e2e_relay/in".into(),
        10,
    );

    assert_eq!(
        instance.type_id(),
        "storage_relay",
        "StorageRelay variant must report correct type_id"
    );
}

#[tokio::test]
async fn e2e_all_variants_constructible() {
    let drivers = vec![
        TransferDriverInstance::direct_tcp("127.0.0.1:9000".into(), "t".into()),
        TransferDriverInstance::storage_relay("/out".into(), "/in".into(), 5),
        TransferDriverInstance::external_command("echo".into(), "true".into(), 30),
        TransferDriverInstance::udp_blast("192.168.254.2:9002".into()),
    ];

    assert_eq!(drivers.len(), 4, "all 4 variants must be constructible");

    for (i, d) in drivers.iter().enumerate() {
        assert!(!d.name().is_empty(), "driver {} name must not be empty", i);
        assert!(!d.type_id().is_empty(), "driver {} type_id must not be empty", i);
    }
}
