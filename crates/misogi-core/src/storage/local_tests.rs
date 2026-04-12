// =============================================================================
// Unit Tests for LocalStorage — Filesystem StorageBackend Implementation
// =============================================================================
// Comprehensive test suite covering:
// - Put/Get roundtrip with data integrity verification (Test 1)
// - Delete idempotency — non-existent key succeeds (Test 2)
// - Exists behavior — true/false after put/delete (Test 3)
// - Directory auto-creation on put (Test 4)
// - Path traversal rejection — security critical (Test 5)
// - Non-existent key returns NotFound error (Test 6)
// - ETag generation — SHA-256 correctness (Test 7)
// - Health check validates base_path (Test 8)
// - Concurrent access safety — multiple tokio tasks (Test 9)
// - Large data handling >1 MB (Test 10)
// - Empty key rejection (Test 11)
// - Overlong key rejection (Test 12)
// - Trait object compatibility — dyn StorageBackend (Test 13)
// - Null byte in key rejection (Test 14)
// - Put overwrite — last-writer-wins (Test 15)
// =============================================================================

use std::sync::Arc;

// NOTE: Included via include!() from local.rs — types are in parent scope.
// Do NOT re-import items already present in the parent module.

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Create a LocalStorage backed by a temp directory (must exist).
async fn make_test_storage() -> (LocalStorage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let storage =
        LocalStorage::new(dir.path()).expect("failed to create LocalStorage");
    (storage, dir)
}

/// Create a LocalStorage with auto-create enabled (base_path need not exist).
async fn make_auto_storage() -> (LocalStorage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let sub_path = dir.path().join("auto_created_root");
    let storage = LocalStorage::new_auto(&sub_path)
        .await
        .expect("failed to create auto LocalStorage");
    (storage, dir)
}

// ---------------------------------------------------------------------
// Test 1: Put/Get Roundtrip — Data Integrity
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_put_get_roundtrip() {
    let (storage, _dir) = make_test_storage().await;

    let original = Bytes::from_static(b"Hello, LocalStorage!");
    let info = storage.put("greeting.txt", original.clone()).await.unwrap();

    assert_eq!(info.key, "greeting.txt");
    assert_eq!(info.size, 20);
    assert!(info.has_etag());
    assert!(info.has_timestamp());

    let retrieved = storage.get("greeting.txt").await.unwrap();
    assert_eq!(retrieved, original, "retrieved data must match original");
}

// ---------------------------------------------------------------------
// Test 2: Delete Idempotency
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_delete_idempotency() {
    let (storage, _dir) = make_test_storage().await;

    // Delete of non-existent key must succeed (idempotent contract)
    let result = storage.delete("no/such/key").await;
    assert!(
        result.is_ok(),
        "delete of non-existent key must succeed (idempotent)"
    );

    // Put then delete twice — both must succeed
    storage
        .put("tmp/file", Bytes::from_static(b"data"))
        .await
        .unwrap();
    storage.delete("tmp/file").await.unwrap();

    let double_delete = storage.delete("tmp/file").await;
    assert!(
        double_delete.is_ok(),
        "second delete must also succeed (idempotent)"
    );
}

// ---------------------------------------------------------------------
// Test 3: Exists Behavior
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_exists_behavior() {
    let (storage, _dir) = make_test_storage().await;

    // Key not yet stored
    assert!(!storage.exists("missing").await.unwrap());

    // After put — exists
    storage
        .put("present", Bytes::from_static(b"I am here"))
        .await
        .unwrap();
    assert!(storage.exists("present").await.unwrap());

    // After delete — gone
    storage.delete("present").await.unwrap();
    assert!(!storage.exists("present").await.unwrap());
}

// ---------------------------------------------------------------------
// Test 4: Directory Auto-Creation on Put
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_directory_auto_creation() {
    let (_storage, dir) = make_auto_storage().await;

    // new_auto should have created the sub-path
    let sub_path = dir.path().join("auto_created_root");
    assert!(
        sub_path.exists(),
        "auto-created root directory must exist"
    );

    // Nested key should create intermediate dirs when create_dir_if_missing=true
    let storage = LocalStorage::new(&sub_path).unwrap();
    let storage_with_auto = LocalStorage {
        base_path: storage.base_path.clone(),
        create_dir_if_missing: true,
        default_permissions: None,
    };

    storage_with_auto
        .put(
            "deeply/nested/path/file.bin",
            Bytes::from_static(b"nested content"),
        )
        .await
        .unwrap();

    let nested_file = sub_path.join("deeply/nested/path/file.bin");
    assert!(
        nested_file.exists(),
        "nested file must be created with auto-dir creation"
    );
}

// ---------------------------------------------------------------------
// Test 5: Path Traversal Rejection (Security Critical)
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_path_traversal_rejection() {
    let (storage, _dir) = make_test_storage().await;

    let traversal_keys: Vec<&str> = vec![
        "../etc/passwd",
        "foo/../../etc/shadow",
        "/absolute/path",
        "foo\\..\\bar", // Windows-style (caught by ParentDir component)
    ];

    for key in &traversal_keys {
        let result = storage.put(*key, Bytes::from_static(b"bad")).await;
        assert!(
            result.is_err(),
            "key '{}' must be rejected (path traversal)",
            key
        );
        matches!(
            result.unwrap_err(),
            StorageError::ConfigurationError(_)
        );
    }
}

// ---------------------------------------------------------------------
// Test 6: Non-existent Key Returns NotFound
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_not_found_on_get() {
    let (storage, _dir) = make_test_storage().await;

    let result = storage.get("absent/key.dat").await;
    assert!(result.is_err());

    match result.unwrap_err() {
        StorageError::NotFound(key) => {
            assert_eq!(key, "absent/key.dat");
        }
        other => panic!("Expected NotFound, got: {}", other),
    }
}

// ---------------------------------------------------------------------
// Test 7: ETag Generation (SHA-256 Correctness)
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_etag_sha256() {
    let (storage, _dir) = make_test_storage().await;

    let data = Bytes::from_static(b"etag-test-data");
    let info = storage.put("etag-check", data.clone()).await.unwrap();

    let expected_etag = LocalStorage::compute_etag(&data);
    assert_eq!(
        info.etag.as_deref(),
        Some(expected_etag.as_str()),
        "etag must be SHA-256 hex digest of the data"
    );

    // SHA-256 produces 64 hex characters
    assert_eq!(info.etag.unwrap().len(), 64);
}

// ---------------------------------------------------------------------
// Test 8: Health Check Validates Base Path
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_health_check_success() {
    let (storage, _dir) = make_test_storage().await;

    let result = storage.health_check().await;
    assert!(
        result.is_ok(),
        "health_check must succeed on valid base_path: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_health_check_invalid_path_rejected_at_construction() {
    let err = LocalStorage::new("/nonexistent/misogi/path/xyz")
        .expect_err("should fail for nonexistent path");

    matches!(err, StorageError::ConfigurationError(_));
}

// ---------------------------------------------------------------------
// Test 9: Concurrent Access Safety
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_access_safety() {
    let (storage, _dir) = make_test_storage().await;
    let storage = Arc::new(storage);

    // Spawn 20 concurrent writers to different keys
    let mut handles = Vec::new();
    for i in 0..20u32 {
        let s = Arc::clone(&storage);
        handles.push(tokio::spawn(async move {
            let key = format!("concurrent/key-{:03}", i);
            let data = Bytes::from(format!("payload-{}", i));
            s.put(&key, data).await.unwrap()
        }));
    }

    // All writes must complete successfully
    let infos: Vec<crate::traits::storage::StorageInfo> =
        futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();

    assert_eq!(infos.len(), 20, "all 20 writes must succeed");

    // All data must be readable and size-consistent
    for info in &infos {
        let retrieved = storage.get(&info.key).await.unwrap();
        assert_eq!(retrieved.len() as u64, info.size);
    }
}

// ---------------------------------------------------------------------
// Test 10: Large Data Handling (>1 MB)
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_large_data_handling() {
    let (storage, _dir) = make_test_storage().await;

    let large_data = Bytes::from(vec![0xCDu8; 2 * 1024 * 1024]); // 2 MB
    let info = storage
        .put("large/binary.blob", large_data.clone())
        .await
        .unwrap();

    assert_eq!(info.size, 2 * 1024 * 1024);

    let retrieved = storage.get("large/binary.blob").await.unwrap();
    assert_eq!(retrieved, large_data, "large data roundtrip must be exact");
}

// ---------------------------------------------------------------------
// Test 11: Empty Key Rejection
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_empty_key_rejection() {
    let (storage, _dir) = make_test_storage().await;

    let result = storage.put("", Bytes::from_static(b"x")).await;
    assert!(result.is_err());
    matches!(
        result.unwrap_err(),
        StorageError::ConfigurationError(_)
    );
}

// ---------------------------------------------------------------------
// Test 12: Overlong Key Rejection
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_overlong_key_rejection() {
    let (storage, _dir) = make_test_storage().await;

    let long_key = "a".repeat(MAX_KEY_LENGTH + 1);
    let result = storage.put(&long_key, Bytes::from_static(b"x")).await;
    assert!(result.is_err());
    matches!(
        result.unwrap_err(),
        StorageError::ConfigurationError(_)
    );
}

// ---------------------------------------------------------------------
// Test 13: Trait Object Compatibility (dyn StorageBackend)
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_trait_object_compatibility() {
    let (storage, _dir) = make_test_storage().await;

    // Must be usable as dyn StorageBackend behind Arc (plugin architecture)
    let backend: Arc<dyn StorageBackend> = Arc::new(storage);

    assert_eq!(backend.backend_type(), "local");

    let data = Bytes::from_static(b"dyn dispatch test");
    let info = backend.put("dyn/test.txt", data.clone()).await.unwrap();
    assert_eq!(info.key, "dyn/test.txt");

    let retrieved = backend.get("dyn/test.txt").await.unwrap();
    assert_eq!(retrieved, data);

    assert!(backend.exists("dyn/test.txt").await.unwrap());
    backend.health_check().await.unwrap();
    backend.delete("dyn/test.txt").await.unwrap();
}

// ---------------------------------------------------------------------
// Test 14: Null Byte in Key Rejection
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_null_byte_in_key_rejection() {
    let (storage, _dir) = make_test_storage().await;

    let result = storage
        .put("safe\0unsafe", Bytes::from_static(b"x"))
        .await;
    assert!(result.is_err());
    matches!(
        result.unwrap_err(),
        StorageError::ConfigurationError(_)
    );
}

// ---------------------------------------------------------------------
// Test 15: Put Overwrite (Last-Writer-Wins Semantics)
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_put_overwrite() {
    let (storage, _dir) = make_test_storage().await;

    storage
        .put("overwrite-me", Bytes::from_static(b"version-1"))
        .await
        .unwrap();

    let info2 = storage
        .put("overwrite-me", Bytes::from_static(b"version-2"))
        .await
        .unwrap();

    let retrieved = storage.get("overwrite-me").await.unwrap();
    assert_eq!(retrieved, Bytes::from_static(b"version-2"));
    assert_eq!(info2.size, 9);
}

// ---------------------------------------------------------------------
// Test 16: LocalConfig TOML Deserialization and build()
// ---------------------------------------------------------------------

#[test]
fn test_local_config_deserialization() {
    let toml_str = r#"
        base_path = "/var/lib/misogi/data"
        create_dir_if_missing = true
        default_permissions = 493  # 0o755
    "#;

    let config: LocalConfig = toml::from_str(toml_str)
        .expect("TOML deserialization must succeed");

    assert_eq!(
        config.base_path,
        std::path::PathBuf::from("/var/lib/misogi/data")
    );
    assert!(config.create_dir_if_missing);
    assert_eq!(config.default_permissions, Some(493));

    // Verify defaults when fields are omitted
    let minimal_toml = r#"base_path = "/tmp/misogi""#;
    let minimal: LocalConfig =
        toml::from_str(minimal_toml).expect("minimal TOML must parse");

    assert!(!minimal.create_dir_if_missing);
    assert!(minimal.default_permissions.is_none());
}
