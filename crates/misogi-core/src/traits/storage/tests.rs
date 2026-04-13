// =============================================================================
// Unit Tests for StorageBackend Trait
// =============================================================================
// Comprehensive test suite covering:
// - CRUD operations (put, get, exists, delete)
// - Trait object safety (dynamic dispatch via dyn)
// - Error conversion (From<std::io::Error>)
// - All StorageError variant display formatting
// - StorageInfo helper methods
// - Concurrent access safety
// - Health check integration
// - NotFound error handling
// - Idempotent delete behavior
// - Large data handling (1 MB)
// =============================================================================

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use md5::Digest;

use super::{StorageBackend, StorageError, StorageInfo};

// -------------------------------------------------------------------------
// Mock Implementation for Testing
// -------------------------------------------------------------------------

/// In-memory storage backend for unit testing.
///
/// Implements [`StorageBackend`] using a `HashMap` backed by `Arc<RwLock<>>`
/// for thread-safe concurrent access. This mock is used exclusively for
/// verifying trait contract compliance and error handling logic.
///
/// # Limitations
/// - No persistence (data lost on drop).
/// - No size quotas (unbounded memory usage).
/// - No real timestamps (uses Utc::now()).
/// - Not intended for production use under any circumstances.
#[derive(Debug)]
struct MockStorageBackend {
    store: Arc<parking_lot::RwLock<std::collections::HashMap<String, Bytes>>>,
    backend_name: &'static str,
}

impl MockStorageBackend {
    /// Create a new mock storage backend with the given type identifier.
    fn new(backend_name: &'static str) -> Self {
        Self {
            store: Arc::new(parking_lot::RwLock::new(
                std::collections::HashMap::new(),
            )),
            backend_name,
        }
    }
}

#[async_trait]
impl StorageBackend for MockStorageBackend {
    async fn put(
        &self,
        key: &str,
        data: Bytes,
    ) -> Result<StorageInfo, StorageError> {
        let mut store = self.store.write();
        let size = data.len() as u64;
        store.insert(key.to_string(), data);
        Ok(StorageInfo {
            key: key.to_string(),
            size,
            content_type: Some("application/octet-stream".to_string()),
            created_at: Some(Utc::now()),
            etag: Some(format!("{:x}", md5::Md5::digest(&store[key]))),
        })
    }

    async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        let store = self.store.read();
        store
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let mut store = self.store.write();
        store.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let store = self.store.read();
        Ok(store.contains_key(key))
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        // Always healthy for in-memory mock
        Ok(())
    }

    fn backend_type(&self) -> &'static str {
        self.backend_name
    }
}

// -------------------------------------------------------------------------
// Test 1: Basic CRUD Operations (Put, Get, Exists, Delete)
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_basic_crud_operations() {
    let backend = MockStorageBackend::new("memory-test");

    // Put: store data
    let data = Bytes::from_static(b"Hello, Misogi Storage!");
    let info = backend.put("test/key1", data.clone()).await.unwrap();

    assert_eq!(info.key, "test/key1");
    assert_eq!(info.size, 22);
    assert!(info.content_type.is_some());
    assert!(info.has_timestamp());
    assert!(info.has_etag());

    // Get: retrieve data
    let retrieved = backend.get("test/key1").await.unwrap();
    assert_eq!(retrieved, data);

    // Exists: verify presence
    assert!(backend.exists("test/key1").await.unwrap());

    // Delete: remove data
    backend.delete("test/key1").await.unwrap();

    // Verify deletion
    assert!(!backend.exists("test/key1").await.unwrap());

    // Get after delete should fail
    let result = backend.get("test/key1").await;
    assert!(result.is_err());
    matches!(result.unwrap_err(), StorageError::NotFound(_));
}

// -------------------------------------------------------------------------
// Test 2: Trait Object Safety (Dynamic Dispatch via Dyn)
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_trait_object_safety() {
    // Verify that StorageBackend can be used as a trait object (dyn StorageBackend).
    // This is essential for the plugin architecture where backends are selected
    // at runtime via configuration.
    let backend: Arc<dyn StorageBackend> =
        Arc::new(MockStorageBackend::new("memory-dyn"));

    // Verify all methods work through trait object
    let data = Bytes::from_static(b"trait object test");
    let info = backend.put("dyn/test", data.clone()).await.unwrap();
    assert_eq!(info.key, "dyn/test");

    let retrieved = backend.get("dyn/test").await.unwrap();
    assert_eq!(retrieved, data);

    assert!(backend.exists("dyn/test").await.unwrap());
    assert_eq!(backend.backend_type(), "memory-dyn");

    backend.health_check().await.unwrap();
    backend.delete("dyn/test").await.unwrap();
}

// -------------------------------------------------------------------------
// Test 3: Error Conversion (From<std::io::Error>)
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_error_conversion_from_io_error() {
    // Verify that std::io::Error converts to StorageError::IoError
    let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let storage_err: StorageError = io_err.into();

    match storage_err {
        StorageError::IoError(ref source) => {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert_eq!(
                source.to_string(),
                "file not found"
            );
        }
        _ => panic!("Expected StorageError::IoError variant"),
    }

    // Verify Display implementation works correctly
    let display_str = format!("{}", storage_err);
    assert!(display_str.contains("I/O error"));
    assert!(display_str.contains("file not found"));
}

// -------------------------------------------------------------------------
// Test 4: All StorageError Variants Display Correctly
// -------------------------------------------------------------------------

#[test]
fn test_all_error_variants_display() {
    let cases: Vec<(StorageError, &str)> = vec![
        (StorageError::NotFound("key1".to_string()), "not found"),
        (
            StorageError::AlreadyExists("key2".to_string()),
            "already exists",
        ),
        (
            StorageError::PermissionDenied("access denied".to_string()),
            "permission denied",
        ),
        (
            StorageError::QuotaExceeded("limit reached".to_string()),
            "quota exceeded",
        ),
        (
            StorageError::NetworkError("connection refused".to_string()),
            "network error",
        ),
        (
            StorageError::InternalError("unexpected state".to_string()),
            "internal storage error",
        ),
        (
            StorageError::NotSupported("listing".to_string()),
            "operation not supported",
        ),
        (
            StorageError::ConfigurationError("missing endpoint".to_string()),
            "configuration error",
        ),
    ];

    for (err, expected_substr) in cases {
        let display = format!("{}", err);
        assert!(
            display.to_lowercase().contains(expected_substr),
            "Expected '{}' to contain '{}', got: '{}'",
            display,
            expected_substr,
            display
        );
    }
}

// -------------------------------------------------------------------------
// Test 5: StorageInfo Helper Methods
// -------------------------------------------------------------------------

#[test]
fn test_storage_info_helper_methods() {
    // With etag and timestamp
    let info_with_all = StorageInfo {
        key: "full/object".to_string(),
        size: 4096,
        content_type: Some("application/pdf".to_string()),
        created_at: Some(Utc::now()),
        etag: Some("\"abc123\"".to_string()),
    };
    assert!(info_with_all.has_etag());
    assert!(info_with_all.has_timestamp());

    // Without etag
    let info_no_etag = StorageInfo {
        key: "partial/object".to_string(),
        size: 1024,
        content_type: None,
        created_at: Some(Utc::now()),
        etag: None,
    };
    assert!(!info_no_etag.has_etag());
    assert!(info_no_etag.has_timestamp());

    // Empty etag should return false
    let info_empty_etag = StorageInfo {
        key: "empty-etag".to_string(),
        size: 512,
        content_type: None,
        created_at: None,
        etag: Some(String::new()),
    };
    assert!(!info_empty_etag.has_etag());
    assert!(!info_empty_etag.has_timestamp());

    // Constructor with defaults
    let info_new = StorageInfo::new("constructed/key", 2048);
    assert_eq!(info_new.key, "constructed/key");
    assert_eq!(info_new.size, 2048);
    assert!(info_new.content_type.is_none());
    assert!(!info_new.has_timestamp());
    assert!(!info_new.has_etag());
}

// -------------------------------------------------------------------------
// Test 6: Concurrent Access Safety
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_access_safety() {
    let backend: Arc<dyn StorageBackend> =
        Arc::new(MockStorageBackend::new("memory-concurrent"));

    // Spawn multiple concurrent tasks writing to different keys
    let mut handles = Vec::new();
    for i in 0..10 {
        let b = Arc::clone(&backend);
        handles.push(tokio::spawn(async move {
            let key = format!("concurrent/key-{}", i);
            let data = Bytes::from(format!("data-{}", i));
            b.put(&key, data).await.unwrap();
        }));
    }

    // Wait for all writes to complete
    for h in handles {
        h.await.expect("Task panicked");
    }

    // Verify all data is readable
    for i in 0..10 {
        let key = format!("concurrent/key-{}", i);
        let expected = Bytes::from(format!("data-{}", i));
        let retrieved = backend.get(&key).await.unwrap();
        assert_eq!(retrieved, expected);
        assert!(backend.exists(&key).await.unwrap());
    }
}

// -------------------------------------------------------------------------
// Test 7: Health Check Integration
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_health_check_and_backend_type() {
    let backend = MockStorageBackend::new("mock-backend");

    // Health check should pass
    let health_result = backend.health_check().await;
    assert!(health_result.is_ok(), "Health check should succeed");

    // Backend type should match constructor argument
    assert_eq!(backend.backend_type(), "mock-backend");

    // Verify backend_type is 'static (required by trait signature)
    let _: &'static str = backend.backend_type();
}

// -------------------------------------------------------------------------
// Test 8: NotFound Error on Missing Key
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_not_found_on_missing_key() {
    let backend = MockStorageBackend::new("memory-notfound");

    // Getting a non-existent key should return NotFound
    let result = backend.get("nonexistent/key").await;
    assert!(result.is_err());

    match result.unwrap_err() {
        StorageError::NotFound(key) => {
            assert_eq!(key, "nonexistent/key");
        }
        other => panic!("Expected NotFound, got: {}", other),
    }

    // Existence check should return false (not error)
    let exists = backend.exists("nonexistent/key").await.unwrap();
    assert!(!exists);
}

// -------------------------------------------------------------------------
// Test 9: Idempotent Delete (Deleting Non-existent Key)
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_idempotent_delete() {
    let backend = MockStorageBackend::new("memory-idempotent-delete");

    // Deleting a key that never existed should succeed (idempotent)
    let result = backend.delete("never/existed").await;
    assert!(
        result.is_ok(),
        "Delete of non-existent key should succeed, got err: {:?}",
        result.err()
    );

    // Put then delete twice should both succeed
    backend
        .put("twice/deleted", Bytes::from_static(b"data"))
        .await
        .unwrap();
    backend.delete("twice/deleted").await.unwrap();
    let double_delete_result = backend.delete("twice/deleted").await;
    assert!(
        double_delete_result.is_ok(),
        "Second delete should also succeed"
    );
}

// -------------------------------------------------------------------------
// Test 10: Large Data Handling
// -------------------------------------------------------------------------

#[tokio::test]
async fn test_large_data_handling() {
    let backend = MockStorageBackend::new("memory-large");

    // Create 1 MB of data
    let large_data = Bytes::from(vec![0xABu8; 1024 * 1024]);
    let info = backend.put("large/file", large_data.clone()).await.unwrap();

    assert_eq!(info.size, 1024 * 1024);

    // Retrieve and verify
    let retrieved = backend.get("large/file").await.unwrap();
    assert_eq!(retrieved.len(), 1024 * 1024);
    assert_eq!(retrieved, large_data);
}
