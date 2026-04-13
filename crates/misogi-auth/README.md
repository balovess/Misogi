# misogi-auth

**Authentication and Authorization Framework for Misogi**

Comprehensive RBAC framework aligned with Japanese organizational hierarchy and LGWAN compliance requirements. Provides role-based access control, session management, and user store with pluggable backends.

## Key Public API

- **`User` struct** — Core user representation (user_id, display_name, role, etc.)
- **`UserRole` enum** — Three roles: Staff, Approver, Admin
- **`SessionToken` struct** — Lightweight token-based authentication
- **`UserStore` struct** — Persistent user storage with async operations
- **`AuthError` enum** — Comprehensive error types

## Key Dependencies

- `tokio`: Async runtime
- `serde`/`serde_json`: Serialization and JSON handling
- `uuid`: Unique identifiers
- `chrono`: Date and time handling
- `thiserror`: Error handling

## Quick Example

```rust
use misogi_auth::{User, UserRole, SessionToken};

let staff = User::staff("EMP001", "田中 太郎");
let token = SessionToken::new(&staff, 8);
assert!(staff.role.can_upload());
assert!(!staff.role.can_approve());
```

## Full Documentation

For complete usage examples, security considerations, enterprise IDP integration patterns, performance benchmarks, and production deployment guide, see the [root README](../../README.md).
