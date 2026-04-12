# misogi-auth

Authentication and Authorization Framework for Misogi

## Overview

`misogi-auth` provides a comprehensive authentication and authorization framework for the Misogi file transfer system. It implements role-based access control (RBAC) aligned with Japanese organizational hierarchy and LGWAN (Local Government Wide Area Network) compliance requirements.

## Features

### Core Capabilities

- **Role-Based Access Control (RBAC)**: Hierarchical permission model
- **Session Management**: Lightweight token-based authentication
- **User Store**: File-backed JSON storage with pluggable backends
- **Japanese Organizational Alignment**: Designed for public sector workflows
- **External IDP Ready**: Structured for LDAP/Active Directory/SAML integration

### User Roles

The system implements three distinct roles aligned with Japanese organizational structure:

#### Staff (一般職員)
- **Permissions**: File upload and transfer request creation
- **Restrictions**: Cannot approve transfer requests
- **Use Case**: General employees initiating file transfers

#### Approver (上長承認者)
- **Permissions**: File upload, transfer approval/rejection
- **Authority**: Can approve requests from Staff members
- **Use Case**: Department managers, section chiefs
- **Compliance**: Required for LGWAN-compliant workflows

#### Admin (管理者)
- **Permissions**: Full system access
- **Capabilities**: User management, audit log export, configuration changes
- **Use Case**: System administrators, IT staff

## Architecture

```
┌─────────────────┐
│  Client Request │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Authentication │
│  Middleware     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Session Token  │
│  Validation     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Role-Based     │
│  Authorization  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Resource Access│
│  (Allowed/      │
│   Denied)       │
└─────────────────┘
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
misogi-auth = { path = "../misogi-auth" }
```

## Usage

### Creating Users

```rust
use misogi_auth::{User, UserRole};

// Create a staff member
let staff = User::staff("EMP001", "田中 太郎");

// Create an approver
let approver = User::approver("MGR001", "佐藤 次長");

// Create an administrator
let admin = User::admin("ADMIN001", "鈴木 管理者");

// Custom user with specific role
let user = User::new(
    "EMP002".to_string(),
    "山田 花子".to_string(),
    UserRole::Staff,
);
```

### Session Management

```rust
use misogi_auth::{User, SessionToken};

// Create user
let user = User::staff("EMP001", "田中 太郎");

// Generate session token (8-hour TTL)
let token = SessionToken::new(&user, 8);

// Check expiration
if token.is_expired() {
    println!("Session expired, please re-authenticate");
} else {
    println!("Token valid until: {}", token.expires_at);
}
```

### Role-Based Authorization

```rust
use misogi_auth::{User, UserRole};

let staff = User::staff("EMP001", "田中 太郎");
let approver = User::approver("MGR001", "佐藤 次長");
let admin = User::admin("ADMIN001", "鈴木 管理者");

// Check upload permission
assert!(staff.role.can_upload());      // true
assert!(approver.role.can_upload());   // true
assert!(admin.role.can_upload());      // true

// Check approval permission
assert!(!staff.role.can_approve());    // false
assert!(approver.role.can_approve());  // true
assert!(admin.role.can_approve());     // true

// Check admin permission
assert!(!staff.role.can_administer());    // false
assert!(!approver.role.can_administer()); // false
assert!(admin.role.can_administer());     // true
```

### User Store Operations

```rust
use misogi_auth::{User, UserStore, UserRole};
use std::path::Path;

// Initialize user store
let store = UserStore::new(Path::new("users.json")).await?;

// Add user
let user = User::staff("EMP001", "田中 太郎");
store.add_user(&user).await?;

// Retrieve user
let retrieved = store.get_user("EMP001").await?;
assert_eq!(retrieved.display_name, "田中 太郎");

// Update user role
store.update_user_role("EMP001", UserRole::Approver).await?;

// List all users
let users = store.list_users().await?;
for user in users {
    println!("{} - {} ({})", 
        user.user_id, 
        user.display_name, 
        user.role.display_name_jp()
    );
}
```

## API Reference

### User Struct

Core user representation:

```rust
pub struct User {
    pub user_id: String,           // Unique identifier
    pub display_name: String,      // Japanese format name
    pub email: Option<String>,     // Optional email
    pub department: Option<String>, // Organizational unit
    pub role: UserRole,            // Assigned role
    pub created_at: DateTime<Utc>, // Creation timestamp
    pub is_active: bool,           // Account status
}
```

### SessionToken Struct

Lightweight authentication token:

```rust
pub struct SessionToken {
    pub token_id: String,          // Unique token identifier
    pub user_id: String,           // Associated user ID
    pub user_name: String,         // Cached user name
    pub role: UserRole,            // Cached role
    pub created_at: DateTime<Utc>, // Creation time
    pub expires_at: DateTime<Utc>, // Expiration time
}
```

### UserRole Enum

Role classification with permission methods:

```rust
pub enum UserRole {
    Staff,    // 一般職員
    Approver, // 上長承認者
    Admin,    // 管理者
}

impl UserRole {
    pub fn can_upload(&self) -> bool;
    pub fn can_approve(&self) -> bool;
    pub fn can_administer(&self) -> bool;
    pub fn display_name_jp(&self) -> &'static str;
}
```

### UserStore

Persistent user storage:

```rust
pub struct UserStore {
    // Internal storage backend
}

impl UserStore {
    pub async fn new(path: &Path) -> Result<Self>;
    pub async fn add_user(&self, user: &User) -> Result<()>;
    pub async fn get_user(&self, user_id: &str) -> Result<User>;
    pub async fn update_user(&self, user: &User) -> Result<()>;
    pub async fn update_user_role(&self, user_id: &str, role: UserRole) -> Result<()>;
    pub async fn delete_user(&self, user_id: &str) -> Result<()>;
    pub async fn list_users(&self) -> Result<Vec<User>>;
}
```

## Security Considerations

### Token Security

Current implementation uses lightweight session tokens:
- **Storage**: In-memory or file-backed JSON
- **Expiration**: Configurable TTL (Time To Live)
- **Validation**: Expiration check on every request

**Production Recommendation**: Replace with JWT/OIDC tokens from enterprise identity provider.

### Password Handling

Current implementation does not include password management:
- Designed for external IDP integration
- Local storage for development/testing only
- Production deployments should use:
  - LDAP/Active Directory
  - SAML 2.0 identity providers
  - OAuth2/OpenID Connect

### Access Control

Role-based permissions are enforced at the API layer:
- All endpoints must validate session tokens
- Role checks performed before resource access
- Audit logging of all authorization decisions

### Audit Trail

All authentication and authorization events are logged:
- Login attempts (success/failure)
- Token generation and validation
- Role-based access decisions
- Administrative actions

## Integration Patterns

### Enterprise IDP Integration

```rust
// Example: LDAP integration pattern
async fn authenticate_with_ldap(username: &str, password: &str) -> Result<User> {
    // Query LDAP directory
    let ldap_entry = ldap_client.search(username).await?;
    
    // Validate credentials
    ldap_client.bind(username, password).await?;
    
    // Map LDAP attributes to Misogi user
    let user = User {
        user_id: ldap_entry.uid,
        display_name: ldap_entry.cn,
        email: Some(ldap_entry.mail),
        department: ldap_entry.ou,
        role: map_ldap_group_to_role(&ldap_entry.groups),
        created_at: Utc::now(),
        is_active: true,
    };
    
    Ok(user)
}
```

### Middleware Integration

```rust
// Example: Axum middleware for authentication
async fn auth_middleware(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<Response> {
    // Extract token from header
    let token = extract_token(&req)?;
    
    // Validate token
    let user = store.validate_token(&token).await?;
    
    // Add user to request extensions
    req.extensions_mut().insert(user);
    
    // Continue to handler
    Ok(next.run(req).await)
}
```

## Error Handling

Comprehensive error types:

```rust
pub enum AuthError {
    #[error("User not found: {0}")]
    UserNotFound(String),
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Insufficient permissions: required {required}, has {has}")]
    InsufficientPermissions {
        required: UserRole,
        has: UserRole,
    },
    
    #[error("User account inactive: {0}")]
    AccountInactive(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
```

## Testing

Run the test suite:

```bash
cargo test -p misogi-auth
```

### Test Coverage

- User creation and management
- Session token lifecycle
- Role-based authorization
- User store operations
- Error handling scenarios

## Dependencies

- `tokio`: Async runtime
- `serde`: Serialization framework
- `serde_json`: JSON handling
- `uuid`: Unique identifiers
- `chrono`: Date and time handling
- `thiserror`: Error handling
- `tracing`: Logging and diagnostics

## Performance

### Benchmarks

Typical operation latencies:

| Operation | Latency |
|-----------|---------|
| Token validation | < 1 ms |
| User lookup | < 5 ms |
| Role check | < 0.1 ms |
| Token generation | < 2 ms |

### Optimization Tips

1. **Token Caching**: Cache validated tokens for repeated requests
2. **Connection Pooling**: Use connection pools for external IDP
3. **Async I/O**: Leverage Tokio for non-blocking operations
4. **Batch Operations**: Batch user store operations when possible

## Production Deployment

### Recommended Architecture

```
┌─────────────────┐
│  Application    │
│  (Misogi)       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Auth Middleware│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Enterprise IDP │
│  (LDAP/AD/SAML) │
└─────────────────┘
```

### Configuration

```toml
# config.toml example
[auth]
# Session token TTL in hours
session_ttl_hours = 8

# External IDP configuration
[idp]
type = "ldap"
server = "ldap://ad.example.com"
base_dn = "dc=example,dc=com"
bind_dn = "cn=misogi,ou=services,dc=example,dc=com"
# Use environment variables for credentials
```

### Security Hardening

1. **Use External IDP**: Never store credentials in application
2. **Enable TLS**: Encrypt all authentication traffic
3. **Short TTL**: Use short session timeouts (4-8 hours)
4. **Audit Logging**: Log all auth events to SIEM
5. **Rate Limiting**: Prevent brute force attacks
6. **MFA Support**: Integrate multi-factor authentication

## Contributing

Contributions welcome! Please note:
- All code must compile with Rust 2024 Edition
- Comprehensive documentation required
- Tests mandatory for security-related changes
- Security review required for auth logic changes

## License

Licensed under Apache 2.0 License. See [LICENSE](../../LICENSE) for details.

---

**Security Notice**: This module provides authentication framework. Production deployments MUST integrate with enterprise identity providers for security compliance.
