# ADR-0004: Three-Role Authorization Model

## Status

Accepted

## Context

Misogi requires an authorization system aligned with Japanese organizational hierarchy and LGWAN (Local Government Wide Area Network) compliance requirements.

### Japanese Organizational Context

Japanese government agencies typically have:
- **一般職員 (Staff)**: File handling, no approval authority
- **上長 (Approver)**: Approval authority for subordinate actions
- **管理者 (Admin)**: Full system administration

### LGWAN Requirements

- Transfer requests require approval workflow
- Audit log access is restricted
- System configuration is highly privileged

## Decision

**We adopt a three-role model: Staff, Approver, Admin.**

### Role Definitions

| Role | Japanese | Capabilities |
|------|----------|--------------|
| **Staff** | 一般職員 | Upload, download own files |
| **Approver** | 上長承認者 | Staff + approve/reject transfers + view audit logs |
| **Admin** | 管理者 | All capabilities + user management + system config |

### Permission Matrix

| Permission | Staff | Approver | Admin |
|------------|:-----:|:--------:|:-----:|
| `file_upload` | ✅ | ✅ | ✅ |
| `file_download` | ✅ | ✅ | ✅ |
| `transfer_approve` | ❌ | ✅ | ✅ |
| `user_manage` | ❌ | ❌ | ✅ |
| `policy_manage` | ❌ | ❌ | ✅ |
| `audit_view` | ❌ | ✅ | ✅ |
| `audit_export` | ❌ | ❌ | ✅ |
| `system_config` | ❌ | ❌ | ✅ |
| `api_key_manage` | ❌ | ❌ | ✅ |

### Implementation

```rust
pub enum UserRole {
    Staff,      // 一般職員
    Approver,   // 上長承認者
    Admin,      // 管理者
}

pub struct Permissions {
    pub file_upload: bool,
    pub file_download: bool,
    pub transfer_approve: bool,
    pub user_manage: bool,
    pub policy_manage: bool,
    pub audit_view: bool,
    pub audit_export: bool,
    pub system_config: bool,
    pub api_key_manage: bool,
}
```

## Consequences

### Positive

- **Cultural alignment**: Matches Japanese organizational expectations
- **LGWAN compliance**: Approval workflow built-in
- **Simplicity**: Three roles cover most scenarios
- **Audit clarity**: Role-based access is easy to audit

### Negative

- **Limited granularity**: Cannot create custom roles
- **No inheritance**: Roles are discrete, not hierarchical
- **Permission coupling**: Cannot grant individual permissions

### Mitigations

- **ABAC extension**: Attribute-based access control for complex scenarios
- **Future roles**: Enum is extensible for new roles
- **Permission checks**: Use `Permissions::can()` for fine-grained checks

## Alternatives Considered

### Alternative 1: Single Role (Admin Only)

Rejected. Violates separation of duties. No approval workflow.

### Alternative 2: RBAC with Custom Roles

Considered but rejected:
- Adds configuration complexity
- Japanese organizations prefer fixed hierarchies
- Audit trail becomes harder to interpret

### Alternative 3: ABAC Only (No Roles)

Rejected:
- Too complex for typical use cases
- Japanese users expect role-based model
- Performance overhead for attribute evaluation

### Alternative 4: Five+ Roles

Rejected:
- Over-engineering for current requirements
- Japanese model is three-tier
- Can extend later if needed

## Extension Points

The model is designed for extension:

```rust
// Future roles can be added without breaking changes
pub enum UserRole {
    Staff,
    Approver,
    Admin,
    // Future extensions:
    // Auditor,    // Audit-only role
    // Operator,   // Operations without admin
}
```

ABAC layer available for complex scenarios:

```rust
pub struct AbacContext {
    pub user_role: UserRole,
    pub department: String,
    pub time_of_day: TimeRange,
    pub source_ip: IpAddr,
}
```

## References

- [LGWAN Security Guidelines](https://www.lgwan.or.jp/)
- [Japanese Government Information Security Standards](https://www.soumu.go.jp/)
- [role.rs](../../crates/misogi-auth/src/role.rs) — Implementation

---

## History

| Date | Change |
|------|--------|
| 2026-06-08 | Initial ADR creation |
