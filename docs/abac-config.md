# ABAC Configuration Guide

## Overview

The ABAC (Attribute-Based Access Control) Engine implements fine-grained authorization following the NIST SP 800-162 framework. Unlike traditional RBAC, ABAC makes access decisions based on attributes of the subject, resource, action, and environment.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ABAC Decision Flow                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Access Request                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Subject: user_id, department, role, clearance_level               │    │
│  │  Resource: file_id, classification, owner, project                 │    │
│  │  Action: read, write, delete, share                                │    │
│  │  Environment: time, ip_address, device_type                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  Attribute Resolution                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Resolve attributes from AD, database, and request context          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  Policy Evaluation                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Evaluate rules in priority order                                   │    │
│  │  Apply deny-precedence semantics                                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                         ┌────────────┴────────────┐                        │
│                         ▼                         ▼                        │
│                  ┌─────────────┐           ┌─────────────┐                 │
│                  │   PERMIT    │           │    DENY     │                 │
│                  └─────────────┘           └─────────────┘                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Configuration Structure

### AbacConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Master switch for ABAC engine |
| `default_effect` | `String` | `"deny"` | Default decision when no rule matches |
| `decision_cache_ttl_secs` | `u64` | `300` | Decision cache TTL in seconds |
| `audit_log_all_decisions` | `bool` | `true` | Log all decisions for audit |
| `rules` | `Vec<AbacPolicyRule>` | `[]` | Policy rules |
| `approval_templates` | `Vec<ApprovalTemplate>` | `[]` | Approval workflow templates |

---

## Policy Rule Structure

### AbacPolicyRule

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | `String` | Unique identifier |
| `priority` | `i32` | Evaluation order (higher = first) |
| `effect` | `PolicyEffect` | `"permit"` or `"deny"` |
| `target` | `PolicyTarget` | Subject/resource targets |
| `conditions` | `Vec<PolicyCondition>` | AND-combined conditions |
| `obligation` | `Option<Obligation>` | Optional approval workflow |

### PolicyTarget

```yaml
target:
  subjects:
    - attribute: "department"
      values: ["finance", "hr"]
  resources:
    - attribute: "classification"
      values: ["confidential", "internal"]
  actions:
    - "read"
    - "write"
```

### PolicyCondition

```yaml
conditions:
  - attribute: "clearance_level"
    operator: "Gt"
    value: 3
  - attribute: "ip_address"
    operator: "IpInRange"
    value: "10.0.0.0/8"
```

---

## Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `Eq` | Equality check | `department Eq "finance"` |
| `Neq` | Inequality check | `role Neq "guest"` |
| `In` | Membership test | `department In ["hr", "finance"]` |
| `NotIn` | Non-membership test | `role NotIn ["guest", "temp"]` |
| `Gt` | Greater than | `clearance_level Gt 3` |
| `Lt` | Less than | `file_size Lt 10485760` |
| `Gte` | Greater than or equal | `priority Gte 5` |
| `Lte` | Less than or equal | `attempts Lte 3` |
| `Regex` | Pattern matching | `email Regex ".*@company\\.com$"` |
| `IpInRange` | CIDR range check | `ip_address IpInRange "10.0.0.0/8"` |

---

## Approval Workflows

### ApprovalTemplate

```yaml
approval_templates:
  - template_id: "manager_approval"
    name: "Manager Approval"
    description: "Requires manager approval for sensitive operations"
    required_approvers: 1
    approver_pool:
      source: "attribute"
      attribute: "manager_id"
    timeout_hours: 24
    auto_reject_on_timeout: true
```

### Obligation

```yaml
obligation:
  type: "approval"
  template_id: "manager_approval"
  reason: "Access to confidential document requires manager approval"
```

### Approval Flow

```
┌─────────────┐
│   Request   │
│   Matches   │
│   Rule with │
│  Obligation │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│   Create    │────▶│   Notify    │
│   Approval  │     │  Approvers  │
│   Request   │     │             │
└─────────────┘     └─────────────┘
       │
       ▼
┌─────────────┐
│   Wait for  │
│   Approval  │
└──────┬──────┘
       │
       ├──────────────────────┐
       │                      │
       ▼                      ▼
┌─────────────┐        ┌─────────────┐
│   Approved  │        │   Rejected  │
└──────┬──────┘        └──────┬──────┘
       │                      │
       ▼                      ▼
┌─────────────┐        ┌─────────────┐
│   Execute   │        │    Deny     │
│   Action    │        │   Access    │
└─────────────┘        └─────────────┘
```

---

## YAML Configuration Example

```yaml
# ABAC Configuration
abac:
  enabled: true
  default_effect: "deny"
  decision_cache_ttl_secs: 300
  audit_log_all_decisions: true

  # Policy Rules
  rules:
    # Rule 1: Deny all guest access to confidential files
    - rule_id: "deny_guest_confidential"
      priority: 100
      effect: "deny"
      target:
        subjects:
          - attribute: "role"
            values: ["guest"]
        resources:
          - attribute: "classification"
            values: ["confidential", "secret"]
      conditions: []

    # Rule 2: Allow finance department access to finance files
    - rule_id: "allow_finance_files"
      priority: 50
      effect: "permit"
      target:
        subjects:
          - attribute: "department"
            values: ["finance"]
        resources:
          - attribute: "project"
            values: ["finance"]
        actions:
          - "read"
          - "write"
      conditions:
        - attribute: "clearance_level"
          operator: "Gte"
          value: 3

    # Rule 3: Allow internal network access during business hours
    - rule_id: "allow_internal_business_hours"
      priority: 30
      effect: "permit"
      target:
        subjects:
          - attribute: "role"
            values: ["employee", "manager"]
      conditions:
        - attribute: "ip_address"
          operator: "IpInRange"
          value: "10.0.0.0/8"
        - attribute: "time_of_day"
          operator: "In"
          value: ["09:00-18:00"]

    # Rule 4: Require manager approval for delete operations
    - rule_id: "require_approval_delete"
      priority: 40
      effect: "permit"
      target:
        actions:
          - "delete"
      conditions:
        - attribute: "role"
          operator: "In"
          values: ["employee", "manager"]
      obligation:
        type: "approval"
        template_id: "manager_approval"
        reason: "Delete operations require manager approval"

  # Approval Templates
  approval_templates:
    - template_id: "manager_approval"
      name: "Manager Approval"
      description: "Requires manager approval"
      required_approvers: 1
      approver_pool:
        source: "attribute"
        attribute: "manager_id"
      timeout_hours: 24
      auto_reject_on_timeout: true
```

---

## Hot Reload

The ABAC engine supports hot reload of policy rules without service restart.

```toml
[abac.hot_reload]
enabled = true
watch_path = "/etc/misogi/abac/policies.yaml"
check_interval_secs = 30
```

**Reload Flow**:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Watch     │────▶│   Detect    │────▶│   Validate  │
│   File      │     │   Change    │     │   Config    │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │   Atomic    │
                                        │   Swap      │
                                        └─────────────┘
```

---

## Decision Caching

Cache decisions to improve performance for repeated requests.

```toml
[abac.cache]
enabled = true
ttl_secs = 300
max_entries = 10000
eviction_policy = "lru"
```

**Cache Key**: Hash of (subject_id, resource_id, action, environment_hash)

---

## Best Practices

### Security

- Always use `default_effect: "deny"` (fail-closed)
- Enable `audit_log_all_decisions: true`
- Use deny rules for sensitive resources
- Require approval for destructive operations

### Performance

- Enable decision caching for high-traffic systems
- Order rules by frequency of matching
- Use specific conditions to reduce evaluation

### Compliance

- Log all policy changes
- Document rule rationale
- Regular policy audits
- Version control policy files

### Maintainability

- Use descriptive rule_id values
- Group related rules by priority range
- Comment complex conditions
- Use templates for common patterns

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| All requests denied | `default_effect: "deny"` with no matching rules | Add permit rules |
| Unexpected denial | Rule priority order | Check rule priorities |
| Slow evaluation | Too many rules | Optimize rule order |
| Stale decisions | Cache not invalidated | Reduce TTL or clear cache |

### Diagnostic Commands

```bash
# Check ABAC status
misogi abac status

# Evaluate a request
misogi abac evaluate --subject user@company.com --resource file123 --action read

# List active rules
misogi abac rules list

# View decision cache
misogi abac cache stats

# Clear decision cache
misogi abac cache clear
```

---

## Related Documentation

- [architecture-overview.md](architecture-overview.md) - System architecture
- [enterprise-deployment.md](enterprise-deployment.md) - Deployment guide
- [integrity-config.md](integrity-config.md) - Integrity layer configuration
