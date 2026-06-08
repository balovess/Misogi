//! Attribute value system for ABAC (Attribute-Based Access Control).
//!
//! This module defines the core data types used to represent subject,
//! resource, and environmental attributes in the Misogi ABAC engine.
//! All attribute values are strongly-typed and serializable for
//! persistent storage and network transmission.
//!
//! # Design Principles
//!
//! - **Type safety**: Each attribute variant carries its own type information,
//!   preventing accidental type confusion at evaluation time.
//! - **Extensibility**: The `Custom` variant allows domain-specific attributes
//!   without modifying the core enum definition.
//! - **Zero-allocation accessors**: Type conversion methods return `Option<&T>`
//!   to avoid unnecessary cloning when the caller only needs read access.

mod tests;

use serde::{Deserialize, Serialize};

// ===========================================================================
// AbacValue
// ===========================================================================

/// Polymorphic attribute value supporting five primitive types.
///
/// This enum represents the right-hand side of ABAC condition evaluations.
/// Every comparison operator in a policy rule compares an `AbacAttribute`
/// against an `AbacValue`.
///
/// # Variants
///
/// | Variant | Internal Type | Use Case |
/// |---------|--------------|----------|
/// | `String` | `String` | Role names, department IDs, file types |
/// | `Integer` | `i64` | File sizes, clearance levels, thresholds |
/// | `Float` | `f64` | Ratios, percentages, confidence scores |
/// | `Boolean` | `bool` | Flags (MFA verified, device compliant) |
/// | `List` | `Vec<AbacValue>` | Multi-value membership checks |
///
/// # Serialization
///
/// Uses serde's externally-tagged representation by default, producing
/// JSON such as `{"String":"admin"}` or `{"Integer":42}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum AbacValue {
    /// UTF-8 string value. Used for role names, department identifiers,
    /// data classification labels, and any text-based attribute.
    String(String),

    /// Signed 64-bit integer. Used for file sizes (bytes), clearance levels,
    /// numeric thresholds, and count-based comparisons.
    Integer(i64),

    /// 64-bit floating point. Reserved for ratio-based policies and
    /// future probability scoring extensions.
    Float(f64),

    /// Boolean flag. Used for binary state attributes such as MFA
    /// verification status, device compliance, PII presence detection.
    Boolean(bool),

    /// Ordered collection of values. Used with `In` / `NotIn` operators
    /// for membership testing against allowed/denied value sets.
    List(Vec<AbacValue>),
}

impl AbacValue {
    /// Returns a reference to the inner string if this is `AbacValue::String`.
    ///
    /// Returns `None` for all other variants. Prefer this method over
    /// pattern matching when you need optional string access without cloning.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let val = AbacValue::String("admin".to_string());
    /// assert_eq!(val.as_str(), Some("admin"));
    /// ```
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the inner `i64` if this is `AbacValue::Integer`.
    ///
    /// Returns `None` for all other variants including `Float`, even when
    /// the float value happens to be a whole number. This strict typing
    /// prevents silent precision loss in policy evaluation.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the inner `bool` if this is `AbacValue::Boolean`.
    ///
    /// Returns `None` for all other variants. Note that integer values
    /// (0/1) are NOT automatically converted to boolean; explicit
    /// `Boolean` variants must be used in policy conditions.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns a human-readable type name for logging and debugging.
    ///
    /// The returned string matches the serde tag name: `"String"`,
    /// `"Integer"`, `"Float"`, `"Boolean"`, or `"List"`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::String(_) => "String",
            Self::Integer(_) => "Integer",
            Self::Float(_) => "Float",
            Self::Boolean(_) => "Boolean",
            Self::List(_) => "List",
        }
    }
}

// ===========================================================================
// TimeWindow
// ===========================================================================

/// Represents a contiguous time range within a single day (24-hour clock).
///
/// Used by environmental attributes to enforce temporal access restrictions
/// such as business-hours-only policies or after-hours transfer blocks.
///
/// # Boundary Behavior
///
/// The window uses inclusive start and exclusive end semantics:
/// `[start_hour:start_minute, end_hour:end_minute)`. A window that spans
/// midnight (e.g., 22:00 -- 06:00) is not supported; use two separate
/// windows combined with OR logic at the policy level instead.
///
/// # Validation
///
/// All fields are validated at construction time:
/// - `start_hour` and `end_hour` must be in `0..=23`
/// - `start_minute` and `end_minute` must be in `0..=59`
/// - The end time must be strictly greater than the start time
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeWindow {
    /// Hour component of the window start (0--23, inclusive).
    pub start_hour: u8,

    /// Minute component of the window start (0--59, inclusive).
    pub start_minute: u8,

    /// Hour component of the window end (0--23, inclusive).
    pub end_hour: u8,

    /// Minute component of the window end (0--59, inclusive).
    pub end_minute: u8,
}

impl TimeWindow {
    /// Maximum valid hour value (23).
    pub const MAX_HOUR: u8 = 23;
    /// Maximum valid minute value (59).
    pub const MAX_MINUTE: u8 = 59;

    /// Constructs a new `TimeWindow` with validation.
    ///
    /// # Errors
    ///
    /// Panics (via debug assertion) if any field exceeds its valid range
    /// or if the end time is not strictly after the start time.
    /// In release builds, out-of-range values produce undefined behavior
    /// in [`contains`](Self::contains).
    pub fn new(
        start_hour: u8,
        start_minute: u8,
        end_hour: u8,
        end_minute: u8,
    ) -> Self {
        debug_assert!(start_hour <= Self::MAX_HOUR);
        debug_assert!(start_minute <= Self::MAX_MINUTE);
        debug_assert!(end_hour <= Self::MAX_HOUR);
        debug_assert!(end_minute <= Self::MAX_MINUTE);
        debug_assert!(
            (end_hour, end_minute) > (start_hour, start_minute),
            "TimeWindow: end must be strictly after start"
        );

        Self { start_hour, start_minute, end_hour, end_minute }
    }

    /// Returns `true` if the given `(hour, minute)` falls within this window.
    ///
    /// Comparison uses half-open interval semantics: the start boundary is
    /// inclusive and the end boundary is exclusive. For example, a window
    /// of `09:00--17:00` contains `09:00` but does NOT contain `17:00`.
    ///
    /// # Parameters
    ///
    /// - `hour`: Hour component (0--23). Values > 23 always return `false`.
    /// - `minute`: Minute component (0--59). Values > 59 may produce
    ///   incorrect results due to overflow in internal comparison.
    pub fn contains(&self, hour: u8, minute: u8) -> bool {
        let start = (self.start_hour, self.start_minute);
        let end = (self.end_hour, self.end_minute);
        let query = (hour, minute);

        query >= start && query < end
    }
}

// ===========================================================================
// DayMask
// ===========================================================================

/// Bitmask representing a set of days of the week.
///
/// Each bit position corresponds to one day using ISO weekday numbering
/// (Monday = 1, Sunday = 7). The bitmask enables efficient storage and
/// bitwise operations for day-set union, intersection, and difference.
///
/// # Bit Assignment
///
/// | Day       | Bit Position | Bit Value |
/// |-----------|-------------|-----------|
/// | Monday    | 0           | 1  (`0x01`) |
/// | Tuesday   | 1           | 2  (`0x02`) |
/// | Wednesday | 2           | 4  (`0x04`) |
/// | Thursday  | 3           | 8  (`0x08`) |
/// | Friday    | 4           | 16 (`0x10`) |
/// | Saturday  | 5           | 32 (`0x20`) |
/// | Sunday    | 6           | 64 (`0x40`) |
///
/// # Weekday Numbering Convention
///
/// This struct uses **1-based** weekday numbers matching `chrono::Weekday`
/// (Monday=1 .. Sunday=7). This differs from Rust's `time` crate which
/// uses 0-based numbering. Callers MUST pass values in the range 1..=7.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct DayMask {
    /// Internal bitmask. Only bits 0--6 are significant; bits 7+ are reserved.
    bits: u8,
}

impl DayMask {
    /// Bit value for Monday (bit 0).
    pub const MON: u8 = 0x01;
    /// Bit value for Tuesday (bit 1).
    pub const TUE: u8 = 0x02;
    /// Bit value for Wednesday (bit 2).
    pub const WED: u8 = 0x04;
    /// Bit value for Thursday (bit 3).
    pub const THU: u8 = 0x08;
    /// Bit value for Friday (bit 4).
    pub const FRI: u8 = 0x10;
    /// Bit value for Saturday (bit 5).
    pub const SAT: u8 = 0x20;
    /// Bit value for Sunday (bit 6).
    pub const SUN: u8 = 0x40;

    /// Constructs a `DayMask` from a single weekday number (1=Mon .. 7=Sun).
    ///
    /// For weekdays outside the valid range (1..=7), returns a mask with
    /// no bits set (equivalent to [`DayMask::empty()`]). This is intentional:
    /// invalid input silently produces an empty mask rather than panicking,
    /// since weekday numbers may originate from external configuration files.
    pub fn from_weekday(weekday: u8) -> Self {
        let bit = match weekday {
            1 => Self::MON,
            2 => Self::TUE,
            3 => Self::WED,
            4 => Self::THU,
            5 => Self::FRI,
            6 => Self::SAT,
            7 => Self::SUN,
            _ => 0,
        };
        Self { bits: bit }
    }

    /// Returns `true` if the given weekday (1=Mon .. 7=Sun) is included
    /// in this mask.
    ///
    /// Invalid weekday numbers (> 7) always return `false`.
    pub fn contains(&self, weekday: u8) -> bool {
        let bit = match weekday {
            1 => Self::MON,
            2 => Self::TUE,
            3 => Self::WED,
            4 => Self::THU,
            5 => Self::FRI,
            6 => Self::SAT,
            7 => Self::SUN,
            _ => return false,
        };
        (self.bits & bit) != 0
    }

    /// Returns a mask containing only Monday through Friday (business days).
    ///
    /// Equivalent to `0x1F` (bits 0--4 set).
    pub fn weekdays() -> Self {
        Self { bits: Self::MON | Self::TUE | Self::WED | Self::THU | Self::FRI }
    }

    /// Returns a mask containing all seven days of the week.
    ///
    /// Equivalent to `0x7F` (bits 0--6 set).
    pub fn every_day() -> Self {
        Self { bits: 0x7F }
    }

    /// Returns a mask with no days selected.
    ///
    /// Useful as a neutral element for bitwise OR accumulation.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Returns the raw bitmask value for serialization or debugging.
    pub fn as_bits(&self) -> u8 {
        self.bits
    }
}

// ===========================================================================
// AbacAttribute
// ===========================================================================

/// Comprehensive enumeration of all attributes recognized by the ABAC engine.
///
/// Attributes are categorized into three NIST-aligned domains:
///
/// 1. **Subject attributes** — Identity and properties of the requesting user.
/// 2. **Resource attributes** — Classification and metadata of the target resource.
/// 3. **Environmental attributes** — Contextual conditions independent of both
///    subject and resource (time, location, network).
///
/// Additionally, a `Custom` extension point allows domain-specific attributes
/// without requiring modifications to this core enum.
///
/// # Equality Semantics
///
/// Two `AbacAttribute` values are equal if and only if they belong to the same
/// variant and carry identical payload values. This enables exact-match lookup
/// in condition evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "category", content = "data")]
pub enum AbacAttribute {
    // -----------------------------------------------------------------------
    // Subject Attributes (who is making the request?)
    // -----------------------------------------------------------------------

    /// Unique identifier of the authenticated user (e.g., LDAP DN, UPN).
    UserId(String),

    /// Organizational role assignment (e.g., "admin", "operator", "auditor").
    Role(String),

    /// Organizational unit or department name (e.g., "IT Security").
    Department(String),

    /// Numerical clearance level (0--255). Higher values indicate greater
    /// access privileges. Mapping to specific classification labels
    /// (e.g., Unclassified/Secret/TopSecret) is the responsibility of
    /// the identity provider integration layer.
    ClearanceLevel(u8),

    /// Name of a group the subject belongs to (e.g., "DLP-Reviewers").
    /// A subject may have multiple group memberships, represented as
    /// separate `GroupMembership` attribute instances.
    GroupMembership(String),

    /// IPv4 or IPv6 address of the client endpoint. Stored as string
    /// to support both address families without separate variants.
    IpAddress(String),

    /// Geographic region code derived from IP geolocation or VPN assignment
    /// (e.g., "JP-13" for Tokyo, "US-DC" for Washington D.C.).
    GeographicRegion(String),

    /// Whether multi-factor authentication has been successfully completed
    /// for the current session. Policies may require `MfaVerified(true)`
    /// for high-sensitivity actions.
    MfaVerified(bool),

    /// Whether the client device passes the organization's compliance
    /// check (OS version, patch level, disk encryption status, etc.).
    DeviceCompliant(bool),

    // -----------------------------------------------------------------------
    // Resource Attributes (what is being accessed?)
    // -----------------------------------------------------------------------

    /// Data classification label assigned to the resource (e.g.,
    /// "public", "internal", "confidential", "restricted").
    DataClassification(String),

    /// MIME type or file extension category (e.g., "application/pdf",
    /// "text/plain", "archive"). Used to apply format-specific policies.
    FileType(String),

    /// Size of the resource in bytes. Enables size-threshold policies
    /// (e.g., block transfers larger than 100 MB).
    FileSizeBytes(u64),

    /// Target security zone for cross-zone transfer requests
    /// (e.g., "internal", "dmz", "external"). Used in data diode
    /// and air-gap enforcement scenarios.
    DestinationZone(String),

    /// Whether the resource contains Personally Identifiable Information
    /// as determined by the PII scanner pipeline. When true, additional
    /// approval obligations are typically triggered.
    ContainsPii(bool),

    // -----------------------------------------------------------------------
    // Environmental Attributes (under what context?)
    // -----------------------------------------------------------------------

    /// Time-of-day window during which the action is permitted.
    /// Combined with `DayOfWeek` to form full temporal constraints.
    TimeOfDay(TimeWindow),

    /// Set of days on which the action is permitted. Represented as a
    /// bitmask for efficient storage and bitwise operations.
    DayOfWeek(DayMask),

    /// Whether the current date falls on a business day (non-holiday
    /// weekday). Sourced from the calendar provider integration.
    BusinessDay(bool),

    /// Network classification of the source (e.g., "corporate-lan",
    /// "vpn", "guest-wifi"). Used to enforce network-segment policies.
    SourceNetwork(String),

    // -----------------------------------------------------------------------
    // Custom Extension Point
    // -----------------------------------------------------------------------

    /// User-defined attribute for domain-specific extensions that do not
    /// fit into the predefined categories above.
    ///
    /// The `key` field serves as the attribute identifier in condition
    /// matching, while `value` provides the typed payload for comparison.
    Custom {
        /// Attribute key (identifier). Must be non-empty and unique within
        /// a policy's attribute map.
        key: String,
        /// Typed attribute value for comparison against policy conditions.
        value: AbacValue,
    },
}
