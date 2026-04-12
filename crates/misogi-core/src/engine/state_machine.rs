// =============================================================================
// Generic Finite State Machine Engine
// =============================================================================
// Provides a thread-safe, async-compatible finite state machine (FSM) with
// configurable transition rules, optional guard functions, and event-driven
// trigger mechanisms.
//
// Design Goals:
// 1. Type Safety: Generic over state type S with Clone + Eq + Hash bounds.
// 2. Concurrency: RwLock-protected state allows concurrent reads, serialized writes.
// 3. Extensibility: Guard functions enable runtime policy enforcement.
// 4. Observability: Transition results include full audit trail metadata.
//
// Usage Pattern:
// ```rust
// let mut sm = StateMachine::new(FileLifecycleState::PendingApproval);
// sm.add_state(FileLifecycleState::Approved);
// sm.add_transition(
//     FileLifecycleState::PendingApproval,
//     FileLifecycleState::Approved,
//     "approve",
//     None,
// );
// let result = sm.trigger("approve", context)?;
// ```
//
// Thread Safety:
// The current state is protected by RwLock<S>. Multiple tasks can read the
// current state concurrently via current_state(). Write operations (transition)
// acquire exclusive access atomically. Guard functions are executed while
// holding a read lock on the state map but before acquiring the write lock
// for the actual state update, minimizing lock contention.
// =============================================================================

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{MisogiError, Result};

// =============================================================================
// Public Types
// =============================================================================

/// Contextual information passed to guard functions during transition evaluation.
///
/// Carries actor identity and arbitrary metadata that guards may use to make
/// authorization decisions (e.g., "only admins can approve transfers > 1GB").
///
/// # Fields
/// - `actor_id`: Optional identifier of the entity initiating the transition.
///   May be user ID, service account name, or system process name.
/// - `metadata`: Key-value pairs carrying additional context (file size,
///   source zone, approval reason, etc.) for complex guard logic.
#[derive(Debug, Clone)]
pub struct TransitionContext {
    /// Identifier of the entity initiating this state transition.
    /// `None` indicates system-initiated or anonymous transitions.
    pub actor_id: Option<String>,

    /// Arbitrary key-value metadata for guard function evaluation.
    /// Common keys: "file_size", "source_zone", "approval_reason".
    pub metadata: HashMap<String, String>,
}

impl TransitionContext {
    /// Create a new transition context with the given actor identifier.
    ///
    /// # Arguments
    /// * `actor_id` - Optional identifier of the initiating entity.
    ///
    /// # Returns
    /// A TransitionContext with empty metadata map.
    pub fn new(actor_id: Option<impl Into<String>>) -> Self {
        Self {
            actor_id: actor_id.map(|s| s.into()),
            metadata: HashMap::new(),
        }
    }

    /// Add a metadata key-value pair to this context.
    ///
    /// # Arguments
    /// * `key` - Metadata key (e.g., "file_size").
    /// * `value` - Metadata value (e.g., "1048576").
    ///
    /// # Returns
    /// `&mut self` for method chaining.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

impl Default for TransitionContext {
    fn default() -> Self {
        Self::new(None::<String>)
    }
}

/// Result of a successful state transition operation.
///
/// Provides complete audit trail information including source/destination states,
/// trigger name, and precise timestamp. This structure is suitable for:
/// - Audit log entries (serialized to JSONL)
/// - Event subscriber notifications
/// - Debugging and troubleshooting transition histories
///
/// # Serialization
/// Implements Serialize for JSON output. The state type S must also implement
/// Serialize (enforced by the StateMachine bounds).
#[derive(Debug, Clone, Serialize)]
pub struct TransitionResult<S> {
    /// Source state before the transition.
    pub from: S,

    /// Destination state after the transition.
    pub to: S,

    /// Name of the trigger that initiated this transition.
    pub trigger: String,

    /// UTC timestamp of when the transition completed (RFC3339 format).
    pub timestamp: DateTime<Utc>,
}

/// Type alias for guard functions used in transition rules.
///
/// Guards are invoked synchronously during [`StateMachine::transition()`] and
/// [`StateMachine::trigger()`]. They receive a reference to the transition
/// context and return `true` if the transition should proceed, `false` to block.
///
/// # Thread Safety
/// Wrapped in Arc<dyn Fn + Send + Sync> enabling safe sharing across async
/// tasks and threads. Implementations MUST NOT perform blocking I/O or
/// long-running computations (target < 10ms execution time).
pub type GuardFn = Arc<dyn Fn(&TransitionContext) -> bool + Send + Sync>;

// =============================================================================
// Internal Types
// =============================================================================

/// Configuration for a single state in the FSM.
///
/// Stores all outgoing transition rules from this state. States with no
/// outgoing transitions are terminal states (end of workflow).
struct StateConfig<S> {
    /// Ordered list of transition rules from this state.
    /// Order matters when multiple rules share the same target state.
    transitions: Vec<TransitionRule<S>>,
}

impl<S> Default for StateConfig<S> {
    fn default() -> Self {
        Self {
            transitions: Vec::new(),
        }
    }
}

/// Defines a single transition rule from one state to another.
///
/// Each rule specifies the target state, the trigger name that activates it,
/// and an optional guard function for conditional transitions.
pub struct TransitionRule<S> {
    /// Destination state when this rule fires.
    target_state: S,

    /// Trigger name that activates this transition (e.g., "approve", "reject").
    /// Must be unique within a single state's transition set.
    trigger_name: String,

    /// Optional guard function evaluated before allowing the transition.
    /// `None` means unconditional (always allowed).
    guard: Option<GuardFn>,
}

// =============================================================================
// StateMachine Implementation
// =============================================================================

/// Generic finite state machine with configurable transitions, guards, and async safety.
///
/// This is the core workflow engine for Misogi's approval system. It manages
/// file lifecycle states (PendingApproval -> Approved -> Transferring, etc.)
/// with pluggable validation logic via guard functions.
///
/// # Type Parameters
/// - `S`: State enum type. Must implement Clone (for result copying), Eq (for
///   state equality checks), Hash (for HashMap keys), and Serialize (for
///   audit trail output).
///
/// # Concurrency Model
/// - **Read operations** (`current_state`, `valid_transitions_from`) acquire
///   shared read locks, allowing unlimited concurrent readers.
/// - **Write operations** (`transition`, `trigger`) acquire exclusive write locks,
///   serializing all state mutations.
/// - **Configuration operations** (`add_transition`, `add_state`) are only safe
///   to call during initialization before any concurrent access begins.
///
/// # Example
/// ```rust
/// use misogi_core::engine::{StateMachine, TransitionContext};
///
/// #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)]
/// enum MyState { Idle, Running, Stopped }
///
/// let mut sm = StateMachine::new(MyState::Idle);
/// sm.add_state(MyState::Running);
/// sm.add_state(MyState::Stopped);
/// sm.add_transition(MyState::Idle, MyState::Running, "start", None);
/// sm.add_transition(MyState::Running, MyState::Stopped, "stop", None);
///
/// assert_eq!(sm.current_state(), MyState::Idle);
/// let result = sm.trigger("start", TransitionContext::default())?;
/// assert_eq!(sm.current_state(), MyState::Running);
/// # Ok::<(), misogi_core::error::MisogiError>(())
/// ```
pub struct StateMachine<S: Clone + Eq + Hash + Serialize + std::fmt::Debug> {
    /// Complete state graph: maps each state to its configuration (outgoing transitions).
    states: HashMap<S, StateConfig<S>>,

    /// Current state of the machine, protected by RwLock for thread-safe access.
    /// Initialized to the provided initial state and updated atomically on transitions.
    current: RwLock<S>,

    /// Initial state provided at construction time. Used for reset operations
    /// and diagnostic logging.
    #[allow(dead_code)]
    initial: S,
}

impl<S: Clone + Eq + Hash + Serialize + std::fmt::Debug> StateMachine<S> {
    /// Create a new state machine initialized to the given state.
    ///
    /// The initial state is automatically registered in the state graph.
    /// Additional states must be explicitly registered via [`add_state()`](Self::add_state)
    /// before transitions can be defined to/from them.
    ///
    /// # Arguments
    /// * `initial_state` - The starting state for this machine instance.
    ///
    /// # Returns
    /// A new StateMachine instance with no transition rules defined.
    ///
    /// # Example
    /// ```rust
    /// # use misogi_core::engine::StateMachine;
    /// # #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)] enum S { A }
    /// let sm = StateMachine::new(S::A);
    /// assert_eq!(sm.current_state(), S::A);
    /// ```
    pub fn new(initial_state: S) -> Self {
        let mut states = HashMap::new();
        states.insert(initial_state.clone(), StateConfig::default());

        Self {
            states,
            current: RwLock::new(initial_state.clone()),
            initial: initial_state,
        }
    }

    /// Register a state in the machine's state graph (even if it has no outgoing transitions).
    ///
    /// Terminal states (states with no valid outgoing transitions) MUST be registered
    /// explicitly via this method. Failure to register a state before adding transitions
    /// to/from it will cause those transition additions to fail.
    ///
    /// # Arguments
    /// * `state` - The state to register. If already registered, this is a no-op.
    ///
    /// # Panics
    /// This method does not panic. Duplicate registrations are silently ignored.
    ///
    /// # Example
    /// ```rust
    /// # use misogi_core::engine::StateMachine;
    /// # #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)] enum S { A, B }
    /// let mut sm = StateMachine::new(S::A);
    /// sm.add_state(S::B); // Register terminal state B
    /// ```
    pub fn add_state(&mut self, state: S) {
        self.states.entry(state).or_insert_with(StateConfig::default);
    }

    /// Define a transition rule from one state to another.
    ///
    /// Both the `from` and `to` states MUST be registered (via [`new()`](Self::new) or
    /// [`add_state()`](Self::add_state)) before calling this method. The transition
    /// rule is appended to the `from` state's existing transition list.
    ///
    /// # Arguments
    /// * `from` - Source state (must be registered).
    /// * `to` - Target state (must be registered).
    /// * `trigger_name` - Human-readable trigger name (e.g., "approve", "reject").
    ///   Must be non-empty. Used by [`trigger()`](Self::trigger) for event-driven transitions.
    /// * `guard` - Optional guard function. If `Some(guard)`, the guard is invoked
    ///   during transition attempts and must return `true` for the transition to proceed.
    ///   Pass `None` for unconditional transitions.
    ///
    /// # Errors
    /// Returns [`MisogiError::Protocol`] if either state is not registered in the graph.
    ///
    /// # Example
    /// ```rust
    /// # use misogi_core::engine::{StateMachine, TransitionContext};
    /// # use std::sync::Arc;
    /// # #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)] enum S { A, B }
    /// let mut sm = StateMachine::new(S::A);
    /// sm.add_state(S::B);
    ///
    /// // Unconditional transition
    /// sm.add_transition(S::A, S::B, "go", None)?;
    ///
    /// // Conditional transition (only allow if actor is "admin")
    /// let guard: std::sync::Arc<dyn Fn(&TransitionContext) -> bool + Send + Sync> =
    ///     Arc::new(|ctx: &TransitionContext| {
    ///         ctx.actor_id.as_deref() == Some("admin")
    ///     });
    /// sm.add_transition(S::B, S::A, "return", Some(guard))?;
    /// # Ok::<(), misogi_core::error::MisogiError>(())
    /// ```
    pub fn add_transition(
        &mut self,
        from: S,
        to: S,
        trigger_name: impl Into<String>,
        guard: Option<GuardFn>,
    ) -> Result<()> {
        // Validate both states exist in the graph
        if !self.states.contains_key(&from) {
            return Err(MisogiError::Protocol(format!(
                "Source state not registered: {:?}",
                from
            )));
        }
        if !self.states.contains_key(&to) {
            return Err(MisogiError::Protocol(format!(
                "Target state not registered: {:?}",
                to
            )));
        }

        let trigger = trigger_name.into();
        if trigger.is_empty() {
            return Err(MisogiError::Protocol(
                "Trigger name must not be empty".to_string(),
            ));
        }

        // Append transition rule to source state's configuration
        let config = self.states.get_mut(&from).unwrap();
        config.transitions.push(TransitionRule {
            target_state: to,
            trigger_name: trigger,
            guard,
        });

        Ok(())
    }

    /// Execute a transition to the specified target state.
    ///
    /// This method performs the following steps atomically:
    /// 1. Acquires read lock to check current state matches expected `from` state.
    /// 2. Validates that a transition rule exists from current state to `target`.
    /// 3. If a guard function is present, evaluates it with the provided context.
    /// 4. Acquires write lock and updates current state to `target`.
    /// 5. Constructs and returns a [`TransitionResult`] with full audit trail.
    ///
    /// # Arguments
    /// * `target` - Desired destination state (must have a valid transition rule).
    /// * `context` - Transition context carrying actor identity and metadata
    ///   for guard function evaluation and audit logging.
    ///
    /// # Returns
    /// A [`TransitionResult`] containing source/destination states, trigger name,
    /// and timestamp on success.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if no valid transition exists from current state to `target`.
    /// - [`MisogiError::Protocol`] if a guard function rejects the transition.
    ///
    /// # Concurrency Safety
    /// The transition check-and-update sequence is NOT atomic with respect to other
    /// concurrent transitions. Two simultaneous calls may both pass the guard check,
    /// but only one will succeed in updating the state (the second will fail because
    /// the current state no longer matches). This is by design: the FSM model assumes
    /// serializable transitions where the first writer wins.
    ///
    /// # Example
    /// ```rust
    /// # use misogi_core::engine::{StateMachine, TransitionContext};
    /// # #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)] enum S { A, B }
    /// # let mut sm = StateMachine::new(S::A);
    /// # sm.add_state(S::B);
    /// # sm.add_transition(S::A, S::B, "go", None).unwrap();
    /// let ctx = TransitionContext::new(Some("user-123"));
    /// let result = sm.transition(S::B, ctx)?;
    /// assert_eq!(result.to, S::B);
    /// # Ok::<(), misogi_core::error::MisogiError>(())
    /// ```
    pub fn transition(&self, target: S, context: TransitionContext) -> Result<TransitionResult<S>> {
        // Step 1: Read current state (shared lock)
        let current_state = self
            .current
            .read()
            .map_err(|e| MisogiError::PoisonError(format!("RwLock poisoned: {}", e)))?
            .clone();

        // Step 2: Find matching transition rule
        let config = self
            .states
            .get(&current_state)
            .ok_or_else(|| MisogiError::Protocol(format!("Current state not registered: {:?}", current_state)))?;

        let matching_rule = config
            .transitions
            .iter()
            .find(|rule| rule.target_state == target)
            .ok_or_else(|| {
                MisogiError::Protocol(format!(
                    "No transition from {:?} to {:?}",
                    current_state, target
                ))
            })?;

        // Step 3: Evaluate guard function if present
        if let Some(ref guard) = matching_rule.guard {
            if !guard(&context) {
                return Err(MisogiError::Protocol(format!(
                    "Guard function rejected transition from {:?} to {:?}",
                    current_state, target
                )));
            }
        }

        // Step 4: Update current state (exclusive lock)
        {
            let mut state = self
                .current
                .write()
                .map_err(|e| MisogiError::PoisonError(format!("RwLock poisoned: {}", e)))?;

            // Double-check: another task may have changed the state since we read it
            if *state != current_state {
                return Err(MisogiError::Protocol(format!(
                    "Race condition: state changed from {:?} to {:?} during transition",
                    current_state, *state
                )));
            }

            *state = target.clone();
        }

        // Step 5: Construct result
        Ok(TransitionResult {
            from: current_state,
            to: target,
            trigger: matching_rule.trigger_name.clone(),
            timestamp: Utc::now(),
        })
    }

    /// Execute a transition triggered by name rather than target state.
    ///
    /// Convenience wrapper around [`transition()`](Self::transition) that searches
    /// for a transition rule whose `trigger_name` matches the given string. This
    /// enables event-driven workflows where external systems send trigger names
    /// ("approve", "reject") without knowing the concrete target state.
    ///
    /// # Arguments
    /// * `trigger_name` - Name of the trigger to fire (must match a rule on the
    ///   current state's transition list exactly).
    /// * `context` - Transition context for guard evaluation and audit trail.
    ///
    /// # Returns
    /// A [`TransitionResult`] on success.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if no transition rule with the given trigger name
    ///   exists on the current state.
    /// - Propagates errors from [`transition()`](Self::transition) (guard rejection,
    ///   race conditions, etc.).
    ///
    /// # Example
    /// ```rust
    /// # use misogi_core::engine::{StateMachine, TransitionContext};
    /// # #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)] enum S { Pending, Approved }
    /// # let mut sm = StateMachine::new(S::Pending);
    /// # sm.add_state(S::Approved);
    /// # sm.add_transition(S::Pending, S::Approved, "approve", None).unwrap();
    /// let result = sm.trigger("approve", TransitionContext::default())?;
    /// assert_eq!(result.to, S::Approved);
    /// # Ok::<(), misogi_core::error::MisogiError>(())
    /// ```
    pub fn trigger(
        &self,
        trigger_name: &str,
        context: TransitionContext,
    ) -> Result<TransitionResult<S>> {
        // Read current state
        let current_state = self
            .current
            .read()
            .map_err(|e| MisogiError::PoisonError(format!("RwLock poisoned: {}", e)))?
            .clone();

        // Find rule by trigger name
        let config = self
            .states
            .get(&current_state)
            .ok_or_else(|| MisogiError::Protocol(format!("Current state not registered: {:?}", current_state)))?;

        let rule = config
            .transitions
            .iter()
            .find(|r| r.trigger_name == trigger_name)
            .ok_or_else(|| {
                MisogiError::Protocol(format!(
                    "No trigger '{}' found on state {:?}",
                    trigger_name, current_state
                ))
            })?;

        // Delegate to transition() with the resolved target state
        self.transition(rule.target_state.clone(), context)
    }

    /// Query the current state of the machine.
    ///
    /// Returns a clone of the current state. This operation acquires a shared
    /// read lock and is safe to call concurrently from multiple tasks.
    ///
    /// # Returns
    /// Clone of the current state value.
    ///
    /// # Performance
    /// O(1) time complexity. Lock contention only occurs during active transitions.
    ///
    /// # Example
    /// ```rust
    /// # use misogi_core::engine::StateMachine;
    /// # #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)] enum S { A }
    /// let sm = StateMachine::new(S::A);
    /// assert_eq!(sm.current_state(), S::A);
    /// ```
    pub fn current_state(&self) -> S {
        self.current
            .read()
            .map_err(|e| MisogiError::PoisonError(format!("RwLock poisoned: {}", e)))
            .expect("RwLock poisoned in current_state()")
            .clone()
    }

    /// List all valid transition rules from a given state.
    ///
    /// Useful for building UI forms (showing available actions), API documentation
    /// (listing possible next states), and debugging (inspecting the state graph).
    ///
    /// # Arguments
    /// * `state` - The state to query (must be registered).
    ///
    /// # Returns
    /// Vector of references to [`TransitionRule`] instances. Empty vector if the
    /// state has no outgoing transitions (terminal state) or is not registered.
    ///
    /// # Example
    /// ```rust
    /// # use misogi_core::engine::StateMachine;
    /// # #[derive(Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize, Debug)] enum S { A, B, C }
    /// # let mut sm = StateMachine::new(S::A);
    /// # sm.add_state(S::B);
    /// # sm.add_state(S::C);
    /// # sm.add_transition(S::A, S::B, "to_b", None).unwrap();
    /// # sm.add_transition(S::A, S::C, "to_c", None).unwrap();
    /// let transitions = sm.valid_transitions_from(&S::A);
    /// assert_eq!(transitions.len(), 2);
    /// ```
    pub fn valid_transitions_from(&self, state: &S) -> Vec<&TransitionRule<S>> {
        self.states
            .get(state)
            .map(|config| config.transitions.iter().collect())
            .unwrap_or_default()
    }
}

// =============================================================================
// Trait Implementation for ApprovalTrigger Compatibility
// =============================================================================
// The StateMachine implements the trait interface defined in traits/mod.rs
// to satisfy the ApprovalTrigger<S>::start() signature which expects
// Arc<dyn StateMachine<S>>.

impl<S: Clone + Eq + Hash + Send + Sync + Serialize + std::fmt::Debug + 'static> crate::traits::StateMachine<S>
    for StateMachine<S>
{
    /// Subscribe to state change events from this machine.
    ///
    /// Returns a closure that will be invoked whenever a transition completes
    /// successfully. The closure receives the new state value.
    ///
    /// # Note
    /// This is a simplified stub implementation. Production usage would integrate
    /// with an event bus or channel-based notification system. The returned closure
    /// currently logs state changes via tracing.
    fn subscribe(&self) -> Box<dyn Fn(S) + Send + Sync> {
        // In a production implementation, this would register with an event dispatcher.
        // For now, we return a closure that logs state changes.
        let _machine = self; // Capture reference for potential future use
        Box::new(move |new_state: S| {
            tracing::info!(state = ?new_state, "State machine transitioned");
        })
    }

    /// Query the current state of the machine.
    ///
    /// Delegates to [`current_state()`](StateMachine::current_state).
    fn current_state(&self) -> S {
        self.current_state()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================
// Comprehensive test suite covering basic operations, error cases, guard functions,
// concurrency safety, and trigger-based transitions.

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Simple test state enum for unit testing.
    #[derive(Clone, Eq, Hash, PartialEq, Serialize, Deserialize, Debug)]
    enum TestState {
        Idle,
        Running,
        Stopped,
        Error,
    }

    /// Helper to create a pre-configured test machine with standard transitions.
    fn create_test_machine() -> StateMachine<TestState> {
        let mut sm = StateMachine::new(TestState::Idle);
        sm.add_state(TestState::Running);
        sm.add_state(TestState::Stopped);
        sm.add_state(TestState::Error);
        sm
            .add_transition(TestState::Idle, TestState::Running, "start", None)
            .unwrap();
        sm.add_transition(
            TestState::Running,
            TestState::Stopped,
            "stop",
            None,
        )
        .unwrap();
        sm.add_transition(TestState::Running, TestState::Error, "fail", None)
            .unwrap();
        sm
    }

    // -------------------------------------------------------------------------
    // Test 1: Basic Valid Transition
    // -------------------------------------------------------------------------

    #[test]
    fn test_basic_valid_transition() {
        let sm = create_test_machine();

        assert_eq!(sm.current_state(), TestState::Idle);

        let result = sm
            .transition(TestState::Running, TransitionContext::default())
            .expect("Valid transition should succeed");

        assert_eq!(result.from, TestState::Idle);
        assert_eq!(result.to, TestState::Running);
        assert_eq!(result.trigger, "start");
        assert_eq!(sm.current_state(), TestState::Running);

        // Verify timestamp is recent (within last 5 seconds)
        let age = Utc::now().signed_duration_since(result.timestamp);
        assert!(age.num_seconds() < 5, "Timestamp should be recent");
    }

    // -------------------------------------------------------------------------
    // Test 2: Invalid Transition Rejection
    // -------------------------------------------------------------------------

    #[test]
    fn test_invalid_transition_rejection() {
        let sm = create_test_machine();

        // Cannot transition from Idle to Stopped (no direct rule)
        let result = sm.transition(TestState::Stopped, TransitionContext::default());
        assert!(result.is_err(), "Invalid transition should fail");

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No transition"),
            "Error should mention missing transition: {}",
            err
        );
    }

    // -------------------------------------------------------------------------
    // Test 3: Guard Function Blocks Transition
    // -------------------------------------------------------------------------

    #[test]
    fn test_guard_blocks_transition() {
        let _sm = create_test_machine();

        // Add a guarded transition: Idle -> Running (guarded_start)
        let guard = Arc::new(|ctx: &TransitionContext| {
            // Only allow if actor_id starts with "admin"
            ctx.actor_id
                .as_ref()
                .map(|id| id.starts_with("admin"))
                .unwrap_or(false)
        });

        // Replace existing start transition with guarded version (need new machine)
        let mut sm_guarded = StateMachine::new(TestState::Idle);
        sm_guarded.add_state(TestState::Running);
        sm_guarded
            .add_transition(
                TestState::Idle,
                TestState::Running,
                "guarded_start",
                Some(guard),
            )
            .unwrap();

        // Try with non-admin actor (should fail)
        let ctx_non_admin = TransitionContext::new(Some("user-123"));
        let result = sm_guarded.transition(TestState::Running, ctx_non_admin);
        assert!(result.is_err(), "Guard should block non-admin");
        assert!(
            result.unwrap_err().to_string().contains("Guard"),
            "Error should mention guard rejection"
        );

        // Verify state did not change
        assert_eq!(sm_guarded.current_state(), TestState::Idle);
    }

    // -------------------------------------------------------------------------
    // Test 4: Guard Allows Transition
    // -------------------------------------------------------------------------

    #[test]
    fn test_guard_allows_transition() {
        let guard = Arc::new(|ctx: &TransitionContext| {
            ctx.actor_id.as_ref().map(|id| id.starts_with("admin")).unwrap_or(false)
        });

        let mut sm = StateMachine::new(TestState::Idle);
        sm.add_state(TestState::Running);
        sm.add_transition(
            TestState::Idle,
            TestState::Running,
            "admin_start",
            Some(guard),
        )
        .unwrap();

        // Try with admin actor (should succeed)
        let ctx_admin = TransitionContext::new(Some("admin-alice"));
        let result = sm.transition(TestState::Running, ctx_admin);
        assert!(result.is_ok(), "Guard should allow admin");

        let result = result.unwrap();
        assert_eq!(result.to, TestState::Running);
        assert_eq!(sm.current_state(), TestState::Running);
    }

    // -------------------------------------------------------------------------
    // Test 5: Concurrent Transition Safety
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_concurrent_transition_safety() {
        let sm = Arc::new(create_test_machine());

        // Spawn two tasks trying to transition simultaneously from Idle
        let sm_clone = Arc::clone(&sm);
        let handle1 = tokio::spawn(async move {
            sm_clone.transition(TestState::Running, TransitionContext::default())
        });

        let sm_clone2 = Arc::clone(&sm);
        let handle2 = tokio::spawn(async move {
            sm_clone2.transition(TestState::Running, TransitionContext::default())
        });

        let result1 = handle1.await.expect("Task 1 should not panic");
        let result2 = handle2.await.expect("Task 2 should not panic");

        // Exactly one should succeed, the other should fail due to race condition
        let success_count = [result1.is_ok(), result2.is_ok()]
            .iter()
            .filter(|&&x| x)
            .count();

        assert_eq!(
            success_count, 1,
            "Exactly one concurrent transition should succeed, got {}",
            success_count
        );

        // Final state should be Running (the winning transition)
        assert_eq!(
            sm.current_state(),
            TestState::Running,
            "Final state should be Running after successful transition"
        );

        // The failed attempt should mention race condition or state mismatch
        let failed_result = if result1.is_err() { result1 } else { result2 };
        if let Err(e) = failed_result {
            let err_msg = e.to_string();
            assert!(
                err_msg.contains("No transition") || err_msg.contains("Race condition"),
                "Failure should indicate invalid transition or race: {}",
                err_msg
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test 6: Trigger-Based Transition
    // -------------------------------------------------------------------------

    #[test]
    fn test_trigger_based_transition() {
        let sm = create_test_machine();

        // Use trigger name instead of explicit target state
        let result = sm.trigger("start", TransitionContext::default());
        assert!(result.is_ok(), "Trigger 'start' should succeed");

        let result = result.unwrap();
        assert_eq!(result.from, TestState::Idle);
        assert_eq!(result.to, TestState::Running);
        assert_eq!(result.trigger, "start");

        // Now trigger "stop" from Running state
        let result2 = sm.trigger("stop", TransitionContext::default());
        assert!(result2.is_ok(), "Trigger 'stop' should succeed");
        assert_eq!(result2.unwrap().to, TestState::Stopped);

        // Invalid trigger name should fail
        let result3 = sm.trigger("invalid_trigger", TransitionContext::default());
        assert!(result3.is_err(), "Invalid trigger should fail");
        assert!(
            result3.unwrap_err().to_string().contains("No trigger"),
            "Error should mention missing trigger"
        );
    }

    // -------------------------------------------------------------------------
    // Additional Edge Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_valid_transitions_from() {
        let sm = create_test_machine();

        // Idle state should have 1 transition (to Running)
        let idle_transitions = sm.valid_transitions_from(&TestState::Idle);
        assert_eq!(idle_transitions.len(), 1);
        assert_eq!(idle_transitions[0].target_state, TestState::Running);

        // Running state should have 2 transitions (to Stopped, Error)
        let running_transitions = sm.valid_transitions_from(&TestState::Running);
        assert_eq!(running_transitions.len(), 2);

        // Stopped state should have 0 transitions (terminal)
        let stopped_transitions = sm.valid_transitions_from(&TestState::Stopped);
        assert_eq!(stopped_transitions.len(), 0);
    }

    #[test]
    fn test_unregistered_state_rejection() {
        let mut sm = StateMachine::new(TestState::Idle);

        // Try to add transition to unregistered state
        let result = sm.add_transition(
            TestState::Idle,
            TestState::Running,
            "start",
            None,
        );
        assert!(result.is_err(), "Should reject unregistered target state");
        assert!(
            result.unwrap_err().to_string().contains("not registered"),
            "Error should mention unregistered state"
        );
    }

    #[test]
    fn test_empty_trigger_name_rejection() {
        let mut sm = create_test_machine();

        let result = sm.add_transition(
            TestState::Idle,
            TestState::Running,
            "",
            None,
        );
        assert!(result.is_err(), "Should reject empty trigger name");
    }

    #[test]
    fn test_guard_receives_context() {
        static GUARD_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

        let guard = Arc::new(|ctx: &TransitionContext| {
            GUARD_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
            // Verify context fields are accessible
            assert!(
                ctx.metadata.contains_key("test_key"),
                "Guard should receive metadata"
            );
            true // Allow transition
        });

        let mut sm = StateMachine::new(TestState::Idle);
        sm.add_state(TestState::Running);
        sm.add_transition(TestState::Idle, TestState::Running, "test", Some(guard))
            .unwrap();

        let ctx = TransitionContext::new(Some("tester")).with_metadata("test_key", "test_value");
        sm.transition(TestState::Running, ctx).unwrap();

        assert_eq!(
            GUARD_CALL_COUNT.load(Ordering::SeqCst),
            1,
            "Guard should be called exactly once"
        );
    }

    #[test]
    fn test_multiple_guards_same_target() {
        let mut sm = StateMachine::new(TestState::Idle);
        sm.add_state(TestState::Running);

        // First guard: requires actor "alice"
        let guard_alice = Arc::new(|ctx: &TransitionContext| {
            ctx.actor_id.as_deref() == Some("alice")
        });
        sm.add_transition(
            TestState::Idle,
            TestState::Running,
            "start_alice",
            Some(guard_alice),
        )
        .unwrap();

        // Second guard: requires actor "bob"
        let guard_bob = Arc::new(|ctx: &TransitionContext| {
            ctx.actor_id.as_deref() == Some("bob")
        });
        sm.add_transition(
            TestState::Idle,
            TestState::Running,
            "start_bob",
            Some(guard_bob.clone()),
        )
        .unwrap();

        // Alice can use her trigger
        let result = sm.trigger(
            "start_alice",
            TransitionContext::new(Some("alice")),
        );
        assert!(result.is_ok(), "Alice's trigger should work");

        // Reset for bob test
        let mut sm2 = StateMachine::new(TestState::Idle);
        sm2.add_state(TestState::Running);
        sm2.add_transition(
            TestState::Idle,
            TestState::Running,
            "start_bob",
            Some(guard_bob),
        )
        .unwrap();

        let result = sm2.trigger("start_bob", TransitionContext::new(Some("bob")));
        assert!(result.is_ok(), "Bob's trigger should work");

        // Wrong actor fails
        let result =
            sm2.trigger("start_bob", TransitionContext::new(Some("charlie")));
        assert!(result.is_err(), "Charlie should fail Bob's guard");
    }
}
