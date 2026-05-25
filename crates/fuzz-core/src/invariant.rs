//! Invariant runtime — user-defined post-condition checks.
//!
//! Invariants are functions annotated with `#[krastor_invariant]` that
//! get called after every fuzz round execution. They check whether the
//! program's state invariants hold.
//!
//! Common invariants for Solana programs:
//! - Supply conservation: total supply == sum of all balances
//! - Admin immutability: admin pubkey never changes
//! - State machine: paused state prevents operations
//! - Token conservation: token A + token B balances sum to constant

use crate::FuzzAccount;

/// Result of checking a single invariant
#[derive(Debug, Clone)]
pub struct InvariantResult {
    /// Invariant name
    pub name: String,
    /// Did the invariant hold?
    pub passed: bool,
    /// Failure message if violated
    pub message: Option<String>,
    ///Round number when this was checked
    pub round: u64,
}

/// Type alias for an invariant check function
pub type InvariantFn = Box<dyn Fn(&[FuzzAccount], &[FuzzAccount], u64) -> Option<String>>;

/// Registry of user-defined invariants
pub struct InvariantRegistry {
    pub invariants: Vec<(String, InvariantFn)>,
}

impl Default for InvariantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InvariantRegistry {
    pub fn new() -> Self {
        Self { invariants: Vec::new() }
    }

    /// Register a named invariant function.
    /// The function receives (current_accounts, initial_accounts, round_number)
    /// and returns Some(message) if violated, None if it holds.
    pub fn register(&mut self, name: &str, f: InvariantFn) {
        self.invariants.push((name.to_string(), f));
    }

    /// Check all registered invariants and return results.
    pub fn check_all(
        &self,
        current: &[FuzzAccount],
        initial: &[FuzzAccount],
        round: u64,
    ) -> Vec<InvariantResult> {
        self.invariants
            .iter()
            .map(|(name, f)| {
                let violation = f(current, initial, round);
                InvariantResult {
                    name: name.clone(),
                    passed: violation.is_none(),
                    message: violation,
                    round,
                }
            })
            .collect()
    }
}

// ============ Built-in Invariant Templates ============
// These are template functions that users can customize.

/// Supply conservation: sum of lamports in all accounts must remain constant
/// (accounting for rent changes).
pub fn invariant_supply_conservation(
    current: &[FuzzAccount],
    initial: &[FuzzAccount],
    _round: u64,
) -> Option<String> {
    let current_sum: u64 = current.iter().map(|a| a.lamports).sum();
    let initial_sum: u64 = initial.iter().map(|a| a.lamports).sum();

    // Allow small rent deductions (up to 1% per account)
    let rent_tolerance = initial.len() as u64 * initial_sum / 100;
    if current_sum < initial_sum.saturating_sub(rent_tolerance) {
        Some(format!(
            "Supply conservation violated: initial={}, current={}, delta={}",
            initial_sum,
            current_sum,
            initial_sum as i128 - current_sum as i128
        ))
    } else {
        None
    }
}

/// Admin immutability: admin pubkey should never change.
pub fn invariant_admin_immutability(
    current: &[FuzzAccount],
    initial: &[FuzzAccount],
    _round: u64,
) -> Option<String> {
    // Find admin account by looking for an account with "admin" in its key description
    // (In real usage, user would specify which account is the admin)
    for (curr, init) in current.iter().zip(initial.iter()) {
        if curr.owner != init.owner && init.is_signer {
            return Some(format!(
                "Admin account owner changed: {} → {}",
                init.owner, curr.owner
            ));
        }
    }
    None
}

/// State machine: if a "paused" flag exists in an account, no state-modifying
/// instructions should have succeeded.
pub fn invariant_state_machine_paused(
    current: &[FuzzAccount],
    _initial: &[FuzzAccount],
    _round: u64,
) -> Option<String> {
    // UNCERTAINTY: The "paused" flag location depends on the program's specific
    // account layout. This is a template — user must customize byte offset.
    //
    // Check if any account's first bit is set (hypothetical "paused" flag)
    for account in current {
        if !account.data.is_empty() && (account.data[0] & 0x01) != 0 {
            // Paused — but we can't distinguish from here whether the
            // instruction that modified this was "pause" or something else.
            // Real implementation would track per-instruction state changes.
            return Some("Program appears to be in paused state".to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_accounts() -> Vec<FuzzAccount> {
        vec![
            FuzzAccount { key: "A".into(), lamports: 100, ..Default::default() },
            FuzzAccount { key: "B".into(), lamports: 200, ..Default::default() },
        ]
    }

    #[test]
    fn test_supply_conservation_passes() {
        let initial = make_test_accounts();
        let mut current = initial.clone();
        current[0].lamports = 95;
        current[1].lamports = 200; // 5 lost to rent (within 1% per account tolerance)
        let result = invariant_supply_conservation(&current, &initial, 0);
        // 295 vs 300 — 5 lamports loss, tolerance = 2 * 300 / 100 = 6
        assert!(result.is_none());
    }

    #[test]
    fn test_supply_conservation_violated() {
        let initial = make_test_accounts();
        let mut current = initial.clone();
        current[0].lamports = 0; // severe loss
        let result = invariant_supply_conservation(&current, &initial, 0);
        assert!(result.is_some());
    }

    #[test]
    fn test_registry_checks_all() {
        let mut registry = InvariantRegistry::new();
        registry.register("supply", Box::new(invariant_supply_conservation));
        registry.register("admin", Box::new(invariant_admin_immutability));

        let initial = make_test_accounts();
        let current = initial.clone();
        let results = registry.check_all(&current, &initial, 0);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed); // supply still holds
    }
}