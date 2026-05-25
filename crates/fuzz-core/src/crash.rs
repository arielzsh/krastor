//! Crash recording — serialization, shrinking, and reproducibility.
//!
//! When a crash is found (execution error or invariant violation), the
//! triggering sequence is saved as a JSON record. The `shrink` function
//! reduces the sequence to the minimal reproducible subsequence.

use crate::{FuzzAction, FuzzActionSequence};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A crash record — the minimum information needed to reproduce a failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    /// The original (pre-shrinking) action sequence
    pub original_sequence: FuzzActionSequence,
    /// The minimal (post-shrinking) action sequence
    pub minimal_sequence: FuzzActionSequence,
    /// Human-readable crash description
    pub description: String,
    /// Error type classification
    pub crash_type: CrashType,
    /// Round number when discovered
    pub discovered_at_round: u64,
    /// Timestamp
    pub timestamp: String,
    /// Number of shrunken instructions removed
    pub instructions_removed: usize,
}

/// Types of crashes the fuzzer can detect
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashType {
    /// Transaction execution failed (panic, arithmetic overflow, etc.)
    ExecutionError,
    /// A user-defined invariant was violated
    InvariantViolation(String),
    /// Excessive compute unit consumption
    ComputeBudgetExceeded,
    /// Unexpected account state change
    StateCorruption,
}

impl std::fmt::Display for CrashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrashType::ExecutionError => write!(f, "ExecutionError"),
            CrashType::InvariantViolation(s) => write!(f, "InvariantViolation({})", s),
            CrashType::ComputeBudgetExceeded => write!(f, "ComputeBudgetExceeded"),
            CrashType::StateCorruption => write!(f, "StateCorruption"),
        }
    }
}

impl CrashRecord {
    /// Create a new crash record from a sequence.
    pub fn new(
        sequence: FuzzActionSequence,
        description: String,
        crash_type: CrashType,
        round: u64,
    ) -> Self {
        Self {
            original_sequence: sequence.clone(),
            minimal_sequence: sequence,
            description,
            crash_type,
            discovered_at_round: round,
            timestamp: chrono::Utc::now().to_rfc3339(),
            instructions_removed: 0,
        }
    }

    /// Save crash record to JSON file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load crash record from JSON file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

/// Binary search + greedy shrinking: remove instructions one by one
/// until only the minimal crash-triggering subsequence remains.
///
/// Algorithm:
/// 1. Binary delete: try removing the first half. If crash still happens, keep halving.
/// 2. Greedy delete: for each remaining instruction, try removing it.
/// 3. Parameter minimization: for each retained instruction, try simplifying params.
///
/// Returns the minimal sequence and count of removed instructions.
pub fn shrink(
    sequence: &FuzzActionSequence,
    crash_detector: &dyn Fn(&FuzzActionSequence) -> bool,
) -> (FuzzActionSequence, usize) {
    let mut minimal = sequence.actions.clone();
    let initial_len = minimal.len();
    let mut _removed_count = 0;

    // Pass 1: binary deletion
    let mut step = minimal.len();
    while step > 1 {
        step = step.div_ceil(2);
        if step < minimal.len() {
            let candidate: Vec<FuzzAction> = minimal[step..].to_vec();
            let candidate_seq = FuzzActionSequence {
                actions: candidate,
                initial_accounts: sequence.initial_accounts.clone(),
            };
            if crash_detector(&candidate_seq) && candidate_seq.actions.len() < minimal.len() {
                minimal = candidate_seq.actions;
                _removed_count += step;
            }
        }
    }

    // Pass 2: greedy single-instruction deletion
    let mut i = 0;
    while i < minimal.len() {
        let mut candidate = minimal.clone();
        candidate.remove(i);
        let candidate_seq = FuzzActionSequence {
            actions: candidate,
            initial_accounts: sequence.initial_accounts.clone(),
        };
        if crash_detector(&candidate_seq) {
            minimal.remove(i);
            _removed_count += 1;
        } else {
            i += 1;
        }
    }

    // Pass 3: parameter minimization
    let mut changed = true;
    while changed {
        changed = false;
        let mut idx = 0;
        while idx < minimal.len() {
            // Try halving ix_data
            if minimal[idx].ix_data.len() > 8 {
                let half = minimal[idx].ix_data.len() / 2;
                let original = minimal[idx].ix_data.clone();
                minimal[idx].ix_data.truncate(std::cmp::max(8usize, half));
                let candidate_seq = FuzzActionSequence {
                    actions: minimal.clone(),
                    initial_accounts: sequence.initial_accounts.clone(),
                };
                if crash_detector(&candidate_seq) {
                    _removed_count += 1;
                    changed = true;
                    break;
                } else {
                    minimal[idx].ix_data = original;
                }
            }
            // Try removing an account
            if minimal[idx].accounts.len() > 1 {
                let original = minimal[idx].accounts.clone();
                minimal[idx].accounts.pop();
                let candidate_seq = FuzzActionSequence {
                    actions: minimal.clone(),
                    initial_accounts: sequence.initial_accounts.clone(),
                };
                if crash_detector(&candidate_seq) {
                    _removed_count += 1;
                    changed = true;
                    break;
                } else {
                    minimal[idx].accounts = original;
                }
            }
            idx += 1;
        }
    }

    let final_len = minimal.len();
    let minimal_seq = FuzzActionSequence {
        actions: minimal,
        initial_accounts: sequence.initial_accounts.clone(),
    };

    (minimal_seq, initial_len - final_len)
}

// UNCERTAINTY: chrono crate needs to be in Cargo.toml dependencies.
// Add: chrono = { version = "0.4", features = ["serde"] }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FuzzAccount;

    fn test_actions() -> Vec<FuzzAction> {
        (0..10)
            .map(|i| FuzzAction {
                ix_discriminator: [i as u8; 8],
                ix_name: format!("ix_{}", i),
                program_id: "Test".into(),
                accounts: vec![FuzzAccount::default()],
                ix_data: vec![0u8; 32],
            })
            .collect()
    }

    #[test]
    fn test_shrink_binary_delete() {
        let actions = test_actions();
        let seq = FuzzActionSequence {
            actions: actions.clone(),
            initial_accounts: vec![],
        };

        // Detector: crash if sequence has >= 1 actions (always true after any delete)
        let detector = |s: &FuzzActionSequence| !s.actions.is_empty();

        let (minimal, removed) = shrink(&seq, &detector);
        assert_eq!(minimal.actions.len(), 1);
        assert!(removed > 0);
    }

    #[test]
    fn test_crash_record_serialization() {
        let record = CrashRecord {
            original_sequence: FuzzActionSequence {
                actions: vec![],
                initial_accounts: vec![],
            },
            minimal_sequence: FuzzActionSequence {
                actions: vec![],
                initial_accounts: vec![],
            },
            description: "test crash".into(),
            crash_type: CrashType::ExecutionError,
            discovered_at_round: 42,
            timestamp: "2026-01-01T00:00:00Z".into(),
            instructions_removed: 5,
        };

        let json = serde_json::to_string(&record).unwrap();
        let decoded: CrashRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.description, "test crash");
        assert_eq!(decoded.instructions_removed, 5);
    }
}
