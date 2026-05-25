//! Krastor Fuzz Core — Coverage-guided execution engine for Solana programs.
//!
//! ## Architecture
//! ```text
//! Fuzzer::run_one_round()
//!   ├─ random_action()         → pick random instruction + account params
//!   ├─ mutate_accounts()       → Solana-aware directed mutations
//!   ├─ LiteSVM::execute()      → deploy + construct + submit transaction
//!   ├─ check_invariants()      → user-defined post-condition checks
//!   └─ log_coverage()          → (optional) coverage bitmap collection
//! ```

pub mod fuzzer;
pub mod mutator;
pub use fuzzer::Fuzzer;
pub mod crash;
pub mod executor;
pub mod invariant;

use rand::Rng;
use serde::{Deserialize, Serialize};

// ============ FuzzAccount ============
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzAccount {
    /// Base58-encoded public key
    pub key: String,
    /// Account data as base64-encoded bytes
    pub data: Vec<u8>,
    /// Owner program (base58)
    pub owner: String,
    /// Lamports balance
    pub lamports: u64,
    /// Is this account rent-exempt?
    pub rent_epoch: u64,
    /// Is this account writable?
    pub is_writable: bool,
    /// Is this account a signer?
    pub is_signer: bool,
    /// PDA seeds if derived
    pub seeds: Option<Vec<Vec<u8>>>,
}

impl Default for FuzzAccount {
    fn default() -> Self {
        Self {
            key: String::new(),
            data: vec![0u8; 32],
            owner: "11111111111111111111111111111111".to_string(),
            lamports: 1_000_000,
            rent_epoch: u64::MAX,
            is_writable: true,
            is_signer: false,
            seeds: None,
        }
    }
}

impl FuzzAccount {
    pub fn random(rng: &mut impl Rng) -> Self {
        let data_len: usize = rng.gen_range(1..=1024);
        let mut data = vec![0u8; data_len];
        rng.fill(&mut data[..]);

        Self {
            key: bs58_encode(&random_bytes(rng, 32)),
            data,
            owner: bs58_encode(&random_bytes(rng, 32)),
            lamports: rng.gen_range(1..10_000_000),
            rent_epoch: u64::MAX,
            is_writable: rng.gen_bool(0.8),
            is_signer: rng.gen_bool(0.1),
            seeds: if rng.gen_bool(0.3) {
                Some(vec![random_bytes(rng, 16)])
            } else {
                None
            },
        }
    }

    /// Check if an account is rent-exempt based on current rent settings
    pub fn is_rent_exempt(&self) -> bool {
        // UNCERTAINTY: rent-exempt threshold calculation depends on exact Solana's
        // rent sysvar format. Current formula: data_len * rent_per_byte_year * 2 years
        // Correct implementation requires reading Rent sysvar or using LiteSVM helper.
        let min_lamports = self.data.len() as u64 * 3480 * 2; // approx rent
        self.lamports >= min_lamports && self.rent_epoch != 0
    }
}

// ============ FuzzAction ============
/// A single fuzzing action: one instruction invocation with specific accounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzAction {
    /// Anchor instruction discriminator (8 bytes, hex)
    pub ix_discriminator: [u8; 8],
    /// Instruction name (from IDL)
    pub ix_name: String,
    /// Program ID to invoke
    pub program_id: String,
    /// Accounts passed to the instruction
    pub accounts: Vec<FuzzAccount>,
    /// Serialized instruction data
    pub ix_data: Vec<u8>,
}

// ============ FuzzActionSequence ============
/// Full execution round: multiple instructions in sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzActionSequence {
    pub actions: Vec<FuzzAction>,
    pub initial_accounts: Vec<FuzzAccount>,
}

// ============ CoverageBitmap ============
/// AFL-style coverage bitmap (65536 entries is standard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageBitmap {
    /// Hit counts for each edge (reduce to 0-255 in AFL style)
    pub edges: Vec<u8>,
    /// Total edges with non-zero hit count
    pub covered_edges: usize,
}

impl Default for CoverageBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageBitmap {
    pub fn new() -> Self {
        Self {
            edges: vec![0u8; 65536],
            covered_edges: 0,
        }
    }

    /// Record an edge transition (prev → cur)
    pub fn record_edge(&mut self, prev: usize, cur: usize) -> bool {
        let idx = (prev ^ cur) % self.edges.len();
        let was_zero = self.edges[idx] == 0;
        if self.edges[idx] < u8::MAX {
            self.edges[idx] = self.edges[idx].saturating_add(1);
        }
        if was_zero && self.edges[idx] > 0 {
            self.covered_edges += 1;
        }
        was_zero // new edge discovered?
    }

    /// Check if this bitmap has new coverage compared to the global one
    pub fn has_new_coverage(&self, global: &CoverageBitmap) -> bool {
        self.edges
            .iter()
            .zip(global.edges.iter())
            .any(|(a, b)| a > b)
    }

    /// Merge global coverage with this bitmap
    pub fn merge(&mut self, global: &CoverageBitmap) {
        for (a, b) in self.edges.iter_mut().zip(global.edges.iter()) {
            *a = a.saturating_add(*b);
        }
    }
}

// ============ Helpers ============
fn random_bytes(rng: &mut impl Rng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.gen()).collect()
}

// Simple base58 encode (placeholder — real impl would use bs58 crate)
pub fn bs58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = String::new();
    let mut num = 0u128;
    let mut count = 0;
    for &byte in data {
        num = num * 256 + byte as u128;
        count += 1;
        if count >= 16 {
            while num > 0 {
                result.push(ALPHABET[(num % 58) as usize] as char);
                num /= 58;
            }
            count = 0;
        }
    }
    if result.is_empty() && data.is_empty() {
        result.push('1');
    }
    result
}
