//! Account mutators — Solana-aware directed mutations for vulnerability discovery.
//!
//! Each mutation targets a specific class of Solana security vulnerabilities:
//! - `mutate_owner` → authorization bypass (missing owner check)
//! - `zero_lamports` → rent exemption bypass (missing rent check)
//! - `clear_data` → empty account attack (missing data length check)
//! - `flip_data_bits` → state corruption (general data integrity)
//! - `swap_signer` → signer confusion (missing signer check)
//! - `mutate_seeds` → PDA derivation bypass (missing seed validation)

use rand::Rng;
use crate::FuzzAccount;

/// Configuration for mutation probabilities.
/// Each probability is in the range [0.0, 1.0].
#[derive(Debug, Clone)]
pub struct MutationConfig {
    /// Probability of flipping bits in account data
    pub flip_data: f64,
    /// Probability of replacing the owner field
    pub replace_owner: f64,
    /// Probability of zeroing lamports
    pub zero_lamports: f64,
    /// Probability of clearing all data
    pub clear_data: f64,
    /// Probability of swapping signer status
    pub swap_signer: f64,
    /// Probability of mutating PDA seeds
    pub mutate_seeds: f64,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            flip_data: 0.40,
            replace_owner: 0.10,
            zero_lamports: 0.10,
            clear_data: 0.05,
            swap_signer: 0.15,
            mutate_seeds: 0.10,
        }
    }
}

/// Apply Solana-aware directed mutations to a set of accounts.
/// Returns the number of mutations actually applied.
pub fn mutate_accounts(accounts: &mut [FuzzAccount], config: &MutationConfig, rng: &mut impl Rng) -> usize {
    let mut mutation_count = 0;
    for account in accounts.iter_mut() {
        // Only mutate writable accounts (immutable accounts shouldn't change)
        if !account.is_writable {
            continue;
        }

        if rng.gen_bool(config.flip_data) {
            mutate_flip_data_bits(account, rng);
            mutation_count += 1;
        }
        if rng.gen_bool(config.replace_owner) {
            mutate_owner(account, rng);
            mutation_count += 1;
        }
        if rng.gen_bool(config.zero_lamports) {
            mutate_zero_lamports(account);
            mutation_count += 1;
        }
        if rng.gen_bool(config.clear_data) {
            mutate_clear_data(account);
            mutation_count += 1;
        }
        if rng.gen_bool(config.swap_signer) {
            mutate_swap_signer(account);
            mutation_count += 1;
        }
        if rng.gen_bool(config.mutate_seeds) {
            mutate_seeds(account, rng);
            mutation_count += 1;
        }
    }
    mutation_count
}

/// Authorization bypass: replace owner with a random program.
/// Targets: missing `if ctx.accounts.x.owner == program_id` check.
fn mutate_owner(account: &mut FuzzAccount, rng: &mut impl Rng) {
    // 40% chance: set to a completely random owner
    // 35% chance: set to system program (common target for UPGRADABLE bypass)
    // 25% chance: set to an empty owner (like SOL transfer PDAs)
    let roll = rng.gen_range(0.0..1.0);
    if roll < 0.40 {
        account.owner = crate::bs58_encode(&(0..32).map(|_| rng.gen()).collect::<Vec<u8>>());
    } else if roll < 0.75 {
        // System program (common auth bypass target)
        account.owner = "11111111111111111111111111111111".to_string();
    } else {
        // Empty owner — invalid state
        account.owner = String::new();
    }
}

/// Rent exemption bypass: zero out lamports.
/// Targets: missing `is_rent_exempt` check before operating on account.
fn mutate_zero_lamports(account: &mut FuzzAccount) {
    account.lamports = 0;
    account.rent_epoch = 0;
}

/// Empty account attack: clear all data bytes.
/// Targets: missing `data.len() > 0` or `data.len() >= EXPECTED_SIZE` check.
fn mutate_clear_data(account: &mut FuzzAccount) {
    account.data.clear();
}

/// General state corruption: flip random bits in account data.
/// Targets: missing data validation, state invariants broken by bit corruption.
fn mutate_flip_data_bits(account: &mut FuzzAccount, rng: &mut impl Rng) {
    if account.data.is_empty() {
        return;
    }

    let bit_count = rng.gen_range(1..=usize::min(8, account.data.len() * 8));
    for _ in 0..bit_count {
        let byte_idx = rng.gen_range(0..account.data.len());
        let bit_idx = rng.gen_range(0..8);
        account.data[byte_idx] ^= 1 << bit_idx;
    }
}

/// Signer confusion: toggle signer flag.
/// Targets: missing `is_signer` validation.
fn mutate_swap_signer(account: &mut FuzzAccount) {
    account.is_signer = !account.is_signer;
}

/// PDA derivation bypass: shuffle or corrupt seeds.
/// Targets: missing seed validation or PDA derivation verification.
fn mutate_seeds(account: &mut FuzzAccount, rng: &mut impl Rng) {
    if let Some(ref mut seeds) = account.seeds {
        if seeds.is_empty() {
            return;
        }
        // Either shuffle seed bytes, or remove a seed entirely
        if rng.gen_bool(0.5) {
            // Shuffle bytes in a random seed element
            let idx = rng.gen_range(0..seeds.len());
            for byte in seeds[idx].iter_mut() {
                *byte ^= rng.gen::<u8>();
            }
        } else {
            // Remove a random seed (PDA derivation will break)
            seeds.remove(rng.gen_range(0..seeds.len()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_mutate_owner_changes_owner() {
        let mut account = FuzzAccount::default();
        let original = account.owner.clone();
        mutate_owner(&mut account, &mut thread_rng());
        assert_ne!(account.owner, original);
    }

    #[test]
    fn test_zero_lamports() {
        let mut account = FuzzAccount::default();
        account.lamports = 500;
        mutate_zero_lamports(&mut account);
        assert_eq!(account.lamports, 0);
    }

    #[test]
    fn test_clear_data() {
        let mut account = FuzzAccount::default();
        account.data = vec![1, 2, 3, 4];
        mutate_clear_data(&mut account);
        assert!(account.data.is_empty());
    }

    #[test]
    fn test_mutate_accounts_returns_count() {
        let mut accounts = vec![FuzzAccount::default(); 10];
        let config = MutationConfig { flip_data: 1.0, replace_owner: 0.0, zero_lamports: 0.0, clear_data: 0.0, swap_signer: 0.0, mutate_seeds: 0.0 };
        let count = mutate_accounts(&mut accounts, &config, &mut thread_rng());
        assert!(count > 0);
    }
}