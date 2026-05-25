//! Fuzzer — main fuzzing engine that orchestrates rounds of random actions,
//! account mutations, LiteSVM execution, and invariant checking.

use crate::crash::CrashRecord;
use crate::executor::LiteSvmExecutor;
use crate::invariant::{InvariantRegistry, InvariantResult};
use crate::mutator::{mutate_accounts, MutationConfig};
use crate::{CoverageBitmap, FuzzAccount, FuzzAction, FuzzActionSequence};
use rand::Rng;

/// Main fuzzer state machine.
pub struct Fuzzer {
    /// Random number generator
    pub rng: Box<dyn rand::RngCore>,
    /// Current set of fuzzing accounts
    pub accounts: Vec<FuzzAccount>,
    /// Mutation probability configuration
    pub mutation_config: MutationConfig,
    /// Global coverage bitmap
    pub global_coverage: CoverageBitmap,
    /// Invariant registry (user-defined checks)
    pub invariants: InvariantRegistry,
    /// Number of rounds executed
    pub round_count: u64,
    /// Number of crashes found
    pub crash_count: u64,
    /// Crash records for reproducibility
    pub crashes: Vec<CrashRecord>,
    /// Seed inputs (inputs that discovered new coverage)
    pub seeds: Vec<FuzzActionSequence>,
    /// Max sequence length per round
    pub max_sequence_length: usize,
    /// Which instructions are available (from IDL)
    pub available_instructions: Vec<(String, [u8; 8])>, // (name, discriminator)
    /// Program ID under test
    pub program_id: String,
    /// LiteSVM execution engine (deploys program, executes transactions)
    pub executor: Option<LiteSvmExecutor>,
    /// Program binary bytes (loaded once, reused for executor reset)
    pub program_bytes: Option<Vec<u8>>,
}

impl Fuzzer {
    pub fn new(program_id: String) -> Self {
        Self {
            rng: Box::new(rand::thread_rng()),
            accounts: Vec::new(),
            mutation_config: MutationConfig::default(),
            global_coverage: CoverageBitmap::new(),
            invariants: InvariantRegistry::new(),
            round_count: 0,
            crash_count: 0,
            crashes: Vec::new(),
            seeds: Vec::new(),
            max_sequence_length: 10,
            available_instructions: Vec::new(),
            program_id,
            executor: None,
            program_bytes: None,
        }
    }

    /// Load and deploy the program binary, initialising the LiteSVM executor.
    pub fn deploy_program(&mut self, program_bytes: Vec<u8>) -> anyhow::Result<()> {
        self.program_bytes = Some(program_bytes.clone());
        let executor = LiteSvmExecutor::new(&self.program_id, &program_bytes)?;
        self.executor = Some(executor);
        Ok(())
    }

    /// Load program from a .so file.
    pub fn deploy_program_from_file(&mut self, so_path: &str) -> anyhow::Result<()> {
        let bytes = crate::executor::load_program_binary(so_path)?;
        self.deploy_program(bytes)
    }

    /// Reset the executor to a fresh state. Useful after a crash round
    /// to ensure clean VM state.
    pub fn reset_executor(&mut self) -> anyhow::Result<()> {
        if let Some(bytes) = &self.program_bytes {
            let executor = LiteSvmExecutor::new(&self.program_id, bytes)?;
            self.executor = Some(executor);
        }
        Ok(())
    }

    /// Register an instruction that the fuzzer can randomly select.
    pub fn register_instruction(&mut self, name: &str, discriminator: [u8; 8]) {
        self.available_instructions
            .push((name.to_string(), discriminator));
    }

    /// Generate a random action: pick a random instruction + random account params.
    pub fn random_action(&mut self) -> FuzzAction {
        if self.available_instructions.is_empty() {
            return FuzzAction {
                ix_discriminator: [0u8; 8],
                ix_name: "noop".into(),
                program_id: self.program_id.clone(),
                accounts: vec![],
                ix_data: vec![],
            };
        }

        let idx = self.rng.gen_range(0..self.available_instructions.len());
        let (name, disc) = self.available_instructions[idx].clone();

        // Pick random subset of accounts
        let account_count = self.rng.gen_range(1..=usize::min(self.accounts.len(), 8));
        let mut used_indices = std::collections::HashSet::new();
        let mut selected_accounts = Vec::new();
        while selected_accounts.len() < account_count {
            let i = self.rng.gen_range(0..self.accounts.len());
            if used_indices.insert(i) {
                selected_accounts.push(self.accounts[i].clone());
            }
        }

        // Generate random instruction data (minimal: just discriminator + noise)
        let data_len = self.rng.gen_range(8..=256);
        let mut ix_data = vec![0u8; data_len];
        ix_data[..8].copy_from_slice(&disc);
        self.rng.fill_bytes(&mut ix_data[8..]);

        FuzzAction {
            ix_discriminator: disc,
            ix_name: name,
            program_id: self.program_id.clone(),
            accounts: selected_accounts,
            ix_data,
        }
    }

    /// Execute one complete fuzz round:
    /// 1. Generate random sequence of actions
    /// 2. Mutate accounts
    /// 3. Set up accounts in LiteSVM and execute
    /// 4. Check invariants
    /// 5. Collect coverage
    pub fn run_one_round(&mut self) -> FuzzRoundResult {
        self.round_count += 1;

        // 1. Generate sequence
        let seq_len = self.rng.gen_range(1..=self.max_sequence_length);
        let actions: Vec<FuzzAction> = (0..seq_len).map(|_| self.random_action()).collect();
        let sequence = FuzzActionSequence {
            actions: actions.clone(),
            initial_accounts: self.accounts.clone(),
        };

        // 2. Mutate accounts
        let mut working_accounts = self.accounts.clone();
        mutate_accounts(&mut working_accounts, &self.mutation_config, &mut self.rng);

        // 3. Execute via LiteSVM (real execution)
        let execution_result = match &mut self.executor {
            Some(executor) => {
                // Set up current working accounts in the VM
                if let Err(e) = executor.set_accounts(&working_accounts) {
                    Err(anyhow::anyhow!("Failed to set accounts: {}", e))
                } else {
                    executor.execute_sequence(&actions, &mut working_accounts)
                }
            }
            None => {
                // Fallback: no executor configured, treat as error
                Err(anyhow::anyhow!(
                    "No executor configured — call deploy_program() first"
                ))
            }
        };

        // 4. Check invariants
        let mut invariant_results = Vec::new();
        let is_crash = execution_result.is_err();
        if !is_crash {
            invariant_results =
                self.invariants
                    .check_all(&working_accounts, &self.accounts, self.round_count);
        } else {
            // On crash, reset the executor for the next round
            let _ = self.reset_executor();
        }

        // 5. Coverage (via instrumentor when available)
        let new_coverage: Option<CoverageBitmap> = None;

        FuzzRoundResult {
            round: self.round_count,
            sequence,
            accounts_after: working_accounts,
            execution_success: execution_result.is_ok(),
            execution_error: execution_result.err().map(|e| e.to_string()),
            invariant_results,
            is_crash,
            new_coverage,
        }
    }
}

/// Result of a single fuzz round
pub struct FuzzRoundResult {
    pub round: u64,
    pub sequence: FuzzActionSequence,
    pub accounts_after: Vec<FuzzAccount>,
    pub execution_success: bool,
    pub execution_error: Option<String>,
    pub invariant_results: Vec<InvariantResult>,
    pub is_crash: bool,
    pub new_coverage: Option<CoverageBitmap>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    #[test]
    fn test_random_action_picks_instruction() {
        let mut fuzzer = Fuzzer::new("TestProg11111111111111111111111111111".into());
        fuzzer.rng = Box::new(SmallRng::seed_from_u64(42));
        fuzzer.accounts = vec![FuzzAccount::default(); 5];
        fuzzer.register_instruction("deposit", [1, 0, 0, 0, 0, 0, 0, 0]);
        fuzzer.register_instruction("withdraw", [2, 0, 0, 0, 0, 0, 0, 0]);

        let action = fuzzer.random_action();
        assert!(!action.ix_name.is_empty());
        assert!(!action.accounts.is_empty());
    }

    #[test]
    fn test_run_one_round_increments_counter() {
        let mut fuzzer = Fuzzer::new("TestProg11111111111111111111111111111".into());
        fuzzer.rng = Box::new(SmallRng::seed_from_u64(42));
        fuzzer.accounts = vec![FuzzAccount::default(); 3];
        fuzzer.register_instruction("transfer", [3, 0, 0, 0, 0, 0, 0, 0]);

        assert_eq!(fuzzer.round_count, 0);
        let _result = fuzzer.run_one_round();
        assert_eq!(fuzzer.round_count, 1);
    }
}
