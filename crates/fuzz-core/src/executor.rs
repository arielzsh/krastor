//! LiteSVM execution wrapper — deploys programs, constructs transactions,
//! submits to the embedded Solana runtime, and collects results.
//!
//! LiteSVM is an embedded, pure-Rust Solana runtime. No external validator process needed.

use crate::{FuzzAccount, FuzzAction};
use anyhow::{Result, anyhow};
use litesvm::LiteSVM;
use solana_account::{Account, ReadableAccount};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// Result of a single instruction execution
#[derive(Debug, Clone)]
pub struct InstructionResult {
    pub success: bool,
    pub error: Option<String>,
    pub compute_units: u64,
    pub logs: Vec<String>,
}

/// A persistent LiteSVM executor that holds the Solana runtime,
/// deployed program, payer keypair, and account state across
/// multiple fuzz rounds.
pub struct LiteSvmExecutor {
    svm: LiteSVM,
    payer: Keypair,
    program_id: Pubkey,
}

impl LiteSvmExecutor {
    /// Create a new executor, deploy the program, and fund the payer.
    pub fn new(program_id_str: &str, program_bytes: &[u8]) -> Result<Self> {
        let mut svm = LiteSVM::new();

        let program_id = Pubkey::try_from(program_id_str)
            .map_err(|_| anyhow!("Invalid program ID: {}", program_id_str))?;

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000)
            .map_err(|e| anyhow!("Airdrop failed: {:?}", e))?;

        svm.add_program(program_id, program_bytes)
            .map_err(|e| anyhow!("Failed to deploy program {}: {}", program_id_str, e))?;

        Ok(Self { svm, payer, program_id })
    }

    /// Load a program binary from disk and create the executor.
    pub fn from_file(program_id_str: &str, so_path: &str) -> Result<Self> {
        let bytes = std::fs::read(so_path)
            .map_err(|e| anyhow!("Failed to read program binary from {}: {}", so_path, e))?;
        Self::new(program_id_str, &bytes)
    }

    /// Returns the program ID being fuzzed.
    pub fn program_id(&self) -> Pubkey {
        self.program_id
    }

    /// Returns the payer's public key.
    pub fn payer_pubkey(&self) -> Pubkey {
        self.payer.pubkey()
    }

    /// Set up accounts in the LiteSVM from a slice of FuzzAccount.
    /// This creates or overwrites accounts in the VM.
    pub fn set_accounts(&mut self, accounts: &[FuzzAccount]) -> Result<()> {
        for acc in accounts {
            let pubkey = Pubkey::try_from(acc.key.as_str())
                .map_err(|_| anyhow!("Invalid pubkey: {}", acc.key))?;
            let owner = Pubkey::try_from(acc.owner.as_str())
                .map_err(|_| anyhow!("Invalid owner: {}", acc.owner))?;

            let account = Account {
                lamports: acc.lamports,
                data: acc.data.clone(),
                owner,
                executable: false,
                rent_epoch: acc.rent_epoch,
            };
            self.svm.set_account(pubkey, account.clone())
                .map_err(|e| anyhow!("Failed to set account {}: {}", acc.key, e))?;
        }
        Ok(())
    }

    /// Read account state back from LiteSVM into FuzzAccount structs.
    pub fn read_accounts(&self, accounts: &mut [FuzzAccount]) -> Result<()> {
        for acc in accounts.iter_mut() {
            let pubkey = Pubkey::try_from(acc.key.as_str())
                .map_err(|_| anyhow!("Invalid pubkey: {}", acc.key))?;
            if let Some(svm_acc) = self.svm.get_account(&pubkey) {
                acc.lamports = svm_acc.lamports();
                acc.data = svm_acc.data().to_vec();
                acc.owner = svm_acc.owner().to_string();
                acc.rent_epoch = svm_acc.rent_epoch();
            }
        }
        Ok(())
    }

    /// Execute a sequence of fuzz actions, collecting results for each.
    ///
    /// On transaction failure, rolls back the VM account state to the
    /// pre-sequence snapshot and returns partial results.
    pub fn execute_sequence(
        &mut self,
        actions: &[FuzzAction],
        accounts: &mut [FuzzAccount],
    ) -> Result<Vec<InstructionResult>> {
        // Snapshot current VM account state for rollback
        let snapshot_accounts = accounts.to_vec();

        let mut results = Vec::new();

        for action in actions {
            let program_id = Pubkey::try_from(action.program_id.as_str())
                .map_err(|_| anyhow!("Invalid program_id in action: {}", action.program_id))?;

            // Build AccountMeta list from FuzzAction accounts
            let account_metas: Vec<AccountMeta> = action
                .accounts
                .iter()
                .map(|a| {
                    let pk = Pubkey::try_from(a.key.as_str()).unwrap_or_default();
                    if a.is_writable && a.is_signer {
                        AccountMeta::new(pk, true)
                    } else if a.is_writable {
                        AccountMeta::new(pk, false)
                    } else {
                        AccountMeta::new_readonly(pk, a.is_signer)
                    }
                })
                .collect();

            let ix = Instruction {
                program_id,
                accounts: account_metas,
                data: action.ix_data.clone(),
            };

            // Build and sign transaction
            let msg = Message::new(&[ix], Some(&self.payer.pubkey()));
            let tx = Transaction::new(&[&self.payer], msg, self.svm.latest_blockhash());

            match self.svm.send_transaction(tx) {
                Ok(meta) => {
                    results.push(InstructionResult {
                        success: true,
                        error: None,
                        compute_units: meta.compute_units_consumed,
                        logs: meta.logs,
                    });
                    // Sync VM state back to FuzzAccount
                    self.read_accounts(accounts)?;
                }
                Err(e) => {
                    // Rollback: restore VM accounts to snapshot
                    if let Err(restore_err) = self.set_accounts(&snapshot_accounts) {
                        eprintln!("WARN: Failed to restore account snapshot: {}", restore_err);
                    }
                    // Restore FuzzAccount slice
                    for (i, snap) in snapshot_accounts.iter().enumerate() {
                        if i < accounts.len() {
                            accounts[i] = snap.clone();
                        }
                    }

                    results.push(InstructionResult {
                        success: false,
                        error: Some(format!("{:?}", e)),
                        compute_units: 0,
                        logs: vec![],
                    });

                    // Return partial results — caller decides if this is a crash
                    return Ok(results);
                }
            }
        }

        Ok(results)
    }

    /// Access the underlying LiteSVM for advanced operations.
    pub fn svm_mut(&mut self) -> &mut LiteSVM {
        &mut self.svm
    }
}

/// Load a program binary from the file system.
pub fn load_program_binary(program_name: &str) -> Result<Vec<u8>> {
    let path = format!("target/deploy/{}.so", program_name);

    if !std::path::Path::new(&path).exists() {
        return Err(anyhow!("Program binary not found at {}", path));
    }

    std::fs::read(&path).map_err(|e| anyhow!("Failed to read program binary: {}", e))
}

/// Check if an execution error is a crash (not a graceful program error).
pub fn is_crash_error(error: &str) -> bool {
    error.contains("access violation")
        || error.contains("out of bounds")
        || error.contains("arithmetic overflow")
        || error.contains("invalid account data")
        || error.contains("not rent exempt")
        || error.contains("owner mismatch")
        || error.contains("signer mismatch")
        || error.contains("AccountNotFound")
        || error.contains("InstructionError")
        || error.contains("PrivilegeEscalation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FuzzAccount;

    #[test]
    fn test_is_crash_error() {
        assert!(is_crash_error("access violation at 0x1234"));
        assert!(is_crash_error("arithmetic overflow"));
        assert!(is_crash_error("InstructionError"));
        assert!(!is_crash_error("insufficient funds"));
    }

    #[test]
    fn test_load_program_binary_missing() {
        let result = load_program_binary("nonexistent_program");
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_new_with_empty_program() {
        // A minimal valid ELF just for instantiation testing
        // LiteSVM expects a valid ELF; an empty slice will fail gracefully
        let result = LiteSvmExecutor::new(
            "Prog111111111111111111111111111111111",
            &[],
        );
        assert!(result.is_err()); // empty bytes should fail to deploy
    }
}