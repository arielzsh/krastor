//! Vulnerable Anchor Program — 3 known bugs for Krastor validation.
//!
//! ⚠️  DEMO ONLY — NOT FOR PRODUCTION USE
//!
//! ## Bugs & Proptest Comparison
//!
//! | # | Bug | Location | Proptest | Krastor |
//! |---|-----|----------|----------|--------|
//! | 1 | Arithmetic overflow | `deposit()`: `vault.total_supply += amount` | ~0% — random u64 rarely hits overflow | `flip_data` 40%/round targets edge values |
//! | 2 | Authorization bypass | `withdraw()`: no owner check | 0% — doesn't model "who should be authorized" | `replace_owner` 10%/round × `swap_signer` 15%/round |
//! | 3 | Borrow counter race | `flash_loan()`: counter updated after transfer | ~0% — needs exact interleaved timing | auto-sequence discovery generates flash_loan patterns |
//!
//! Proptest treats each instruction parameter as independent random values.
//! It cannot correlate account identities across instruction calls, cannot
//! target overflow boundaries, and has no concept of transaction ordering
//! within a sequence. Krastor's Solana-aware mutations (owner, signer, seeds,
//! lamports) directly attack the program's authorization model.

use anchor_lang::prelude::*;

declare_id!("VulnProg111111111111111111111111111111111111");

#[program]
pub mod vulnerable {
    use super::*;

    pub fn deposit(ctx: Context<DepositCtx>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG 1: unchecked addition
        vault.total_supply += amount;
        vault.balances[0] += amount;
        Ok(())
    }

    pub fn withdraw(ctx: Context<WithdrawCtx>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG 2: no owner check
        vault.total_supply -= amount;
        vault.balances[0] -= amount;
        Ok(())
    }

    pub fn initialize(ctx: Context<InitializeCtx>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.authority.key();
        vault.total_supply = 0;
        vault.balances = vec![0; 10];
        vault.total_borrowed = 0;
        Ok(())
    }

    pub fn flash_loan(ctx: Context<FlashLoanCtx>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG 3: borrow counter updated after transfer
        vault.balances[0] -= amount;
        vault.total_borrowed += amount;
        vault.balances[0] += amount;
        vault.total_borrowed -= amount;
        Ok(())
    }
}

#[derive(Accounts)] pub struct InitializeCtx<'info> {
    #[account(init, payer = authority, space = Vault::LEN)] pub vault: Account<'info, Vault>,
    #[account(mut)] pub authority: Signer<'info>, pub system_program: Program<'info, System>,
}
#[derive(Accounts)] pub struct DepositCtx<'info> { #[account(mut)] pub vault: Account<'info, Vault>, }
#[derive(Accounts)] pub struct WithdrawCtx<'info> {
    #[account(mut)] pub vault: Account<'info, Vault>, #[account(mut)] pub authority: Signer<'info>,
}
#[derive(Accounts)] pub struct FlashLoanCtx<'info> {
    #[account(mut)] pub vault: Account<'info, Vault>, #[account(mut)] pub borrower: Signer<'info>,
}

#[account] pub struct Vault {
    pub owner: Pubkey, pub total_supply: u64, pub total_borrowed: u64, pub balances: Vec<u64>,
}
impl Vault { pub const LEN: usize = 8 + 32 + 8 + 8 + 4 + 80; }

#[error_code] pub enum ErrorCode {
    #[msg("Insufficient balance")] InsufficientBalance,
    #[msg("Unauthorized")] Unauthorized,
    #[msg("Overflow")] Overflow,
}