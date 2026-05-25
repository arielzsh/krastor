//! # 🦭 03-stock — Micro-Fractional Equity Distribution Platform
//!
//! ⚠️  **DEMO ONLY — NOT FOR PRODUCTION USE. Contains intentional bugs.**
//!
//! A Token 2022-based fractional stock platform with:
//! - Transfer Hook (market hours enforcement + dynamic stamp tax)
//! - Stock Split (zero-iteration corporate actions — O(1) not O(n))
//! - Dividend Distribution (snapshot + proportional claim)
//! - Oracle Relayer (web2 mock API → on-chain state)
//!
//! ## Architecture
//!
//! ```text
//! [Web2 Stock API] → [Python Relayer] → [Solana Token 2022 Mint]
//!                                              │
//!                                    (every transfer forced CPI)
//!                                              ↓
//!                                   [Transfer Hook]
//!                                    ├── Market hours check (BUG 2)
//!                                    └── Dynamic stamp tax (BUG 4,5)
//!
//! Admin → trigger_stock_split(ratio) → PDA: split_multiplier (BUG 1,7)
//! Admin → snapshot_dividend(amount)   → PDA: dividend snapshot
//! User  → claim_dividend()            → PDA: USDC payout (BUG 3,8)
//! ```
//!
//! ## 8 Intentional Bugs (Krastor Targets — with Proptest Comparison)
//!
//! | # | Bug | Location | Proptest | Krastor |
//! |---|-----|----------|----------|---------|
//! | 1 | Split multiplier overflow | `effective_balance()`: `phys × mult` | ~0% — random rarely hits overflow | `flip_data` 40%/round |
//! | 2 | Market hours Clock bypass | `transfer_hook()`: Clock sysvar | 0% — no sysvar model | auto-seq + Clock manipulation |
//! | 3 | Dividend double-claim | `claim_dividend()`: no claimed flag | 0% — no multi-claim model | auto-seq: claim → claim |
//! | 4 | Stamp tax arithmetic overflow | `dynamic_stamp_tax()`: `cnt × scale` | ~0% — random values | `flip_data` 40%/round |
//! | 5 | Velocity counter race condition | `velocity.transfer_count += 1` | 0% — no parallel model | auto-seq parallel tx |
//! | 6 | Config re-init overwrite | `initialize()`: no existence check | 0% — no re-init concept | auto-seq: init → init |
//! | 7 | Admin authority spoof | `config.admin` check | 0% — no auth model | `replace_owner` 10%/round |
//! | 8 | Dividend pool underfunded | `proportional_payout()` pool check | 0% — no invariant | `zero_lamports` 10%/round |

use anchor_lang::prelude::*;

pub mod state;
pub mod errors;
pub mod math;
pub mod instructions;

// Program ID placeholder — use `solana-keygen new` for production
pub const ID: anchor_lang::solana_program::pubkey::Pubkey =
    anchor_lang::solana_program::pubkey::Pubkey::new_from_array([0u8; 32]);

#[program]
pub mod stock {
    use super::*;

    /// Phase 1: Initialize stock global config
    /// BUG 6: No existence check — can overwrite
    pub fn initialize(ctx: Context<InitializeCtx>, ticker: String) -> Result<()> {
        instructions::initialize_handler(ctx, ticker)
    }

    /// Phase 2: Transfer Hook — called by Token 2022 on every transfer
    /// BUG 2: Clock sysvar can be spoofed
    /// BUG 4: Tax calculation can overflow
    /// BUG 5: Velocity counter race condition
    pub fn transfer_hook(ctx: Context<TransferHookCtx>, amount: u64) -> Result<()> {
        instructions::transfer_hook_handler(ctx, amount)
    }

    /// Phase 3: Execute stock split (zero-iteration, O(1))
    /// BUG 1: Multiplier overflow in view functions
    /// BUG 7: Admin check bypass via replace_owner
    pub fn trigger_stock_split(ctx: Context<SplitCtx>, ratio: u64) -> Result<()> {
        instructions::split_handler(ctx, ratio)
    }

    /// Phase 4: Take dividend snapshot at current slot
    pub fn snapshot_dividend(ctx: Context<SnapshotCtx>, slot: u64, dividend_per_share: u64) -> Result<()> {
        instructions::snapshot_handler(ctx, slot, dividend_per_share)
    }

    /// Phase 4: Claim dividend proportional to your snapshot balance
    /// BUG 3: No claimed flag — double-claim possible
    /// BUG 8: Pool may not have enough USDC
    pub fn claim_dividend(ctx: Context<ClaimCtx>) -> Result<()> {
        instructions::claim_handler(ctx)
    }

    /// Oracle: Update market status (called by Python relayer)
    pub fn update_market_status(ctx: Context<OracleCtx>, status: u8) -> Result<()> {
        instructions::oracle_handler(ctx, status)
    }
}