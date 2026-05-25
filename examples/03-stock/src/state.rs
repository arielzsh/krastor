//! Account state definitions for 03-stock

use anchor_lang::prelude::*;

// ============================================================
// GlobalConfig — singleton PDA for system-wide parameters
// ============================================================
#[account]
pub struct GlobalConfig {
    /// Admin authority (can trigger splits, update oracle)
    /// BUG 7: replace_owner can spoof this field
    pub admin: Pubkey,
    /// Stock ticker (e.g., "AAPL")
    pub ticker: [u8; 8],
    /// Split multiplier (1 = no split, 5 = 1:5 split)
    /// BUG 1: balance * split_multiplier can overflow u64
    /// BUG 8: ratio = 0 causes division by zero
    pub split_multiplier: u64,
    /// Market status: 0=OPEN, 1=CLOSED, 2=PRE_MARKET
    pub market_status: u8,
    /// Base stamp tax in basis points (10 = 0.1%)
    pub base_stamp_tax_bps: u64,
    /// Maximum stamp tax in basis points (500 = 5%)
    pub max_stamp_tax_bps: u64,
    /// Token 2022 Mint pubkey for this stock
    pub token_mint: Pubkey,
    /// PDA bump
    pub bump: u8,
}

impl GlobalConfig {
    pub const LEN: usize = 8 + 32 + 8 + 8 + 1 + 8 + 8 + 32 + 1;
}

// ============================================================
// Velocity — per-user trading frequency tracker
// ============================================================
#[account]
pub struct Velocity {
    /// Owner of this velocity tracker
    pub owner: Pubkey,
    /// Start of current velocity window (Unix timestamp)
    pub window_start: i64,
    /// Number of transfers in current window
    /// BUG 5: concurrent writes can race
    pub transfer_count: u64,
    /// Current effective stamp tax rate (bps)
    pub current_tax_bps: u64,
    /// PDA bump
    pub bump: u8,
}

impl Velocity {
    pub const LEN: usize = 8 + 32 + 8 + 8 + 8 + 1;
}

// ============================================================
// DividendSnapshot — dividend distribution state
// ============================================================
#[account]
pub struct DividendSnapshot {
    /// Slot number when snapshot was taken
    pub slot: u64,
    /// Total token supply at snapshot time (physical, pre-multiplier)
    pub total_supply: u64,
    /// USDC amount per share (in USDC's smallest unit, i.e., 6 decimals)
    pub dividend_per_share: u64,
    /// Total USDC deposited in the pool PDA
    pub pool_lamports: u64,
    /// Number of unique claimers
    pub claimer_count: u64,
    /// PDA bump
    pub bump: u8,
}

impl DividendSnapshot {
    pub const LEN: usize = 8 + 8 + 8 + 8 + 8 + 8 + 1;
}

// ============================================================
// DividendClaim — per-user claim status
// ============================================================
#[account]
pub struct DividendClaim {
    /// Owner of this claim record
    pub owner: Pubkey,
    /// Slot of the snapshot this claim belongs to
    pub snapshot_slot: u64,
    /// Physical token balance at snapshot time
    pub balance_at_snapshot: u64,
    /// USDC amount claimed
    /// BUG 3: no check if claimed > 0 (double-claim)
    pub claimed_amount: u64,
    /// PDA bump
    pub bump: u8,
}

impl DividendClaim {
    pub const LEN: usize = 8 + 32 + 8 + 8 + 8 + 1;
}

// ============================================================
// StockMetadata — stored on-chain via Metadata Pointer extension
// ============================================================
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct StockMetadata {
    /// CUSIP identifier (e.g., "037833100")
    pub cusip: [u8; 9],
    /// ISIN identifier (e.g., "US0378331005")
    pub isin: [u8; 12],
    /// Legal total shares outstanding
    pub total_shares: u64,
    /// Custodian bank vault ID
    pub custodian_vault_id: [u8; 32],
    /// Currency (e.g., "USD")
    pub currency: [u8; 3],
    /// Stock sector
    pub sector: [u8; 16],
}