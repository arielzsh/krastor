//! All stock program instructions (flat module — called from lib.rs)

use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::*;
use crate::math;

// ============================================================
// Constants
// ============================================================
const VELOCITY_WINDOW_SECS: i64 = 60;
const VELOCITY_SCALING_BPS: u64 = 2;

// ============================================================
// Initialize
// ============================================================

#[derive(Accounts)]
#[instruction(ticker: String)]
pub struct InitializeCtx<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    /// BUG 6: init (not init_if_needed) — fails if PDA exists.
    /// But if attacker closes+reopens, metadata can be overwritten.
    #[account(
        init,
        payer = admin,
        space = GlobalConfig::LEN,
        seeds = [b"config"],
        bump
    )]
    pub global_config: Account<'info, GlobalConfig>,

    pub system_program: Program<'info, System>,
}

pub fn initialize_handler(ctx: Context<InitializeCtx>, ticker: String) -> Result<()> {
    let config = &mut ctx.accounts.global_config;

    config.admin = ctx.accounts.admin.key();

    let mut ticker_buf = [0u8; 8];
    let bytes = ticker.as_bytes();
    let len = bytes.len().min(8);
    ticker_buf[..len].copy_from_slice(&bytes[..len]);
    config.ticker = ticker_buf;

    config.split_multiplier = 1;
    config.market_status = 1;       // Start CLOSED
    config.base_stamp_tax_bps = 10; // 0.1%
    config.max_stamp_tax_bps = 500; // 5%
    config.bump = ctx.bumps.global_config;

    msg!("Stock initialized: ticker={} admin={}", ticker, ctx.accounts.admin.key());
    Ok(())
}

// ============================================================
// Transfer Hook (called by Token 2022 on every transfer)
// ============================================================

#[derive(Accounts)]
pub struct TransferHookCtx<'info> {
    /// CHECK: Token 2022 Mint — verified by runtime
    #[account()]
    pub mint: UncheckedAccount<'info>,

    #[account(seeds = [b"config"], bump = global_config.bump)]
    pub global_config: Account<'info, GlobalConfig>,

    /// CHECK: Source owner pubkey from Token 2022 transfer
    #[account()]
    pub source_owner: UncheckedAccount<'info>,

    /// Velocity PDA for this sender
    #[account(
        init_if_needed,
        payer = payer,
        space = Velocity::LEN,
        seeds = [b"velocity", source_owner.key().as_ref()],
        bump
    )]
    pub velocity: Account<'info, Velocity>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn transfer_hook_handler(ctx: Context<TransferHookCtx>, amount: u64) -> Result<()> {
    let config = &ctx.accounts.global_config;
    let velocity = &mut ctx.accounts.velocity;

    // --- BUG 2: Market hours check (Clock sysvar bypass) ---
    if config.market_status == 1 {
        // 🚨 SHOWCASE: 0x1702 — even raw TX is rejected at Runtime level
        return Err(StockError::StockMarketClosed.into());
    }

    // --- BUG 4 & 5: Velocity counter + dynamic stamp tax ---
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;

    if velocity.owner == Pubkey::default() {
        velocity.owner = ctx.accounts.source_owner.key();
        velocity.window_start = now;
        velocity.transfer_count = 0;
        velocity.current_tax_bps = config.base_stamp_tax_bps;
        velocity.bump = ctx.bumps.velocity;
    }

    if now - velocity.window_start > VELOCITY_WINDOW_SECS {
        velocity.window_start = now;
        velocity.transfer_count = 0;
    }

    // BUG 5: non-atomic increment — race with parallel transactions
    velocity.transfer_count += 1;

    // BUG 4: unchecked arithmetic — can overflow
    let tax_bps = math::dynamic_stamp_tax(
        velocity.transfer_count,
        config.base_stamp_tax_bps,
        config.max_stamp_tax_bps,
        VELOCITY_SCALING_BPS,
    );
    velocity.current_tax_bps = tax_bps;

    let tax_amount = math::stamp_tax_amount(amount, tax_bps);

    msg!("Transfer hook: amount={} tax_bps={} tax={} velocity={}",
        amount, tax_bps, tax_amount, velocity.transfer_count);

    Ok(())
}

// ============================================================
// Stock Split (zero-iteration corporate action)
// ============================================================

#[derive(Accounts)]
pub struct SplitCtx<'info> {
    /// BUG 7: replace_owner can spoof config.admin
    pub authority: Signer<'info>,

    #[account(mut, seeds = [b"config"], bump = global_config.bump)]
    pub global_config: Account<'info, GlobalConfig>,
}

pub fn split_handler(ctx: Context<SplitCtx>, ratio: u64) -> Result<()> {
    let config = &mut ctx.accounts.global_config;

    // BUG 7: admin check bypassed by replace_owner
    require!(ctx.accounts.authority.key() == config.admin, StockError::Unauthorized);
    require!(ratio >= 2, StockError::SplitRatioTooSmall);
    require!(ratio <= 1000, StockError::SplitRatioTooSmall);

    let old = config.split_multiplier;
    config.split_multiplier = ratio;

    msg!("Stock split {}:1 (multiplier {} → {}). O(1) — no users iterated.", ratio, old, ratio);
    Ok(())
}

// ============================================================
// Dividend Snapshot
// ============================================================

#[derive(Accounts)]
#[instruction(slot: u64)]
pub struct SnapshotCtx<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(seeds = [b"config"], bump = global_config.bump)]
    pub global_config: Account<'info, GlobalConfig>,

    #[account(
        init,
        payer = admin,
        space = DividendSnapshot::LEN,
        seeds = [b"dividend", &slot.to_le_bytes()],
        bump
    )]
    pub snapshot: Account<'info, DividendSnapshot>,

    /// CHECK: USDC pool PDA
    #[account(mut)]
    pub usdc_pool: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn snapshot_handler(ctx: Context<SnapshotCtx>, slot: u64, dividend_per_share: u64) -> Result<()> {
    require!(ctx.accounts.admin.key() == ctx.accounts.global_config.admin, StockError::Unauthorized);

    let snapshot = &mut ctx.accounts.snapshot;

    snapshot.slot = slot;
    snapshot.total_supply = 0; // In production: read from Token2022 mint supply
    snapshot.dividend_per_share = dividend_per_share;
    snapshot.pool_lamports = ctx.accounts.usdc_pool.lamports();
    snapshot.claimer_count = 0;
    snapshot.bump = ctx.bumps.snapshot;

    msg!("Dividend snapshot at slot {}: {} USDC/share", slot, dividend_per_share);
    Ok(())
}

// ============================================================
// Dividend Claim
// ============================================================

#[derive(Accounts)]
pub struct ClaimCtx<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(seeds = [b"config"], bump = global_config.bump)]
    pub global_config: Account<'info, GlobalConfig>,

    #[account(seeds = [b"dividend", &snapshot.slot.to_le_bytes()], bump = snapshot.bump)]
    pub snapshot: Account<'info, DividendSnapshot>,

    #[account(
        init,
        payer = user,
        space = DividendClaim::LEN,
        seeds = [b"claim", user.key().as_ref(), &snapshot.slot.to_le_bytes()],
        bump
    )]
    pub claim_record: Account<'info, DividendClaim>,

    /// CHECK: USDC pool PDA
    #[account(mut)]
    pub usdc_pool: UncheckedAccount<'info>,

    /// CHECK: User's USDC token account
    #[account(mut)]
    pub user_usdc: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn claim_handler(ctx: Context<ClaimCtx>) -> Result<()> {
    let snapshot = &ctx.accounts.snapshot;
    let claim = &mut ctx.accounts.claim_record;

    // BUG 3: NO claimed flag check!
    // init prevents duplicate PDA, but close+reopen bypasses this.
    // Missing: require!(claim.claimed_amount == 0, AlreadyClaimed);

    let user_balance: u64 = 100; // TODO: read from Token2022 account
    let payout = math::proportional_payout(user_balance, snapshot.pool_lamports, snapshot.total_supply);

    // BUG 8: No check that usdc_pool has >= payout lamports
    // A zero_lamports attack can drain the pool before claims

    claim.owner = ctx.accounts.user.key();
    claim.snapshot_slot = snapshot.slot;
    claim.balance_at_snapshot = user_balance;
    claim.claimed_amount = payout;
    claim.bump = ctx.bumps.claim_record;

    msg!("Dividend claimed: user={} payout={} USDC", ctx.accounts.user.key(), payout);
    Ok(())
}

// ============================================================
// Oracle — Update Market Status
// ============================================================

#[derive(Accounts)]
pub struct OracleCtx<'info> {
    pub relayer: Signer<'info>,

    #[account(mut, seeds = [b"config"], bump = global_config.bump)]
    pub global_config: Account<'info, GlobalConfig>,
}

pub fn oracle_handler(ctx: Context<OracleCtx>, status: u8) -> Result<()> {
    let config = &mut ctx.accounts.global_config;

    require!(ctx.accounts.relayer.key() == config.admin, StockError::Unauthorized);
    require!(status <= 2, StockError::InvalidMarketStatus);

    let old = config.market_status;
    config.market_status = status;

    let s = |v: u8| match v { 0=>"OPEN", 1=>"CLOSED", 2=>"PRE_MARKET", _=>"?" };
    msg!("Market status: {} → {} (by relayer)", s(old), s(status));
    Ok(())
}