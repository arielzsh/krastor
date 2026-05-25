//! # 🦭 Meme Coin — Demo Solana Program with Intentional Bugs
//!
//! ⚠️  **DISCLAIMER: NOT FOR PRODUCTION USE**
//!
//! This program contains **intentional vulnerabilities** designed for
//! Krastor fuzzer validation. DO NOT deploy to mainnet. DO NOT use
//! it for real assets. The bugs included here WILL result in loss of funds.
//!
//! ## Architecture
//!
//! A simple fair-launch meme coin with AMM (constant product) trading:
//!
//! ```text
//! Creator → create_pool(SOL, MEME) → initial liquidity
//! Users   → buy(SOL)  → get MEME tokens from pool
//! Users   → sell(MEME) → get SOL back from pool
//! LP      → add_liquidity(SOL, MEME) → get LP tokens
//! LP      → remove_liquidity(LP) → get SOL + MEME back
//! ```
//!
//! ## Intentional Bugs (Krastor Targets — with Proptest Comparison)
//!
//! | # | Bug | Location | Type | Proptest | Krastor |
//! |---|-----|----------|------|----------|--------|
//! | 1 | Mint authority NOT revoked | `create_pool()` | Infinite mint | 0% — doesn't model auth | `replace_owner` 10%/round |
//! | 2 | AMM `k = x*y` overflow | `buy()` / `sell()` | Flash loan attack | ~0% — needs exact amounts | `flip_data` 40%/round |
//! | 3 | No slippage protection | `buy()` / `sell()` | Sandwich attack | 0% — no seq correlation | auto-sequence discovery |
//! | 4 | LP ratio miscalculation | `add_liquidity()` | LP fund loss | ~0% — random deposits | `flip_data` × sequence |
//! | 5 | Fee bypass (integer div) | `buy()` | Fee evasion | ~0% — exact value needed | `flip_data` explores amounts |
//! | 6 | Unchecked underflow | `sell()` | Reserve drain | ~0% — needs flash loan | `zero_lamports` + `flip_data` |
//!
//! ### Why Proptest Cannot Find These Bugs
//!
//! Proptest treats this program as a black box: generate random `u64` values
//! for `sol_in`/`token_in`, random `Pubkey` for accounts, random bool for `paused`.
//!
//! - **Bug 1 (mint authority)**: proptest generates random signers but has
//!   no concept of "mint authority = creator". It can't know to reuse the
//!   creator's keypair across calls.
//! - **Bug 2-6 (arithmetic)**: proptest might stumble on an overflow value
//!   with probability ≈ 1/2^64 × 1/search_space ≈ 0%. It doesn't target
//!   edge values specifically.
//! - **Bug 3 (sandwich)**: proptest generates independent random rounds —
//!   no concept of transaction ordering within a sequence.
//!
//! Krastor finds all 6 with directed Solana-aware mutations.

use anchor_lang::prelude::*;

// Program ID: MemeCoin (demo — not for production)
pub const ID: anchor_lang::solana_program::pubkey::Pubkey =
    anchor_lang::solana_program::pubkey!("BrWY4UaCjq6dsZxK4KapSR2zCgKYtvLCmHGhBQJgDBVc");

// ============================================================
// Constants
// ============================================================
/// Fee in basis points (0.3% = 30 bps)
const FEE_BPS: u64 = 30;
const FEE_DENOMINATOR: u64 = 10_000;
/// Minimum liquidity to prevent dust attacks (1 lamport — way too low!)
const MINIMUM_LIQUIDITY: u64 = 1;

// ============================================================
// Instructions
// ============================================================
#[program]
pub mod meme_coin {
    use super::*;

    /// Create a new meme coin pool with initial SOL liquidity.
    ///
    /// **BUG 1**: The mint authority is NEVER revoked after pool creation.
    /// Anyone who knows the creator's keypair can mint unlimited tokens.
    pub fn create_pool(ctx: Context<CreatePool>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let creator = &ctx.accounts.creator;

        // Set up pool state
        pool.creator = creator.key();
        pool.mint = ctx.accounts.mint.key();
        pool.sol_reserve = amount;
        pool.token_reserve = amount; // 1:1 initial ratio
        pool.lp_supply = 0;
        pool.total_fees_collected = 0;
        pool.paused = false;
        pool.bump = ctx.bumps.pool;

        // Transfer SOL from creator to pool
        // (In Anchor, this happens via the #[account(mut)] + system_program CPI)
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: creator.to_account_info(),
                    to: pool.to_account_info(),
                },
            ),
            amount,
        )?;

        // Mint initial tokens to the creator
        // BUG 1: mint authority is NOT revoked after this
        // The creator can call mint_to() again at any time!
        token_mint_to(
            &ctx.accounts.token_program,
            &ctx.accounts.mint,
            &ctx.accounts.creator_token_account,
            &creator.to_account_info(),
            &[],
            amount,
        )?;

        pool.token_reserve = amount;

        emit!(PoolCreated {
            creator: creator.key(),
            sol_reserve: amount,
            token_reserve: amount,
        });

        Ok(())
    }

    /// Buy MEME tokens with SOL.
    ///
    /// **BUG 2**: Unchecked multiplication can overflow for large amounts.
    /// `sol_in * token_reserve` may exceed u64::MAX, causing silent overflow.
    ///
    /// **BUG 3**: No minimum-output / slippage check.
    /// Frontrunner can manipulate the price between tx submission and confirmation.
    ///
    /// **BUG 5**: Fee is deducted but can be bypassed by setting `sol_in` such that
    /// `fee = sol_in * FEE_BPS / FEE_DENOMINATOR = 0` for small amounts.
    pub fn buy(ctx: Context<Trade>, sol_in: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        require!(!pool.paused, MemeCoinError::PoolPaused);
        require!(sol_in > 0, MemeCoinError::ZeroAmount);

        // Snapshot PDA seeds before mutable borrow
        let mint_bytes = pool.mint.clone();
        let bump = pool.bump;

        // Calculate fee
        // BUG 5: For sol_in < 333, fee = 0 (333 * 30 / 10000 = 0 due to integer division)
        let fee = sol_in
            .checked_mul(FEE_BPS)
            .ok_or(MemeCoinError::Overflow)?
            .checked_div(FEE_DENOMINATOR)
            .ok_or(MemeCoinError::Overflow)?;

        let sol_after_fee = sol_in
            .checked_sub(fee)
            .ok_or(MemeCoinError::Overflow)?;

        // BUG 2: Unchecked multiplication — can overflow!
        // k = x * y, but k_new should be k_old + sol_after_fee * token_reserve
        //
        // Correct: token_out = token_reserve * sol_after_fee / (sol_reserve + sol_after_fee)
        // BUGGED:  Direct multiplication without safe_mul
        let numerator = pool.token_reserve * sol_after_fee; // ← OVERFLOW!
        let denominator = pool.sol_reserve + sol_after_fee;  // ← OVERFLOW!

        let token_out = if denominator > 0 {
            numerator / denominator
        } else {
            0
        };

        // BUG 3: No minimum-out check — no slippage protection
        require!(token_out > 0, MemeCoinError::InsufficientLiquidity);

        // Transfer SOL from buyer to pool
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: pool.to_account_info(),
                },
            ),
            sol_in,
        )?;

        // Transfer tokens from pool to buyer
        anchor_spl::token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: ctx.accounts.pool_token_account.to_account_info(),
                    to: ctx.accounts.user_token_account.to_account_info(),
                    authority: pool.to_account_info(),
                },
                &[&[b"pool", mint_bytes.as_ref(), &[bump]]],
            ),
            token_out,
        )?;

        // Update reserves
        pool.sol_reserve = pool.sol_reserve + sol_after_fee;  // ← OVERFLOW!
        pool.token_reserve = pool.token_reserve - token_out;   // ← UNDERFLOW!
        pool.total_fees_collected = pool.total_fees_collected + fee; // ← OVERFLOW!

        emit!(TradeEvent {
            user: ctx.accounts.user.key(),
            is_buy: true,
            sol_amount: sol_in,
            token_amount: token_out,
            fee,
            sol_reserve_after: pool.sol_reserve,
            token_reserve_after: pool.token_reserve,
        });

        Ok(())
    }

    /// Sell MEME tokens for SOL.
    ///
    /// **BUG 2**: Same unchecked multiplication as `buy()`.
    ///
    /// **BUG 6**: `token_reserve - token_out` can UNDERFLOW if `token_in` is
    /// manipulated via a flash loan that temporarily inflates reserves.
    pub fn sell(ctx: Context<Trade>, token_in: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        require!(!pool.paused, MemeCoinError::PoolPaused);
        require!(token_in > 0, MemeCoinError::ZeroAmount);

        // Calculate fee
        let fee = token_in
            .checked_mul(FEE_BPS)
            .ok_or(MemeCoinError::Overflow)?
            .checked_div(FEE_DENOMINATOR)
            .ok_or(MemeCoinError::Overflow)?;

        let token_after_fee = token_in
            .checked_sub(fee)
            .ok_or(MemeCoinError::Overflow)?;

        // BUG 2: Unchecked multiplication — can overflow!
        let numerator = pool.sol_reserve * token_after_fee;    // ← OVERFLOW!
        let denominator = pool.token_reserve + token_after_fee; // ← OVERFLOW!

        let sol_out = if denominator > 0 {
            numerator / denominator
        } else {
            0
        };

        // BUG 3: No minimum-out check
        require!(sol_out > 0, MemeCoinError::InsufficientLiquidity);

        // Transfer tokens from seller to pool
        anchor_spl::token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: ctx.accounts.user_token_account.to_account_info(),
                    to: ctx.accounts.pool_token_account.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
                &[],
            ),
            token_in,
        )?;

        // Transfer SOL from pool to seller
        **pool.to_account_info().try_borrow_mut_lamports()? -= sol_out;
        **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? += sol_out;

        // Update reserves
        // BUG 6: If token_reserve was manipulated, this can underflow
        pool.token_reserve = pool.token_reserve + token_after_fee; // ← OVERFLOW!
        pool.sol_reserve = pool.sol_reserve - sol_out;             // ← UNDERFLOW!
        pool.total_fees_collected = pool.total_fees_collected + fee; // ← OVERFLOW!

        emit!(TradeEvent {
            user: ctx.accounts.user.key(),
            is_buy: false,
            sol_amount: sol_out,
            token_amount: token_in,
            fee,
            sol_reserve_after: pool.sol_reserve,
            token_reserve_after: pool.token_reserve,
        });

        Ok(())
    }

    /// Add liquidity to the pool.
    ///
    /// **BUG 4**: LP token ratio miscalculation.
    /// If `sol_in` and `token_in` don't match the current pool ratio,
    /// the LP receives fewer LP tokens than they should.
    /// The leftover tokens are effectively donated to the pool without
    /// the LP receiving credit.
    pub fn add_liquidity(ctx: Context<AddLiquidity>, sol_in: u64, token_in: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        require!(!pool.paused, MemeCoinError::PoolPaused);
        require!(sol_in > 0 && token_in > 0, MemeCoinError::ZeroAmount);

        // Snapshot PDA seeds before mutable borrow
        let mint_bytes = pool.mint.clone();
        let bump = pool.bump;

        // BUG 4: Simplistic LP calculation — doesn't handle imbalanced deposits correctly.
        // If the pool ratio is 2:1 SOL:TOKEN and the user deposits 100:100,
        // they should receive LP tokens based on the MINIMUM of the two ratios.
        // This implementation uses a naive equal-weight calculation.
        let lp_to_mint = if pool.lp_supply == 0 {
            // Initial LP: use sqrt(x*y) approximation via simple formula
            // BUG 4: doesn't handle the case correctly
            let product = (sol_in as f64) * (token_in as f64);
            let sqrt = product.sqrt() as u64;
            sqrt.saturating_sub(MINIMUM_LIQUIDITY)
        } else {
            // BUG: Doesn't handle imbalanced deposits!
            // Should be: lp = min(sol_in * lp_total / sol_reserve, token_in * lp_total / token_reserve)
            let sol_share = sol_in * pool.lp_supply / pool.sol_reserve; // ← OVERFLOW!
            let token_share = token_in * pool.lp_supply / pool.token_reserve; // ← OVERFLOW!
            sol_share.min(token_share)
        };

        require!(lp_to_mint > 0, MemeCoinError::InsufficientLiquidity);

        // Transfer SOL from LP to pool
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: pool.to_account_info(),
                },
            ),
            sol_in,
        )?;

        // Transfer tokens from LP to pool
        anchor_spl::token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: ctx.accounts.user_token_account.to_account_info(),
                    to: ctx.accounts.pool_token_account.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
                &[],
            ),
            token_in,
        )?;

        // Mint LP tokens — but the ratio might be wrong (BUG 4)
        anchor_spl::token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::MintTo {
                    mint: ctx.accounts.lp_mint.to_account_info(),
                    to: ctx.accounts.lp_token_account.to_account_info(),
                    authority: pool.to_account_info(),
                },
                &[&[b"pool", mint_bytes.as_ref(), &[bump]]],
            ),
            lp_to_mint,
        )?;

        // Update reserves (with overflow bugs)
        pool.sol_reserve = pool.sol_reserve + sol_in;    // ← OVERFLOW!
        pool.token_reserve = pool.token_reserve + token_in; // ← OVERFLOW!
        pool.lp_supply = pool.lp_supply + lp_to_mint;    // ← OVERFLOW!

        Ok(())
    }

    /// Remove liquidity from the pool.
    pub fn remove_liquidity(ctx: Context<RemoveLiquidity>, lp_amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        require!(!pool.paused, MemeCoinError::PoolPaused);
        require!(lp_amount > 0, MemeCoinError::ZeroAmount);
        require!(lp_amount <= pool.lp_supply, MemeCoinError::InsufficientLiquidity);

        // Snapshot PDA seeds before mutable borrow
        let mint_bytes = pool.mint.clone();
        let bump = pool.bump;

        // Calculate share of reserves
        let sol_share = ((pool.sol_reserve as u128)
            .checked_mul(lp_amount as u128)
            .ok_or(MemeCoinError::Overflow)?
            .checked_div(pool.lp_supply as u128)
            .ok_or(MemeCoinError::Overflow)?) as u64;

        let token_share = ((pool.token_reserve as u128)
            .checked_mul(lp_amount as u128)
            .ok_or(MemeCoinError::Overflow)?
            .checked_div(pool.lp_supply as u128)
            .ok_or(MemeCoinError::Overflow)?) as u64;

        // Burn LP tokens
        anchor_spl::token::burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::Burn {
                    mint: ctx.accounts.lp_mint.to_account_info(),
                    from: ctx.accounts.lp_token_account.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
                &[],
            ),
            lp_amount,
        )?;

        // Transfer SOL back to LP
        **pool.to_account_info().try_borrow_mut_lamports()? -= sol_share;
        **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? += sol_share;

        // Transfer tokens back to LP
        anchor_spl::token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::Transfer {
                    from: ctx.accounts.pool_token_account.to_account_info(),
                    to: ctx.accounts.user_token_account.to_account_info(),
                    authority: pool.to_account_info(),
                },
                &[&[b"pool", mint_bytes.as_ref(), &[bump]]],
            ),
            token_share,
        )?;

        // Update reserves
        pool.sol_reserve = pool.sol_reserve - sol_share;       // ← UNDERFLOW!
        pool.token_reserve = pool.token_reserve - token_share;  // ← UNDERFLOW!
        pool.lp_supply = pool.lp_supply - lp_amount;           // ← UNDERFLOW!

        Ok(())
    }

    /// ⚠️  BUG 1 DEMONSTRATION: Mint more tokens.
    /// This function exists because the mint authority was NEVER revoked.
    /// Anyone who controls the creator keypair can mint unlimited tokens,
    /// instantly draining the pool.
    pub fn evil_mint(ctx: Context<EvilMint>, amount: u64) -> Result<()> {
        // Note: There's no authorization check here because the mint authority
        // is still set to the creator. This instruction just works.
        anchor_spl::token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token::MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
                &[],
            ),
            amount,
        )?;

        emit!(EvilMintEvent {
            minter: ctx.accounts.authority.key(),
            amount,
        });

        Ok(())
    }

    /// Emergency pause — but with a bug!
    ///
    /// **BUG**: No timelock. The creator can pause trading, frontrun their own
    /// transaction, then unpause — all in the same block.
    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(
            ctx.accounts.authority.key() == pool.creator,
            MemeCoinError::Unauthorized
        );
        pool.paused = paused;
        Ok(())
    }
}

// ============================================================
// Accounts
// ============================================================

#[derive(Accounts)]
pub struct CreatePool<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    /// The MEME token mint
    #[account(
        init,
        payer = creator,
        mint::decimals = 9,
        mint::authority = creator, // ← BUG 1: authority = creator, never revoked!
        mint::freeze_authority = creator,
    )]
    pub mint: Account<'info, anchor_spl::token::Mint>,

    /// Creator's token account for receiving initial tokens
    #[account(
        init,
        payer = creator,
        token::mint = mint,
        token::authority = creator,
    )]
    pub creator_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    /// The pool state account (PDA)
    #[account(
        init,
        payer = creator,
        space = Pool::LEN,
        seeds = [b"pool", mint.key().as_ref()],
        bump,
    )]
    pub pool: Account<'info, Pool>,

    /// Pool's token account (PDA — holds the MEME reserves)
    #[account(
        init,
        payer = creator,
        token::mint = mint,
        token::authority = pool,
    )]
    pub pool_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Trade<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(mut)]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub user_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    #[account(mut)]
    pub pool_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
}

#[derive(Accounts)]
pub struct AddLiquidity<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(mut)]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub user_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    #[account(mut)]
    pub pool_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    #[account(mut)]
    pub lp_mint: Account<'info, anchor_spl::token::Mint>,

    #[account(mut)]
    pub lp_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
}

#[derive(Accounts)]
pub struct RemoveLiquidity<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(mut)]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub user_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    #[account(mut)]
    pub pool_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    #[account(mut)]
    pub lp_mint: Account<'info, anchor_spl::token::Mint>,

    #[account(mut)]
    pub lp_token_account: Account<'info, anchor_spl::token::TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
}

#[derive(Accounts)]
pub struct EvilMint<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub mint: Account<'info, anchor_spl::token::Mint>,

    #[account(mut)]
    pub destination: Account<'info, anchor_spl::token::TokenAccount>,

    pub token_program: Program<'info, anchor_spl::token::Token>,
}

#[derive(Accounts)]
pub struct SetPaused<'info> {
    pub authority: Signer<'info>,
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

// ============================================================
// State
// ============================================================

#[account]
pub struct Pool {
    /// Creator's pubkey (also the mint authority — BUG 1!)
    pub creator: Pubkey,
    /// The token mint address
    pub mint: Pubkey,
    /// SOL reserve in lamports
    pub sol_reserve: u64,
    /// Token reserve (in token's smallest unit)
    pub token_reserve: u64,
    /// Total LP token supply
    /// Total LP token supply
    pub lp_supply: u64,
    /// Total fees collected
    pub total_fees_collected: u64,
    /// Whether trading is paused
    pub paused: bool,
    /// PDA bump
    pub bump: u8,
}

impl Pool {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 1;
}

// ============================================================
// Events
// ============================================================

#[event]
pub struct PoolCreated {
    pub creator: Pubkey,
    pub sol_reserve: u64,
    pub token_reserve: u64,
}

#[event]
pub struct TradeEvent {
    pub user: Pubkey,
    pub is_buy: bool,
    pub sol_amount: u64,
    pub token_amount: u64,
    pub fee: u64,
    pub sol_reserve_after: u64,
    pub token_reserve_after: u64,
}

#[event]
pub struct EvilMintEvent {
    pub minter: Pubkey,
    pub amount: u64,
}

// ============================================================
// Errors
// ============================================================

#[error_code]
pub enum MemeCoinError {
    #[msg("Pool is paused")]
    PoolPaused,
    #[msg("Zero amount not allowed")]
    ZeroAmount,
    #[msg("Insufficient liquidity")]
    InsufficientLiquidity,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Slippage exceeded")]
    SlippageExceeded,
}

// ============================================================
// SPL Token CPI Helpers
// ============================================================

#[allow(unused)]
fn token_mint_to<'info>(
    token_program: &Program<'info, anchor_spl::token::Token>,
    mint: &Account<'info, anchor_spl::token::Mint>,
    destination: &Account<'info, anchor_spl::token::TokenAccount>,
    authority: &AccountInfo<'info>,
    seeds: &[&[&[u8]]],
    amount: u64,
) -> Result<()> {
    let accounts = anchor_spl::token::MintTo {
        mint: mint.to_account_info(),
        to: destination.to_account_info(),
        authority: authority.clone(),
    };
    if seeds.is_empty() {
        anchor_spl::token::mint_to(CpiContext::new(token_program.to_account_info(), accounts), amount)
    } else {
        anchor_spl::token::mint_to(
            CpiContext::new_with_signer(token_program.to_account_info(), accounts, seeds),
            amount,
        )
    }
}

fn token_transfer<'info>(
    token_program: &Program<'info, anchor_spl::token::Token>,
    from: &Account<'info, anchor_spl::token::TokenAccount>,
    to: &Account<'info, anchor_spl::token::TokenAccount>,
    authority: &AccountInfo<'info>,
    seeds: &[&[&[u8]]],
    amount: u64,
) -> Result<()> {
    let accounts = anchor_spl::token::Transfer {
        from: from.to_account_info(),
        to: to.to_account_info(),
        authority: authority.clone(),
    };
    if seeds.is_empty() {
        anchor_spl::token::transfer(CpiContext::new(token_program.to_account_info(), accounts), amount)
    } else {
        anchor_spl::token::transfer(
            CpiContext::new_with_signer(token_program.to_account_info(), accounts, seeds),
            amount,
        )
    }
}

fn token_burn<'info>(
    token_program: &Program<'info, anchor_spl::token::Token>,
    from: &Account<'info, anchor_spl::token::TokenAccount>,
    mint: &Account<'info, anchor_spl::token::Mint>,
    authority: &AccountInfo<'info>,
    seeds: &[&[&[u8]]],
    amount: u64,
) -> Result<()> {
    let accounts = anchor_spl::token::Burn {
        mint: mint.to_account_info(),
        from: from.to_account_info(),
        authority: authority.clone(),
    };
    if seeds.is_empty() {
        anchor_spl::token::burn(CpiContext::new(token_program.to_account_info(), accounts), amount)
    } else {
        anchor_spl::token::burn(
            CpiContext::new_with_signer(token_program.to_account_info(), accounts, seeds),
            amount,
        )
    }
}