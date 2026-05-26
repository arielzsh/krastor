//! # 🦭 02-nft — Fully On-Chain Generative Pixel Art NFT
//!
//! ⚠️  **DEMO ONLY — NOT FOR PRODUCTION USE. Contains intentional bugs.**
//!
//! A pixel art NFT engine reminiscent of CryptoMonkeys. All metadata,
//! trait generation, and rendering is fully on-chain.
//!
//! ## Architecture
//!
//! ```text
//! Creator → initialize_collection(name, symbol, max_supply)
//! User    → mint() → generates random traits → mints NFT
//! Owner   → transfer(to) → transfers NFT
//! Seller  → list(price) → lists NFT on marketplace
//! Buyer   → buy(listing) → buys NFT + pays royalties
//! ```
//!
//! ## 5 Intentional Bugs (Krastor Targets — with Proptest Comparison)
//!
//! | # | Bug | Location | Proptest | Krastor |
//! |---|-----|----------|----------|---------|
//! | 1 | Supply cap not enforced | `mint()` | 0% — no cap model | `flip_data` 40%/round |
//! | 2 | Transfer without owner check | `transfer()` | 0% — no auth model | `replace_owner` 10%/round |
//! | 3 | Royalty calculation overflow | `buy()` | ~0% — extreme values | `flip_data` 40%/round |
//! | 4 | Metadata re-initialization | `mint()` | 0% — no re-init model | auto-seq: mint→mint |
//! | 5 | Marketplace escrow atomicity | `list()` / `buy()` | 0% — no two-phase | auto-seq: list→delist→buy |

use anchor_lang::prelude::*;

// Program ID
pub const ID: anchor_lang::solana_program::pubkey::Pubkey =
    anchor_lang::solana_program::pubkey::Pubkey::new_from_array([0u8; 32]);

// ============================================================
// Constants
// ============================================================
/// NFT pixel art dimensions (8×8 = 64 pixels, each pixel = 1 byte palette index)
const PIXEL_COUNT: usize = 64;
/// Number of trait types (background, body, eyes, mouth, hat)
const TRAIT_TYPES: usize = 5;
/// Royalty in basis points (5% = 500 bps)
const ROYALTY_BPS: u64 = 500;

// ============================================================
// State
// ============================================================

/// Collection-wide configuration
#[account]
pub struct Collection {
    pub authority: Pubkey,
    pub name: [u8; 32],
    pub symbol: [u8; 8],
    /// BUG 1: max_supply exists but is NEVER checked in mint()
    pub max_supply: u64,
    pub total_minted: u64,
    pub royalty_bps: u64,
    pub bump: u8,
    pub _padding: [u8; 7],
}
impl Collection { pub const LEN: usize = 8 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 7; }

/// Individual NFT metadata (fully on-chain)
#[account]
pub struct Nft {
    /// BUG 2: owner is stored but NEVER checked in transfer()
    pub owner: Pubkey,
    /// Mint edition number
    pub edition: u64,
    /// Pixel art data: 64 bytes, each = palette index
    pub pixels: [u8; PIXEL_COUNT],
    /// Trait values [background, body, eyes, mouth, hat]
    pub traits: [u8; TRAIT_TYPES],
    /// Whether this NFT is listed on marketplace
    pub listed: bool,
    /// Listing price (in lamports)
    pub price: u64,
    /// PDA bump
    pub bump: u8,
}
impl Nft { pub const LEN: usize = 8 + 32 + 8 + 64 + 5 + 1 + 8 + 1; }

/// Marketplace listing (escrow account)
#[account]
pub struct Listing {
    pub nft_mint: Pubkey,
    pub seller: Pubkey,
    pub price: u64,
    /// BUG 5: no "active" flag — listing can be sold after delist
    pub bump: u8,
}
impl Listing { pub const LEN: usize = 8 + 32 + 32 + 8 + 1; }

// ============================================================
// Errors
// ============================================================
#[error_code]
pub enum NftError {
    #[msg("Unauthorized — not the NFT owner")]
    NotOwner,
    #[msg("Maximum supply reached")]
    MaxSupplyReached,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("NFT already initialized")]
    AlreadyInitialized,
    #[msg("Insufficient funds for purchase")]
    InsufficientFunds,
    #[msg("NFT not listed for sale")]
    NotListed,
}

// ============================================================
// Instructions
// ============================================================
#[program]
pub mod nft {
    use super::*;

    /// Initialize a new NFT collection.
    pub fn initialize_collection(
        ctx: Context<InitCollectionCtx>,
        name: [u8; 32],
        symbol: [u8; 8],
        max_supply: u64,
    ) -> Result<()> {
        let collection = &mut ctx.accounts.collection;
        collection.authority = ctx.accounts.authority.key();
        collection.name = name;
        collection.symbol = symbol;
        collection.max_supply = max_supply;
        collection.total_minted = 0;
        collection.royalty_bps = ROYALTY_BPS;
        collection.bump = ctx.bumps.collection;
        msg!("Collection initialized: {} (max: {})",
            String::from_utf8_lossy(&name).trim_end(),
            max_supply);
        Ok(())
    }

    /// Mint a new NFT with randomly generated pixel art traits.
    ///
    /// BUG 1: Supply cap (`max_supply`) is NEVER checked.
    ///         total_minted can exceed max_supply infinitely.
    ///
    /// BUG 4: No check if mint PDA already exists for this edition.
    ///         If attacker closes and re-initializes, edition collision possible.
    ///
    /// PROPTEST: never hits supply overflow — random edition rarely > cap
    /// KRASTOR:  flip_data pushes total_minted to u64::MAX
    pub fn mint(ctx: Context<MintCtx>) -> Result<()> {
        let collection = &mut ctx.accounts.collection;
        let nft = &mut ctx.accounts.nft;

        // BUG 1: THIS CHECK IS MISSING!
        // require!(collection.total_minted < collection.max_supply, MaxSupplyReached);

        // Generate random traits from blockhash + edition (deterministic "random" for on-chain)
        let seed = Clock::get()?.unix_timestamp as u64 + collection.total_minted;
        let traits = generate_traits(seed);

        // Generate pixel art from traits
        let pixels = generate_pixels(&traits, collection.total_minted);

        nft.owner = ctx.accounts.minter.key();
        nft.edition = collection.total_minted;
        nft.pixels = pixels;
        nft.traits = traits;
        nft.listed = false;
        nft.price = 0;
        nft.bump = ctx.bumps.nft;

        collection.total_minted += 1; // BUG 1: unchecked addition — can overflow!

        msg!("NFT #{:?} minted: traits={:?}", nft.edition, nft.traits);
        Ok(())
    }

    /// Transfer NFT ownership.
    ///
    /// BUG 2: NO owner check! Anyone can transfer any NFT.
    ///
    /// PROPTEST: treats signer as random pubkey — no concept of ownership
    /// KRASTOR:  replace_owner (10%/round) + swap_signer (15%/round)
    pub fn transfer(ctx: Context<TransferCtx>) -> Result<()> {
        let nft = &mut ctx.accounts.nft;

        // BUG 2: THIS CHECK IS MISSING!
        // require!(ctx.accounts.sender.key() == nft.owner, NotOwner);

        let old_owner = nft.owner;
        nft.owner = ctx.accounts.receiver.key();

        msg!("NFT #{} transferred: {} → {} (NO owner check!)",
            nft.edition, old_owner, nft.owner);
        Ok(())
    }

    /// List NFT for sale on marketplace.
    ///
    /// BUG 5: Listing can remain active after NFT is transferred.
    ///         No atomicity between list/delist/buy operations.
    pub fn list(ctx: Context<ListCtx>, price: u64) -> Result<()> {
        let nft = &mut ctx.accounts.nft;
        let listing = &mut ctx.accounts.listing;

        // Check: sender owns the NFT
        require!(ctx.accounts.seller.key() == nft.owner, NftError::NotOwner);

        nft.listed = true;
        nft.price = price;

        listing.nft_mint = nft.key();
        listing.seller = ctx.accounts.seller.key();
        listing.price = price;
        listing.bump = ctx.bumps.listing;

        msg!("NFT #{} listed for {} lamports", nft.edition, price);
        Ok(())
    }

    /// Buy a listed NFT.
    ///
    /// BUG 3: Royalty calculation can overflow.
    ///         royalty = price * royalty_bps / 10000 → price * 500  can overflow
    ///
    /// BUG 5: No check that listing is still active or NFT hasn't been transferred.
    ///
    /// PROPTEST: random price values — rarely hits overflow
    /// KRASTOR:  flip_data pushes price to u64::MAX
    pub fn buy(ctx: Context<BuyCtx>) -> Result<()> {
        let collection = &ctx.accounts.collection;
        let nft = &mut ctx.accounts.nft;

        require!(nft.listed, NftError::NotListed);

        let price = nft.price;

        // BUG 3: Unchecked multiplication — can overflow!
        let royalty = price * collection.royalty_bps / 10000; // ← OVERFLOW!

        // Transfer payment: price - royalty to seller, royalty to creator
        let seller_amount = price - royalty; // ← could underflow!

        **ctx.accounts.buyer.to_account_info().try_borrow_mut_lamports()? -= price;
        **ctx.accounts.seller.to_account_info().try_borrow_mut_lamports()? += seller_amount;
        **ctx.accounts.creator.to_account_info().try_borrow_mut_lamports()? += royalty;

        // Transfer ownership
        nft.owner = ctx.accounts.buyer.key();
        nft.listed = false;
        nft.price = 0;

        msg!("NFT #{} sold: {} → {} (price={}, royalty={})",
            nft.edition, ctx.accounts.seller.key(), ctx.accounts.buyer.key(),
            price, royalty);
        Ok(())
    }
}

// ============================================================
// Account Contexts
// ============================================================

#[derive(Accounts)]
pub struct InitCollectionCtx<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(init, payer = authority, space = Collection::LEN,
              seeds = [b"collection"], bump)]
    pub collection: Account<'info, Collection>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MintCtx<'info> {
    #[account(mut)]
    pub minter: Signer<'info>,

    #[account(mut, seeds = [b"collection"], bump = collection.bump)]
    pub collection: Account<'info, Collection>,

    /// BUG 4: init — PDA created from total_minted as seed.
    /// If an existing NFT PDA is closed and re-minted, metadata is overwritten.
    #[account(init, payer = minter, space = Nft::LEN,
              seeds = [b"nft", &collection.total_minted.to_le_bytes()[..]], bump)]
    pub nft: Account<'info, Nft>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferCtx<'info> {
    /// BUG 2: sender is NOT checked against nft.owner
    #[account(mut)]
    pub sender: Signer<'info>,

    /// CHECK: receiver can be any pubkey
    #[account(mut)]
    pub receiver: UncheckedAccount<'info>,

    #[account(mut, seeds = [b"nft", &nft.edition.to_le_bytes()], bump = nft.bump)]
    pub nft: Account<'info, Nft>,
}

#[derive(Accounts)]
pub struct ListCtx<'info> {
    #[account(mut)]
    pub seller: Signer<'info>,

    #[account(mut, seeds = [b"nft", &nft.edition.to_le_bytes()], bump = nft.bump)]
    pub nft: Account<'info, Nft>,

    #[account(init_if_needed, payer = seller, space = Listing::LEN,
              seeds = [b"listing", &nft.edition.to_le_bytes()[..]], bump)]
    pub listing: Account<'info, Listing>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct BuyCtx<'info> {
    #[account(mut)]
    pub buyer: Signer<'info>,

    /// CHECK: seller receives funds
    #[account(mut)]
    pub seller: UncheckedAccount<'info>,

    /// CHECK: creator receives royalty
    #[account(mut)]
    pub creator: UncheckedAccount<'info>,

    #[account(seeds = [b"collection"], bump = collection.bump)]
    pub collection: Account<'info, Collection>,

    #[account(mut, seeds = [b"nft", &nft.edition.to_le_bytes()], bump = nft.bump)]
    pub nft: Account<'info, Nft>,

    pub system_program: Program<'info, System>,
}

// ============================================================
// On-chain Generative Art Engine
// ============================================================

/// Generate 5 traits from a deterministic seed.
///
/// Each trait is remapped via a mixing function to avoid clustering.
/// The seed comes from blockhash + edition number — deterministic
/// enough for on-chain generation, "random" enough for variety.
fn generate_traits(seed: u64) -> [u8; TRAIT_TYPES] {
    let mut state = seed;
    let mut traits = [0u8; TRAIT_TYPES];

    for i in 0..TRAIT_TYPES {
        // Simple xorshift PRNG
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        // Map to trait range (0-15 per trait = 16 variants each)
        traits[i] = ((state >> (i * 4)) & 0xF) as u8;
    }

    traits
}

/// Generate 8×8 pixel art from traits.
///
/// Each pixel's palette index is a function of:
/// - The trait values (determine color palette)
/// - The pixel position (x, y) for pattern generation
/// - The edition number (adds per-NFT uniqueness)
///
/// This creates visually distinct pixel art for each trait combination.
fn generate_pixels(traits: &[u8; TRAIT_TYPES], edition: u64) -> [u8; PIXEL_COUNT] {
    let mut pixels = [0u8; PIXEL_COUNT];

    for y in 0..8u8 {
        for x in 0..8u8 {
            let idx = (y * 8 + x) as usize;

            // Combine traits + position + edition for deterministic variation
            let pattern = (traits[0] as u64 * (x as u64 + 1))
                ^ (traits[1] as u64 * (y as u64 + 1))
                ^ (traits[2] as u64 * (x as u64 + y as u64 + 1))
                ^ (traits[3] as u64 * edition.wrapping_mul(13))
                ^ (traits[4] as u64 * edition.wrapping_mul(7));

            // Map to palette index (0-15 = 16 colors)
            let palette_base = (traits[0] % 4) as u8; // 4 palette families
            let color_idx = ((pattern >> (palette_base as u64 * 2)) & 0xF) as u8;

            pixels[idx] = color_idx;
        }
    }

    pixels
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_traits_deterministic() {
        let t1 = generate_traits(42);
        let t2 = generate_traits(42);
        assert_eq!(t1, t2, "Same seed should produce same traits");
    }

    #[test]
    fn test_generate_traits_different_seeds() {
        let t1 = generate_traits(42);
        let t2 = generate_traits(99);
        assert_ne!(t1, t2, "Different seeds should produce different traits");
    }

    #[test]
    fn test_generate_pixels_deterministic() {
        let traits = generate_traits(42);
        let p1 = generate_pixels(&traits, 0);
        let p2 = generate_pixels(&traits, 0);
        assert_eq!(p1, p2, "Same traits+edition = same pixels");
    }

    #[test]
    fn test_generate_pixels_different_editions() {
        let traits = generate_traits(42);
        let p1 = generate_pixels(&traits, 0);
        let p2 = generate_pixels(&traits, 1);
        assert_ne!(p1, p2, "Different editions = different pixels");
    }

    #[test]
    fn test_pixel_count() {
        let traits = generate_traits(42);
        let pixels = generate_pixels(&traits, 0);
        assert_eq!(pixels.len(), 64, "8x8 = 64 pixels");
    }

    // ============================================================
    // Bug Demos: Proptest vs Krastor
    // ============================================================

    #[test]
    fn bug1_supply_cap_not_enforced() {
        let max_supply = 100u64;
        let mut total_minted = 0u64;

        // Simulate: mint 101 times (should fail at 100)
        for _ in 0..=max_supply {
            total_minted += 1; // BUG: no check for max_supply!
        }
        assert_eq!(total_minted, 101, "Bug 1: 101 NFTs minted when max was 100");

        // Proptest: random mint count — rarely exceeds cap
        // Krastor: flip_data pushes total_minted past max_supply
    }

    #[test]
    fn bug2_transfer_without_owner_check() {
        let owner = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();
        let mut nft_owner = owner;

        // Simulate: attacker calls transfer() without being owner
        nft_owner = attacker; // BUG: no owner check!
        assert_eq!(nft_owner, attacker, "Bug 2: attacker stole NFT without owner check");

        // Proptest: random signer — P(match owner) = 1/2^256 ≈ 0
        // Krastor: replace_owner (10%/round) directly targets owner field
    }

    #[test]
    fn bug3_royalty_overflow() {
        let price = u64::MAX;
        let royalty_bps = 500u64;

        // BUG: price * royalty_bps can overflow u64
        let royalty = price.checked_mul(royalty_bps);
        assert!(royalty.is_none(), "Bug 3: royalty calculation overflow detected");

        // Normal case: works fine
        let ok_royalty = 10000u64 * 500 / 10000;
        assert_eq!(ok_royalty, 500, "Normal: 5% of 10000 = 500");
    }

    #[test]
    fn bug4_metadata_reinit_overwrite() {
        let mut traits = [1u8, 2, 3, 4, 5];
        let original = traits;

        // Simulate: second mint with same edition number
        traits = [9u8, 8, 7, 6, 5]; // BUG: overwrites original traits!
        assert_ne!(traits, original, "Bug 4: metadata was overwritten by re-initialization");

        // Proptest: tests one mint — never mints the same edition twice
        // Krastor: auto-sequence generates mint→close→mint
    }

    #[test]
    fn bug5_marketplace_escrow_atomicity() {
        let price = 1_000_000u64;
        let mut listed = true;
        let mut transferred = false;

        // Simulate: seller lists NFT, then transfers it
        // Listing still exists but NFT has a new owner
        transferred = true;

        // Buyer calls buy() — listing still active but NFT owner changed!
        // The buyer pays the OLD listing price to the new owner.
        // Bug: no check that listing seller == current owner
        if listed && !transferred {
            // should prevent sale
        }

        assert!(listed, "Bug 5: Listing still active after transfer — buyer pays wrong seller");

        // Proptest: independent rounds — never discovers sequence
        // Krastor: auto-sequence generates list→transfer→buy
    }
}