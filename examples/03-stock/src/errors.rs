use anchor_lang::prelude::*;

/// 🚨  Showcase Error: Transfer blocked because market is closed.
/// Error code: 0x1702 — "StockMarketClosed"
/// This error MUST be returned at the Runtime level by the Transfer Hook.
/// Even raw transactions bypassing the frontend will be rejected.
#[error_code]
pub enum StockError {
    // --- Initialization ---
    #[msg("Stock already initialized — cannot overwrite metadata")]
    StockAlreadyExists, // 0x1770

    // --- Market Hours ---
    #[msg("Market is closed — transfers are blocked")] // 0x1772
    StockMarketClosed, // ← SHOWCASE: Token 2022 Hook enforces this at Runtime

    // --- Velocity / Tax ---
    #[msg("Velocity tax rate has hit maximum")]
    VelocityTaxLimitExceeded, // 0x1773

    // --- Split ---
    #[msg("Split ratio must be >= 2")]
    SplitRatioTooSmall, // 0x1774
    #[msg("Split ratio is invalid")]
    SplitRatioInvalid, // 0x1775

    // --- Dividend ---
    #[msg("Dividend snapshot already taken for this slot")]
    SnapshotAlreadyTaken, // 0x1776
    #[msg("Dividend already claimed for this snapshot")]
    DividendAlreadyClaimed, // 0x1777
    #[msg("No dividend snapshot found")]
    SnapshotNotFound, // 0x1778
    #[msg("Insufficient USDC in dividend pool")]
    InsufficientDividendPool, // 0x1779

    // --- General ---
    #[msg("Unauthorized — admin only")]
    Unauthorized, // 0x1780
    #[msg("Arithmetic overflow in calculation")]
    Overflow, // 0x1781
    #[msg("Amount is zero")]
    ZeroAmount, // 0x1782
}