//! Fixed-point math library (u64.64) for financial calculations.
//!
//! Solana has no native floating-point support. All financial math
//! (dividends, tax rates, split ratios) must use fixed-point arithmetic.
//!
//! ## Approach
//! - Internal representation: u128 where lower 64 bits = fractional part
//! - Multiplication: `(a as u128 * b as u128) >> 64`
//! - Division: `((a as u128) << 64) / b as u128`
//!
//! ## BUG: Precision loss
//! Integer division truncates, causing precision loss in dividend calculations.
//! Over many operations (compound interest, frequent dividends), this loss accumulates.

/// Scale factor: 2^64
pub const SCALE: u128 = 1u128 << 64;

/// Convert a u64 integer to fixed-point u128 (integer.0 format)
pub fn to_fixed(value: u64) -> u128 {
    (value as u128) * SCALE
}

/// Convert fixed-point u128 back to u64 (truncates fractional part)
/// BUG: Truncation means precision loss — 1.999 → 1 (loses 0.999)
pub fn from_fixed(value: u128) -> u64 {
    (value / SCALE) as u64
}

/// Fixed-point multiplication: (a * b) / SCALE
/// BUG: Intermediate overflow if a * b > u128::MAX
pub fn mul_fixed(a: u64, b: u64) -> u64 {
    let result = (a as u128) * (b as u128) / SCALE;
    result as u64
}

/// Fixed-point division: (a * SCALE) / b
pub fn div_fixed(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    let result = ((a as u128) * SCALE) / (b as u128);
    result as u64
}

/// Calculate effective balance with split multiplier
/// effective = physical_balance * split_multiplier
///
/// **BUG 1**: Unchecked multiplication — `physical * multiplier` can overflow u64
pub fn effective_balance(physical_balance: u64, split_multiplier: u64) -> u64 {
    // BUG: No overflow check!
    physical_balance * split_multiplier
}

/// Calculate proportional dividend payout
/// payout = (user_balance * total_pool) / total_supply
///
/// Uses u128 for intermediate to avoid overflow, then truncates to u64
pub fn proportional_payout(user_balance: u64, total_pool: u64, total_supply: u64) -> u64 {
    if total_supply == 0 {
        return 0;
    }
    let numerator = (user_balance as u128) * (total_pool as u128);
    (numerator / (total_supply as u128)) as u64
}

/// Calculate dynamic stamp tax based on velocity
/// tax_bps = base + (transfer_count_in_window * scaling_factor)
/// Clamped to [base, max]
///
/// **BUG 4**: Unchecked addition — tax_bps can overflow
pub fn dynamic_stamp_tax(
    transfer_count: u64,
    base_bps: u64,
    max_bps: u64,
    scaling_bps_per_transfer: u64,
) -> u64 {
    // BUG: No overflow check on multiplication
    let additional = transfer_count * scaling_bps_per_transfer; // ← OVERFLOW!
    let tax = base_bps + additional; // ← OVERFLOW!

    if tax > max_bps {
        max_bps
    } else if tax < base_bps {
        base_bps
    } else {
        tax
    }
}

/// Calculate stamp tax amount for a given transfer
/// tax_amount = amount * tax_bps / 10_000
///
/// **BUG**: Unchecked multiplication can overflow
pub fn stamp_tax_amount(amount: u64, tax_bps: u64) -> u64 {
    // BUG: No overflow check!
    amount * tax_bps / 10_000 // ← OVERFLOW!
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_balance_normal() {
        assert_eq!(effective_balance(100, 1), 100);
        assert_eq!(effective_balance(100, 5), 500); // 1:5 split
    }

    #[test]
    fn test_proportional_payout() {
        // User has 100 out of 1000 supply, pool has 500 USDC
        let payout = proportional_payout(100, 500, 1000);
        assert_eq!(payout, 50); // 10% of 500 = 50
    }

    #[test]
    fn test_dynamic_stamp_tax_normal() {
        let tax = dynamic_stamp_tax(0, 10, 500, 5);
        assert_eq!(tax, 10); // No transfers → base rate

        let tax = dynamic_stamp_tax(50, 10, 500, 5);
        // 50 * 5 = 250, 10 + 250 = 260 bps = 2.6%
        assert_eq!(tax, 260);
    }

    #[test]
    fn test_dynamic_stamp_tax_clamped_to_max() {
        let tax = dynamic_stamp_tax(1000, 10, 500, 10);
        // 1000 * 10 = 10000, 10 + 10000 > 500 → clamped to 500
        assert_eq!(tax, 500);
    }

    #[test]
    fn test_stamp_tax_amount() {
        assert_eq!(stamp_tax_amount(1000, 10), 1); // 0.1% of 1000 = 1
        assert_eq!(stamp_tax_amount(100000, 500), 5000); // 5% of 100000 = 5000
    }

    #[test]
    fn test_div_fixed() {
        // 1 / 2 = 0.5 in fixed point = 2^63
        let half = div_fixed(1, 2);
        assert_eq!(half, 1u64 << 63);
    }
}