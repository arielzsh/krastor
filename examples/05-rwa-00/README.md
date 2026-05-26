# 05-rwa-00 — Tokenized Government & Corporate Bonds

> 🚧 Placeholder — developed by another team

A **real-world asset platform for tokenizing government and corporate bonds** on Solana.

## Target Features

- Bond issuance (create bond token backed by real bond)
- KYC/Accreditation whitelist
- Coupon payment distribution (periodic yield)
- Maturity redemption (burn tokens → claim principal + interest)
- Secondary market trading (AMM)
- Compliance module (transfer restrictions, jurisdiction checks)

## Intentional Bugs (Krastor Targets)

| # | Bug | Proptest | Krastor |
|---|-----|----------|---------|
| 1 | Coupon precision loss (fixed-point) | ~0% — complex math | `flip_data` targets decimal precision |
| 2 | Whitelist bypass (no owner check) | 0% — no auth model | `replace_owner` 10%/round |
| 3 | Redemption double-spend (non-atomic) | 0% — no two-phase | auto-sequence: redeem → redeem again |
| 4 | Maturity date manipulation (Clock) | 0% — no time model | `flip_data` + Clock sysvar |
| 5 | Interest compound overflow | ~0% — extreme values | `flip_data` 40%/round |
| 6 | Compliance module bypass | 0% — no permission model | `swap_signer` + `replace_owner` |
| 7 | Transfer restriction evasion | 0% — no state model | auto-sequence + `flip_data` |

## Reference

- Ondo Finance, Maple Finance, Centrifuge

---

*Built by arielzsh 🦭 with Krastor · Bubblegum Labs 🫧 — example program for fuzzer validation*