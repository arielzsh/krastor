# 05-rwa-01 — Carbon Credits RWA

> 🚧 Placeholder — developed by another team

A **real-world asset tokenization system based on the carbon emissions market** on Solana.

## Target Features

- Carbon credit token issuance (1 token = 1 ton CO2 equivalent)
- Verification oracle (third-party auditor attestation)
- Retirement/burning (permanently remove credits from circulation)
- Trading marketplace (buy/sell carbon credits)
- Vintage tracking (year of issuance affects price)
- Project registry (track offset project metadata)
- Compliance reporting (regulatory-grade audit trail)

## Intentional Bugs (Krastor Targets)

| # | Bug | Proptest | Krastor |
|---|-----|----------|---------|
| 1 | Double-counting of retired credits | 0% — no retirement model | auto-sequence: retire → transfer |
| 2 | Verification oracle spoofing | 0% — no oracle model | `replace_owner` on oracle account |
| 3 | Vintage price miscalculation | ~0% — time-based math | `flip_data` + Clock manipulation |
| 4 | Burn without ownership check | 0% — no auth model | `swap_signer` 15%/round |
| 5 | Project registry overwrite | 0% — no re-init detection | auto-sequence: register → register (overwrite) |
| 6 | Offset credit mismatch (1 ≠ 1 ton) | ~0% — precision | `flip_data` corrupts ratio |

## Reference

- Toucan Protocol, KlimaDAO, Moss.Earth

---

*Built by arielzsh 🦭 with Krastor · Bubblegum Labs 🫧 — example program for fuzzer validation*