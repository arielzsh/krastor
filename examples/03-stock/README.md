# 03-stock — Fractional Equity Distribution Platform

> 🚧 Placeholder — developed by another team

A **micro-fractionalization and distribution platform** for high-barrier traditional equities (e.g., Tesla, Apple) on Solana.

## Target Features

- Stock token issuance (1 stock = N tokens, fractional)
- Real-time price oracle (Pyth/Chainlink)
- Trading (AMM or orderbook)
- Dividend distribution from real stock dividends
- Corporate actions (stock split, merge, dividend)
- Short selling with borrow/lend pool
- Margin trading with leverage

## Intentional Bugs (Krastor Targets)

| # | Bug | Proptest | Krastor |
|---|-----|----------|---------|
| 1 | Stock split token miscalculation | 0% — no split model | `flip_data` corrupts split ratio |
| 2 | Dividend snapshot/execution desync | 0% — no time model | auto-sequence: deposit → snapshot → withdraw |
| 3 | Short sell collateral unlocked | 0% — no pool state | `zero_lamports` + `flip_data` |
| 4 | Margin liquidation price error | ~0% — no financial math | `flip_data` targets price/ratio |
| 5 | Oracle staleness exploited | 0% — no oracle model | auto-sequence + time warp |
| 6 | Corporate action vote weight bug | 0% — no governance model | `flip_data` corrupts vote weights |

## Reference

- Synthetify, Mango Markets, Drift Protocol

---

*Built by arielzsh 🦭 with Krastor · Bubblegum Labs 🫧 — example program for fuzzer validation*