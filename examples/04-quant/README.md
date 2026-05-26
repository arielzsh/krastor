# 04-quant — High-Frequency Quantitative Trading & Copy-Trading

> 🚧 Placeholder — developed by another team

A **high-frequency cryptocurrency quantitative trading and automated copy-trading system** on Solana.

## Target Features

- Strategy registration (upload quant strategy parameters)
- Automated execution engine (bot-driven trades)
- Copy-trading (follow leader's trades proportionally)
- Performance fee distribution
- Risk management (max drawdown, stop-loss)
- Leaderboard + reputation system

## Intentional Bugs (Krastor Targets)

| # | Bug | Proptest | Krastor |
|---|-----|----------|---------|
| 1 | Strategy parameter manipulation | 0% — no auth model | `replace_owner` + `swap_signer` |
| 2 | Copy-trade ratio overflow | ~0% — rare large values | `flip_data` 40%/round |
| 3 | Performance fee front-running | 0% — no tx ordering | auto-sequence: trade → fee → trade |
| 4 | Stop-loss bypass via oracle lag | 0% — no oracle model | auto-sequence + stale price |
| 5 | Reputation score manipulation | 0% — no multi-round state | `flip_data` + invariant checks |
| 6 | Max drawdown calculation overflow | ~0% — financial math | `flip_data` targets ratio limits |

## Reference

- Numerai, Enzyme Finance, dHedge

---

*Built by arielzsh 🦭 with Krastor · Bubblegum Labs 🫧 — example program for fuzzer validation*