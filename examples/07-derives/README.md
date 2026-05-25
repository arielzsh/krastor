# 07-derives — Advanced Financial Derivatives (Portfolio Margin + Order Book)

> 🚧 Placeholder — developed by another team

An **advanced financial derivatives system supporting portfolio margin and order books**, benchmarking Injective Protocol on Solana.

## Target Features

- Perpetual futures with funding rate
- Options (European, American, exotic)
- Portfolio margin (cross-asset risk calculation)
- Order book (limit orders, market orders, stop-loss)
- Liquidations engine (partial, full, insurance fund)
- Oracle integration (Pyth low-latency feeds)
- Vault strategies (delta-neutral, covered calls)
- Cross-margin and isolated margin modes

## Intentional Bugs (Krastor Targets)

| # | Bug | Proptest | Krastor |
|---|-----|----------|---------|
| 1 | Zero-Copy account data race | 0% — no parallel model | `flip_data` concurrent writes |
| 2 | Fixed-point division precision loss | ~0% — complex math | `flip_data` targets decimal edge |
| 3 | Liquidation time window exploit | 0% — no oracle+time model | auto-sequence + Clock + price change |
| 4 | Funding rate sign inversion | ~0% — rare sign flip | `flip_data` corrupts rate field |
| 5 | Portfolio VaR covariance miscalc | 0% — no financial model | `flip_data` targets matrix values |
| 6 | Order book matching engine race | 0% — no ordering model | auto-sequence: buy → sell → match |
| 7 | Insurance fund drain via spam | 0% — no pool model | `zero_lamports` + `flip_data` |
| 8 | Auto-deleveraging cascading failure | 0% — needs multi-step | auto-sequence: liq → liq → liq |
| 9 | Hybrid (off-chain→on-chain) bypass | 0% — no hybrid model | `flip_data` corrupts verification data |
| 10 | MEV front-run of liquidation | 0% — no MEV model | auto-sequence: price change → liquidate |

## Architecture (5-Layer Design)

```
L1: Account Model       — Zero-Copy, Sealevel parallelization
L2: Computational Layer — Black-Scholes off-chain, Lookup tables on-chain
L3: Risk & Liquidation  — Jito MEV bundles, multi-dimensional risk matrix
L4: Oracle              — Pyth 400ms feeds + confidence intervals
L5: Liquidity & Vaults  — Tranche-based senior/junior pools
```

## Reference

- Injective Protocol, Zeta Markets, Drift Protocol, Cega, Jito

---

*Built by arielzsh 🦭 with Krastor — example program for fuzzer validation*