# 06-gamefi — Virtual RPG with On-Chain Weapon Crafting & Forging

> 🚧 Placeholder — developed by another team

A **virtual RPG GameFi ecosystem featuring on-chain weapon crafting and equipment forging** on Solana.

## Target Features

- Player registration (create hero account)
- Quest completion (earn tokens/XP)
- Weapon crafting (combine materials → weapon with random stats)
- Equipment forging (upgrade weapon tier with rare materials)
- PvP battle (wager match with stat-based outcome)
- Staking (lock weapons/items for passive yield)
- Marketplace (trade crafted items)
- Leaderboard + seasonal rewards

## Intentional Bugs (Krastor Targets)

| # | Bug | Proptest | Krastor |
|---|-----|----------|---------|
| 1 | Quest reward farming (no cooldown) | 0% — no time model | auto-sequence: quest → quest → quest |
| 2 | Craft stat overflow (unchecked +) | ~0% — rare values | `flip_data` 40%/round |
| 3 | Equipment forging tier skip | 0% — no tier model | `flip_data` corrupts tier |
| 4 | PvP wager double-claim | 0% — no two-phase | auto-sequence: battle → claim → claim |
| 5 | Staking reward time manipulation | 0% — no Clock awareness | `flip_data` + Clock sysvar |
| 6 | Item duplication via transfer+craft | 0% — no state race | auto-sequence: craft → transfer → craft |

## Reference

- Star Atlas, Aurory, Genopets, StepN

---

*Built by arielzsh 🦭 with Krastor · Bubblegum Labs 🫧 — example program for fuzzer validation*