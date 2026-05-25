# 02-nft — Pixel Art NFT (Fully On-chain Generative Art Engine)

> 🚧 Placeholder — developed by another team

Reminiscent of CryptoMonkeys, this project is a **fully on-chain generative pixel art NFT engine** built on Solana.

## Target Features

- On-chain SVG/pixel art generation from deterministic seed
- Mint with metadata (name, URI, attributes)
- Transfer between owners
- List/Delist on marketplace
- Buy/Sell with royalties

## Intentional Bugs (Krastor Targets)

| # | Bug | Proptest | Krastor |
|---|-----|----------|---------|
| 1 | Mint without supply cap check | 0% — no cap model | `flip_data` + counter overflow |
| 2 | Transfer without owner check | 0% — no auth model | `replace_owner` 10%/round |
| 3 | Royalty arithmetic overflow | ~0% — rare extreme | `flip_data` 40%/round |
| 4 | Metadata not verified (fake NFT) | 0% — no validation model | `flip_data` corrupts metadata |
| 5 | Marketplace escrow stuck | 0% — no two-phase state | auto-sequence: list → buy → cancel |

## Reference

- Metaplex Token Metadata
- CryptoMonkeys / Solana Monkey Business

---

*Built by arielzsh 🦭 with Krastor — example program for fuzzer validation*