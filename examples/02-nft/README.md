# 02-nft — Fully On-Chain Generative Pixel Art NFT

> 🦭 CrazyMonkey-style NFT engine. All-art-on-chain. 5 intentional bugs.

## Quick Start

```bash
cd examples/02-nft
cargo build-sbf
```

## Features

- **On-chain art generation**: 8×8 pixel art generated deterministically from traits
- **5 trait types**: background, body, eyes, mouth, hat (16 variants each)
- **Marketplace**: list/buy with royalty enforcement
- **Fully on-chain**: no external metadata URIs, no IPFS — everything lives on Solana

## Instructions

| Instruction | Description | Bug |
|-------------|-------------|-----|
| `initialize_collection` | Create collection with name, symbol, max_supply | — |
| `mint` | Mint NFT with random traits + pixel art | BUG 1,4 |
| `transfer` | Transfer NFT to new owner | BUG 2 |
| `list` | List NFT for sale | BUG 5 |
| `buy` | Buy listed NFT | BUG 3,5 |

## 5 Intentional Bugs

### Bug 1: Supply Cap Not Enforced 🔥

```rust
// Missing: require!(total_minted < max_supply, MaxSupplyReached);
config.total_minted += 1;
```

| Proptest | Krastor |
|----------|---------|
| 0% — no cap model | `flip_data` pushes total_minted past max_supply |

### Bug 2: Transfer Without Owner Check 🔥

```rust
// Missing: require!(sender.key() == nft.owner, NotOwner);
nft.owner = receiver.key();
```

Anyone can steal anyone's NFT.

| Proptest | Krastor |
|----------|---------|
| 0% — no auth model | `replace_owner` 10%/round |

### Bug 3: Royalty Calculation Overflow 🔥

```rust
let royalty = price * collection.royalty_bps / 10000; // ← OVERFLOW!
```

| Proptest | Krastor |
|----------|---------|
| ~0% | `flip_data` 40%/round |

### Bug 4: Metadata Re-initialization 🔥

```rust
// init constraint — fails if PDA exists, but close+reopen bypasses
```

| Proptest | Krastor |
|----------|---------|
| 0% | auto-seq: mint→close→mint |

### Bug 5: Marketplace Escrow Atomicity 🔥

```rust
// No check that listing.seller == nft.owner at purchase time
```

Seller lists, transfers, then buyer pays wrong seller.

| Proptest | Krastor |
|----------|---------|
| 0% | auto-seq: list→transfer→buy |

---

*Built by arielzsh 🦭 with Krastor · Bubblegum Labs 🫧 — example program for fuzzer validation*