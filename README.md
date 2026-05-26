# Krastor 🦭🔧

> Coverage-guided Solana program fuzzer powered by **LiteSVM** — no external validator needed.

Krastor fuzzes Anchor programs by generating random instruction sequences with Solana-aware account mutations, executing them against an embedded LiteSVM runtime, and checking user-defined invariants.

## Architecture

```
Fuzzer::run_one_round()
  ├─ random_action()         → pick random instruction + account params
  ├─ mutate_accounts()       → Solana-aware directed mutations (6 types)
  ├─ LiteSVM::execute()      → deploy + construct + submit transaction
  ├─ check_invariants()      → user-defined post-condition checks
  └─ crash record            → minimal reproducible input (binary search shrinker)
```

## Crates

| Crate | Description |
|-------|-------------|
| `fuzz-core` | Core engine: fuzzer, mutators, invariants, crash shrinking, LiteSVM executor |
| `idl-parser` | Anchor IDL JSON parser + Rust harness code generator |
| `cli` | `cargo-krastor` binary: `init`, `fuzz run`, `fuzz repro`, `fuzz coverage` |
| `instrumentor` | SBF ELF disassembler + static instrumentation + coverage bitmap |
| `report` | Self-contained HTML coverage report + CI template |

## Quick Start

```bash
# Install
cargo install cargo-krastor

# Generate fuzz harness from Anchor IDL
cargo krastor init --idl target/idl/your_program.json

# Run fuzzer
cargo krastor fuzz run --program target/deploy/your_program.so --iterations 100000

# Reproduce a crash
cargo krastor fuzz repro crash_0001.json
```

## Mutation Types

| Mutation | Probability | Description |
|----------|------------|-------------|
| `flip_data` | 40% | Random byte flips in account data |
| `swap_signer` | 15% | Toggle signer flag on accounts |
| `replace_owner` | 10% | Randomize account owner |
| `zero_lamports` | 10% | Set account balance to 0 |
| `mutate_seeds` | 10% | Corrupt PDA seeds |
| `clear_data` | 5% | Zero out account data |

## Built-in Invariants

- **Supply Conservation**: total lamports ≈ preserved across transactions
- **Owner Immutability**: account owner never changes unexpectedly
- **Signer Authorization**: only signer accounts can mutate state

## Example: Vulnerable Program

```rust
// Bug 1: unchecked arithmetic overflow
vault.total_supply += amount;   // 💥

// Bug 2: no owner check on withdraw
vault.total_supply -= amount;   // 💥

// Bug 3: borrow counter race condition
vault.total_borrowed += amount; // 💥
```

Krastor catches all three within ~1000 iterations.

## Requirements

- Rust 1.86+
- Solana CLI 2.x (for `cargo build-sbf` to compile test programs)
- LiteSVM 0.7 (embedded, no external validator process)

## License

MIT © arielzsh / Bubblegum Labs 🫧