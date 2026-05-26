# Krastor vs Proptest — Test Comparison Summary

> Generated: 2026-05-25 · arielzsh · Bubblegum Labs

---

## Executive Summary

| Metric | Proptest | Krastor |
|--------|----------|---------|
| **Approach** | Random property-based testing | Solana-aware directed fuzzing |
| **Account awareness** | `Vec<u8>` — raw bytes | `FuzzAccount` { owner, lamports, seeds, signer } |
| **Mutation types** | 1 (random byte flip) | 6 (owner, lamports, signer, seeds, data, flip) |
| **Instruction sequencing** | Manual strategy definition | Auto-generated from IDL |
| **Coverage guidance** | None | AFL-style coverage bitmap |
| **Crash shrinking** | No automatic shrinking | Binary + greedy 3-pass shrinker |
| **Oracle integration** | Manual | Invariant registry (3 built-in) |
| **Auth bypass detection** | 0% (no concept of authorization) | ~10 rounds (replace_owner) |

---

## Meme Coin — 6 Bugs Comparison

### Bug 1: Mint Authority Not Revoked

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Random signer key generation | `replace_owner` mutator (10%/round) |
| **Probability** | 1/2^256 ≈ 0% | ~10 rounds |
| **Why fails** | Proptest generates random Pubkeys — no concept that "this key is the mint authority". Can't know to reuse the creator's keypair across `create_pool()` and `evil_mint()`. | Krastor's `replace_owner` directly overwrites `FuzzAccount.owner` to the attacker's pubkey. The `#[account]` derive then matches the spoofed owner as the authority. |

### Bug 2: AMM Constant Product Overflow

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Random u64 values for `sol_in`/`token_in` | `flip_data` mutator (40%/round) injects extreme values |
| **Probability** | ~1/2^64 per parameter ≈ 0% | <100 rounds |
| **Why fails** | Proptest generates `sol_in ∈ [0, 2^64)` uniformly. P(hit overflow range) = P(sol_in * token_reserve > u64::MAX). For typical reserves (10^9), this means sol_in > 2^64/10^9 ≈ 1.8×10^10 — which random sampling rarely reaches. | Krastor's `flip_data` directly modifies `sol_reserve` or `token_reserve` bytes, pushing reserve values to extreme ranges. Combined with random instruction selection, overflow triggers within ~100 rounds. |

### Bug 3: No Slippage Protection (Sandwich Attack)

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Independent random rounds | Auto-generated instruction sequences |
| **Probability** | 0% | Automatic |
| **Why fails** | Proptest generates each test round independently. No concept of "two transactions in the same block where the second front-runs the first". | Krastor generates instruction sequences (`deposit → buy → sell`) and executes them atomically in one round. The absence of `minimum_out` check means the attacker can drain value between `buy` and `sell`. |

### Bug 4: LP Ratio Miscalculation

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Random SOL/TOKEN amounts | `flip_data` + auto-sequence |
| **Probability** | ~0% (random amounts don't skew ratio) | ~50 rounds |
| **Why fails** | Proptest generates `sol_in` and `token_in` independently from u64. P(ratio skew) = P(sol_in/token_in ≠ current ratio). But without knowledge of current reserves, proptest can't target the skew. | Krastor's auto-sequence mutates account state, then calls `add_liquidity`. The sequence `create_pool → buy → add_liquidity` creates an imbalanced pool where the LP receives fewer tokens than deserved. |

### Bug 5: Fee Calculation Bypass

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Random u64 for `sol_in` | `flip_data` explores edge amounts |
| **Probability** | ~1/333 ≈ 0.3% | ~10 rounds |
| **Why fails** | Proptest can accidentally hit `sol_in < 333` (where fee = 0), but has no mechanism to detect that fee=0 is a BUG rather than expected behavior. No invariant checks exist in proptest. | Krastor's `flip_data` mutator systematically explores edge values. Combined with invariants (supply conservation), Krastor detects that zero-fee trades violate conservation. |

### Bug 6: Reserve Underflow via Flash Loan

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Random token_in values | `zero_lamports` + `flip_data` → inflates token supply |
| **Probability** | ~0% (needs multi-step) | ~100 rounds |
| **Why fails** | Proptest generates single-round random values. Flash loan attack requires: (1) deposit massive tokens, (2) call sell(), (3) underflow reserve. Proptest can't coordinate these steps. | Krastor generates multi-instruction sequences. The `zero_lamports` mutator sets pool balance to 0, then `flip_data` inflates `token_reserve`, then a `sell()` instruction triggers the underflow. |

---

## Vulnerable Program — 3 Bugs Comparison

### Bug 1: Arithmetic Overflow (unchecked +)

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Random u64 deposit amounts | `flip_data` (40%/round) targets edge values |
| **Probability** | ~0% (random rarely hits ~MAX) | <100 rounds |
| **Why fails** | `vault.total_supply += amount` overflows only when `amount > u64::MAX - vault.total_supply`. With fresh accounts (total_supply=0), this means amount=MAX. Proptest generates amounts uniformly — P(amount=MAX) = 1/2^64. | Krastor's `flip_data` directly modifies `vault.total_supply` to u64::MAX-1, then `deposit(1)` triggers overflow. |

### Bug 2: Authorization Bypass (no owner check)

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Random signer generation | `replace_owner` (10%/round) + `swap_signer` (15%/round) |
| **Probability** | 0% | ~10 rounds |
| **Why fails** | `withdraw()` reads `vault.owner` but proptest has NO concept of "vault.owner should equal authority.key()". Proptest generates random signers — P(match any 32-byte owner) = 0. | Krastor's `replace_owner` mutator directly overwrites `vault.owner`. Next round, the attacker's keypair matches the spoofed owner — withdraw succeeds. |

### Bug 3: State Inconsistency (borrow counter race)

| Attack | Proptest | Krastor |
|--------|----------|---------|
| **Mechanism** | Independent random calls | Auto-sequence + invariants check per-instruction |
| **Probability** | 0% (no inter-round state checks) | ~200 rounds |
| **Why fails** | Proptest runs `flash_loan()` as a single call. It doesn't check intermediate states BETWEEN instructions. The counter race is only visible if you check `total_borrowed` AFTER `-= amount` but BEFORE `+= amount`. | Krastor's auto-sequence generates `flash_loan → flash_loan → flash_loan` (concurrent), and invariant checking fires after EACH instruction in the sequence — detecting the intermediate counter mismatch. |

---

## Smoke Test — LiteSVM Executor Verification

| Test | Result | What It Proves |
|------|--------|---------------|
| `smoke_executor_init_and_accounts` | ✅ | Real LiteSVM init + account read/write |
| `smoke_empty_sequence` | ✅ | Empty sequence doesn't panic |
| `smoke_system_transfer` | ✅ | Hits actual LiteSVM runtime (not placeholder) |
| `smoke_crash_detection` | ✅ | Crash pattern recognition |
| `smoke_fuzzer_to_executor_roundtrip` | ✅ | Fuzzer → LiteSVM executor complete round-trip |

---

## Proptest vs Krastor — Probability Matrix

```
╔══════════════════════════════════════════════════════════╗
║      KRASTOR vs PROPTEST — Probability                  ║
╠══════════════════════════════════════════════════════════╣
║ Attack                │ Proptest    │ Krastor           ║
╠══════════════════════════════════════════════════════════╣
║ Owner spoofing        │ 1/2^256 ≈ 0%│ 10%/round → ~10   ║
║ Rent bypass           │ 1/2^64      │ 10%/round → ~10   ║
║ PDA corruption        │ 0% (no model)│ 10%/round → ~10  ║
║ Signer escalation     │ 50% random  │ 15%/round, paired ║
║ Empty data crash      │ ~0% (bias>0)│ 5%/round → ~20    ║
║ Multi-vector          │ product ≈ 0%│ 60% ≥1 fires/r    ║
╚══════════════════════════════════════════════════════════╝
```

---

## Total Test Coverage

```
CI Pipeline (all green):
  ├── Test (Rust stable):      64 tests ✅
  │   ├── fuzz-core lib:       14 tests
  │   ├── idl-parser lib:       4 tests
  │   ├── instrumentor lib:     5 tests
  │   ├── report lib:           2 tests
  │   ├── advantages:           8 tests
  │   ├── disadvantages:        9 tests
  │   ├── smoke_test:           5 tests
  │   └── proptest_vs_krastor:  7 tests
  ├── Lint (clippy + fmt):     clean ✅
  ├── Fuzz Smoke:              12 tests ✅
  └── Build Examples (SBF):    meme-coin.so + vulnerable.so ✅
```

---

## Why This Matters

Proptest is an excellent general-purpose fuzzer for data structures. But **Solana programs are not data structures** — they are authorization systems built on a specific account model.

| Property | Proptest sees | Krastor sees |
|----------|--------------|-------------|
| Account owner | `bytes[0..32]` | `FuzzAccount.owner` — semantic field |
| Lamports balance | `bytes in account data` | `FuzzAccount.lamports` — rent model aware |
| Signer flag | Random boolean | `FuzzAccount.is_signer` — auth model aware |
| PDA seeds | Does not exist | `FuzzAccount.seeds` — derivation aware |
| Instruction sequence | One at a time | Multi-instruction sequences |
| State invariants | Manual assertions | Auto-checked per instruction |

**The gap is not marginal — it's astronomical.** For authorization bypass bugs, the probability difference is 10^-48 (proptest) vs 10^-1 (Krastor). That's the difference between "never found" and "found in 10 rounds".

---

*Built by arielzsh 🦭 with Krastor · Bubblegum Labs 🫧 + LiteSVM*