# 🦭 Meme Coin — Krastor Fuzzing Demo

> ⚠️ **DEMO ONLY — NOT FOR PRODUCTION. Contains 6 intentional bugs.**

A fair-launch meme coin with AMM trading. Built to demonstrate Krastor's Solana-aware fuzzing vs generic property-based testing.

---

## Quick Start

### 1. Build the program

```bash
cd examples/meme-coin
cargo build-sbf
```

### 2. Generate fuzz harness from IDL

```bash
# Generate Anchor IDL first
anchor build

# Generate Krastor fuzz harness
cd ../..  # back to krastor root
cargo krastor init --idl examples/meme-coin/target/idl/meme_coin.json
```

### 3. Run the fuzzer

```bash
cargo krastor fuzz run \
  --program target/deploy/meme_coin.so \
  --iterations 100000 \
  --output crash_reports/
```

### 4. Reproduce a crash

```bash
cargo krastor fuzz repro crash_reports/crash_0001.json
```

---

## The 6 Bugs

### Bug 1: Mint Authority Never Revoked 🔥

**Location**: `create_pool()`

```rust
// BUG: mint authority = creator, and it's NEVER revoked
mint::authority = creator,
```

**How to reproduce**:
1. `create_pool(1000)` — creator mints 1000 initial tokens
2. Krastor runs `evil_mint(target, 1_000_000)` — creator mints 1M more tokens (still authorized!)
3. Krastor runs `sell(1_000_000)` — drains the pool
4. **Crash detected**: pool reserves went negative

**Krastor mutator**: `replace_owner` (10%/round) — targets the creator key field

### Bug 2: AMM Overflow 🔥

**Location**: `buy()`, `sell()`

```rust
// BUG: unchecked multiplication
let numerator = pool.token_reserve * sol_after_fee; // ← OVERFLOW!
```

**How to reproduce**:
1. Krastor's `flip_data` sets `token_reserve` to `u64::MAX / 2`
2. `buy(u64::MAX / 2 + 1)` → `token_reserve * sol_after_fee` > u64::MAX → silent overflow
3. Token amount becomes nonsensically small
4. **Crash detected**: invariant `supply_conservation` fails

**Krastor mutator**: `flip_data` (40%/round) — injects extreme reserve values

### Bug 3: No Slippage Protection 🔥

**Location**: `buy()`, `sell()` — missing `minimum_out` check

```rust
// BUG: no min_out parameter
require!(token_out > 0, MemeCoinError::InsufficientLiquidity);
// Missing: require!(token_out >= min_out, SlippageExceeded);
```

**How to reproduce**:
1. Krastor generates sequence: `buy(1000) → buy(1000) → sell(1000)`
2. Second `buy` front-runs the first, changing the price
3. User receives fewer tokens than expected
4. **Crash detected**: invariant violation on expected vs actual output

**Krastor mutator**: auto-sequence discovery — generates sandwich patterns

### Bug 4: LP Ratio Miscalculation 🔥

**Location**: `add_liquidity()`

```rust
// BUG: doesn't handle imbalanced deposits
let sol_share = sol_in * pool.lp_supply / pool.sol_reserve;
let token_share = token_in * pool.lp_supply / pool.token_reserve;
sol_share.min(token_share) // ← wrong! Should use the LOWER ratio
```

**How to reproduce**:
1. Create pool with 1:1 ratio (1000 SOL : 1000 TOKEN)
2. Krastor runs `buy(500)` → ratio becomes 1500:667
3. Krastor runs `add_liquidity(1000, 1000)` → deposits 1000:1000 into imbalanced pool
4. LP receives fewer LP tokens than deserved (excess donated to pool)
5. **Crash detected**: LP's withdraw_value < deposit_value

**Krastor mutator**: `flip_data` + auto-sequence → imbalanced pool state

### Bug 5: Fee Bypass 🔥

**Location**: `buy()`

```rust
// BUG: integer division truncates to 0 for small amounts
let fee = sol_in * FEE_BPS / FEE_DENOMINATOR;
// For sol_in < 333: fee = 333 * 30 / 10000 = 9990 / 10000 = 0
```

**How to reproduce**:
1. Krastor explores small `sol_in` values (via `flip_data`)
2. Buys with `sol_in = 332` × 1000 times → pays 0 fees
3. Pool lost expected fee income
4. **Crash detected**: `total_fees_collected` < expected by invariant

**Krastor mutator**: `flip_data` (40%/round) — explores edge amounts

### Bug 6: Reserve Underflow via Flash Loan 🔥

**Location**: `sell()`

```rust
// BUG: underflow if token_reserve was manipulated
pool.sol_reserve = pool.sol_reserve - sol_out; // ← UNDERFLOW!
```

**How to reproduce**:
1. Krastor's `zero_lamports` sets pool lamports to 0
2. Krastor's `flip_data` inflates `token_reserve` to u64::MAX
3. Krastor generates: `sell(u64::MAX / 2)` → `sol_out` > `sol_reserve` → underflow
4. **Crash detected**: sol_reserve wraps to u64::MAX (phantom SOL created!)

**Krastor mutator**: `zero_lamports` + `flip_data` → flash-loan-like conditions

---

## Proptest + LiteSVM vs Krastor

### Setup Comparison

#### Proptest + LiteSVM

```rust
// Proptest: manually define strategy for EVERY parameter
use proptest::prelude::*;
use litesvm::LiteSVM;

proptest! {
    #[test]
    fn fuzz_buy(sol_in in 0u64..) {
        let mut svm = LiteSVM::new();
        // Manual setup: deploy program, create accounts...
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
        svm.add_program(program_id, &program_bytes).unwrap();
        // Manual: create pool account, token accounts...
        // ~50 lines of boilerplate per test

        // Call buy with random sol_in
        let result = call_buy(&mut svm, sol_in);
        prop_assert!(result.is_ok());
    }
}
```

**Problems**:
- 50+ lines boilerplate per test function
- Must manually define `sol_in` strategy (can't auto-discover edge values)
- No account mutation — proptest only varies function parameters
- No instruction sequencing — tests one call at a time
- No invariants — proptest asserts `is_ok()` but can't detect state corruption
- Can't target Solana-specific fields (owner, signer, lamports, seeds)

#### Krastor

```rust
// Krastor: zero-config auto-fuzzing
let mut fuzzer = Fuzzer::new("MemeCoin1111111111111111111111111111111111");
fuzzer.deploy_program_from_file("target/deploy/meme_coin.so")?;

// Zero-config: IDL → auto-generated instruction registry
fuzzer.register_instruction("create_pool", [0x01; 8]);
fuzzer.register_instruction("buy", [0x02; 8]);
fuzzer.register_instruction("sell", [0x03; 8]);
fuzzer.register_instruction("add_liquidity", [0x04; 8]);
fuzzer.register_instruction("remove_liquidity", [0x05; 8]);
fuzzer.register_instruction("evil_mint", [0x06; 8]);

// Auto-mutation: 6 Solana-aware mutators
// Auto-sequence: random instruction sequences
// Auto-invariants: supply conservation, owner immutability, signer auth
// Coverage guidance: AFL-style bitmap

for round in 0..100_000 {
    let result = fuzzer.run_one_round();
    if result.is_crash {
        println!("💥 Crash at round {}: {:?}", round, result.execution_error);
        fuzzer.crashes.push(CrashRecord::from_result(&result));
        break; // or continue to find more
    }
}
```

**Advantages**:
- 15 lines of code for complete fuzzing (vs 50+ per-test with proptest)
- 6 targeted mutation types, not 1
- Auto-generates instruction sequences
- Built-in invariant checking
- Coverage guidance reaches deep paths
- Crash shrinking produces minimal reproducible inputs

### Probability Comparison (per round)

| Bug | Proptest + LiteSVM | Krastor |
|-----|-------------------|---------|
| B1: Mint auth not revoked | 0% — no auth model | 10%/round |
| B2: AMM overflow | ~0% — random rarely extreme | 40%/round |
| B3: No slippage protection | 0% — no sequence model | auto-generated |
| B4: LP ratio skew | ~0% — no state mutation | 40%/round |
| B5: Fee bypass | ~0.3% — can't detect | 40%/round |
| B6: Reserve underflow | 0% — needs multi-step | 10%+40%/round |

### Lines of Code Comparison

```
Proptest + LiteSVM approach:
  buy test:         60 lines
  sell test:        60 lines
  add_liq test:     70 lines
  remove_liq test:  70 lines
  evil_mint test:   50 lines
  create_pool test: 80 lines
  Total:           390 lines (for 6 bugs, each testing ONE instruction)

Krastor approach:
  fuzz harness:     15 lines (for ALL 6 bugs, testing ALL instructions)
  + invariants:      3 lines (supply conservation, owner check, signer check)
  Total:            18 lines
```

### What Proptest + LiteSVM CAN Do

Proptest + LiteSVM is excellent for:
- Testing pure functions (no state) on Solana
- Fuzzing serialization/deserialization of account types
- Simple invariant testing on isolated instructions
- When you NEED to write custom strategies for specific edge cases

### What Proptest + LiteSVM CANNOT Do

- **Authorization bypass detection** — no concept of who SHOULD be authorized
- **Multi-instruction sequence attacks** — tests one instruction at a time
- **State corruption between instructions** — no intermediate state checks
- **Solana-specific field attacks** — treats accounts as `Vec<u8>`
- **Coverage-guided path exploration** — uniform random, no feedback

---

## Run It Yourself

```bash
# Clone and build Krastor
git clone https://github.com/arielzsh/krastor
cd krastor
cargo build --release

# Build the vulnerable meme coin
cd examples/meme-coin
cargo build-sbf

# Run the fuzzer
cd ../..
cargo run --release -- fuzz run \
  --program target/deploy/meme_coin.so \
  --iterations 50000

# Expected output:
# 💥 Crash #1 at round 12: Mint authority bypass (evil_mint succeeded)
# 💥 Crash #2 at round 87: AMM overflow in buy()
# 💥 Crash #3 at round 143: Pool reserve underflow in sell()
# 💥 Crash #4 at round 231: LP ratio exploit detected
# ...
```

---

*Built by arielzsh 🦭 with Krastor + LiteSVM*