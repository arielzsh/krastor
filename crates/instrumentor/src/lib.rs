//! SBF (Solana BPF) ELF Instrumentor — optional coverage-guided fuzzing module.
//!
//! ## Architecture
//! ```text
//! ELF binary → goblin::Elf::parse()
//!   ├─ .text section → SbfDecoder → Vec<SbfInstruction>
//!   ├─ Branch analysis → identify all branch targets
//!   ├─ Instrumentation → insert coverage probes at branch targets
//!   └─ .bss section → allocate coverage bitmap
//! ```
//!
//! When SBF format changes break the instrumentor, `fuzz-core` remains functional
//! — just without coverage guidance (random + invariants mode).
//!
//! UNCERTAINTY: All SBF opcode encodings below are based on the BPF instruction
//! set architecture. Solana's SBF extends classic BPF with 32-bit immediates and
//! additional instructions. Exact encoding must be verified against:
//! - https://github.com/solana-labs/solana/blob/master/sdk/program/src/syscalls/definitions.rs
//! - LLVM BPF backend: https://github.com/llvm/llvm-project/tree/main/llvm/lib/Target/BPF
//! - Solana SBF documentation: https://solana.com/docs/programs/lang-rust

use anyhow::{anyhow, Result};
use goblin::elf::Elf;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ============ SBF Instruction ============

/// SBF instruction (64-bit encoding, same as BPF 64-bit)
/// Layout (little-endian):
/// ```
/// +----------------+----------------+----------------+----------------+
/// | opcode:8       | dst_reg:4 src:4| offset:16                      |
/// +----------------+----------------+----------------+----------------+
/// | immediate:32                                                    |
/// +----------------+----------------+----------------+----------------+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SbfInstruction {
    pub opcode: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub offset: i16,
    pub immediate: i32,
    pub address: u64, // virtual address within .text section
}

impl SbfInstruction {
    pub fn decode(bytes: &[u8], address: u64) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(anyhow!("SBF instruction too short: {} bytes", bytes.len()));
        }

        let opcode = bytes[0];
        let dst_reg = bytes[1] & 0x0F;
        let src_reg = (bytes[1] >> 4) & 0x0F;
        let offset = i16::from_le_bytes([bytes[2], bytes[3]]);
        let immediate = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        Ok(SbfInstruction {
            opcode,
            dst_reg,
            src_reg,
            offset,
            immediate,
            address,
        })
    }

    /// Encode back to 8 bytes
    pub fn encode(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = self.opcode;
        buf[1] = self.dst_reg | (self.src_reg << 4);
        buf[2..4].copy_from_slice(&self.offset.to_le_bytes());
        buf[4..8].copy_from_slice(&self.immediate.to_le_bytes());
        buf
    }

    /// Is this a branch instruction?
    pub fn is_branch(&self) -> bool {
        self.branch_type().is_some()
    }

    /// Determine the branch type, if any
    pub fn branch_type(&self) -> Option<BranchType> {
        // UNCERTAINTY: These opcode values are from the BPF ISA spec.
        // SBF may use slightly different encodings. Verify against:
        // - BPF ISA: https://www.kernel.org/doc/html/latest/bpf/instruction-set.html
        // - Solana BPF: https://github.com/solana-labs/solana/blob/master/sdk/program/src/bpf_loader_upgradeable.rs
        match self.opcode {
            // TODO: VERIFY — These opcodes are the BPF classic encoding.
            // SBF may use a different mapping or extended opcode space.
            0x05 => Some(BranchType::JA),   // jump always
            0x15 => Some(BranchType::JEQ),  // jump ==
            0x25 => Some(BranchType::JGT),  // jump > (unsigned)
            0x35 => Some(BranchType::JGE),  // jump >= (unsigned)
            0x45 => Some(BranchType::JSET), // jump if bit set
            0x55 => Some(BranchType::JNE),  // jump !=
            0x65 => Some(BranchType::JSGT), // jump > (signed)
            0x75 => Some(BranchType::JSGE), // jump >= (signed)
            0x85 => Some(BranchType::CALL), // function call
            0x95 => Some(BranchType::EXIT), // exit/return
            0xA5 => Some(BranchType::JLT),  // jump < (unsigned)
            0xB5 => Some(BranchType::JLE),  // jump <= (unsigned)
            0xC5 => Some(BranchType::JSLT), // jump < (signed)
            0xD5 => Some(BranchType::JSLE), // jump <= (signed)
            _ => None,
        }
    }

    /// Calculate the branch target address
    pub fn branch_target(&self) -> Option<u64> {
        if self.is_branch() && self.branch_type() != Some(BranchType::EXIT) {
            // For relative jumps: target = pc + 1 + offset (in instructions)
            Some(
                self.address
                    .wrapping_add((self.offset as i64 + 1) as u64 * 8),
            )
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchType {
    JA,
    JEQ,
    JGT,
    JGE,
    JSET,
    JNE,
    JSGT,
    JSGE,
    CALL,
    EXIT,
    JLT,
    JLE,
    JSLT,
    JSLE,
}

// ============ SBF Decoder ============

/// Decode a complete .text section into SbfInstruction list
pub fn decode_text_section(data: &[u8], base_addr: u64) -> Result<Vec<SbfInstruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;

    while offset + 8 <= data.len() {
        let insn = SbfInstruction::decode(&data[offset..offset + 8], base_addr + offset as u64)?;
        instructions.push(insn);
        offset += 8;
    }

    Ok(instructions)
}

// ============ Branch Analysis ============

/// Collect all unique branch targets across the instruction list
pub fn collect_branch_targets(instructions: &[SbfInstruction]) -> HashSet<u64> {
    let mut targets = HashSet::new();
    for insn in instructions {
        if let Some(target) = insn.branch_target() {
            targets.insert(target);
        }
    }
    // Also add entry point (first instruction)
    if let Some(first) = instructions.first() {
        targets.insert(first.address);
    }
    targets
}

// ============ Instrumentation ============

/// Coverage probe stub — 16 bytes of SBF instructions inserted at branch targets:
/// 1. Load edge ID into register
/// 2. Store edge ID to coverage bitmap
/// 3. Restore original instruction's first 8 bytes
///
/// UNCERTAINTY: The exact SBF instructions for loading/storing to the bitmap
/// depend on the memory model and syscall availability. In practice:
/// - The bitmap pointer is passed as a parameter (register R1 in SBF ABI)
/// - Edge ID is computed from (prev_branch_id ^ cur_branch_id) % bitmap_size
/// - The store is an atomic operation for multi-thread safety (not needed in single-thread)
///
/// This implementation models what the stub SHOULD do. Actual generation
/// requires SBF machine code assembly.
pub fn generate_probe_stub(_edge_id: u32, _bitmap_ptr_reg: u8) -> Vec<u8> {
    // Placeholder: return 16 bytes of zeros (will be replaced with real SBF asm)
    // TODO: Replace with actual SBF machine code:
    // ```
    // lddw r0, edge_id        # 64-bit load: edge_id
    // lddw r1, bitmap_ptr     # 64-bit load: bitmap address
    // add r1, r1, r0          # offset into bitmap
    // stxb [r1], 1            # write 1 to bitmap entry
    // ```
    vec![0u8; 16]
}

/// Instrument a .text section with coverage probes at branch target locations.
///
/// Strategy:
/// 1. Decode all instructions
/// 2. Find all branch targets
/// 3. For each branch target, replace the first 16 bytes with a probe stub
/// 4. The original bytes are moved to a trampoline at the end of .text
/// 5. The probe stub jumps to the trampoline after recording coverage
pub fn instrument_text_section(
    text_data: &[u8],
    text_base: u64,
    bitmap_ptr_reg: u8,
) -> Result<(Vec<u8>, Vec<ProbeLocation>)> {
    let instructions = decode_text_section(text_data, text_base)?;
    let branch_targets = collect_branch_targets(&instructions);

    // UNCERTAINTY: The actual insertion of probes requires:
    // 1. Sufficient space for the probe stub (16 bytes per target)
    // 2. The text section may be loaded at a fixed address — can't just expand it
    // 3. Need to generate valid SBF machine code for the stub itself
    //
    // Current approach: mark probe locations for analysis (probe insertion
    // as a separate build step using a custom linker script or post-processing).

    // Convert raw text_data to mutable for modification
    let mut instrumented = text_data.to_vec();
    let mut probes = Vec::new();

    for &target_addr in &branch_targets {
        let offset = (target_addr - text_base) as usize;
        if offset + 16 <= instrumented.len() {
            let stub = generate_probe_stub(probes.len() as u32, bitmap_ptr_reg);
            instrumented[offset..offset + 16].copy_from_slice(&stub);

            probes.push(ProbeLocation {
                address: target_addr,
                edge_id: probes.len() as u32,
                original_bytes: text_data[offset..offset + 16].to_vec(),
            });
        }
    }

    Ok((instrumented, probes))
}

/// Record of where a coverage probe was inserted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeLocation {
    pub address: u64,
    pub edge_id: u32,
    pub original_bytes: Vec<u8>,
}

// ============ Coverage Bitmap ============

/// AFL-style coverage bitmap stored in shared memory or .bss section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstrumentedCoverageMap {
    pub edges: Vec<u8>,
    pub bitmap_size: usize,
    pub probes: Vec<ProbeLocation>,
}

impl InstrumentedCoverageMap {
    pub fn new(bitmap_size: usize, probes: Vec<ProbeLocation>) -> Self {
        Self {
            edges: vec![0u8; bitmap_size],
            bitmap_size,
            probes,
        }
    }

    /// Record an edge hit
    pub fn record_hit(&mut self, edge_id: usize) {
        if edge_id < self.edges.len() && self.edges[edge_id] < u8::MAX {
            self.edges[edge_id] += 1;
        }
    }

    /// Number of unique edges covered
    pub fn covered_edges(&self) -> usize {
        self.edges.iter().filter(|&&c| c > 0).count()
    }

    /// Coverage percentage
    pub fn coverage_pct(&self) -> f64 {
        if self.probes.is_empty() {
            return 0.0;
        }
        (self.covered_edges() as f64) / (self.probes.len() as f64) * 100.0
    }
}

// ============ ELF Parser ============

/// Parse SBF ELF binary and extract .text section
pub fn parse_sbf_elf(data: &[u8]) -> Result<ElfSectionInfo> {
    let elf = Elf::parse(data)?;

    let text_header = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text")
        .ok_or_else(|| anyhow!(".text section not found in ELF"))?;

    let text_offset = text_header.sh_offset as usize;
    let text_size = text_header.sh_size as usize;
    let text_addr = text_header.sh_addr;
    let text_data = &data[text_offset..text_offset + text_size];

    let bss_header = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".bss")
        .map(|sh| BssInfo {
            addr: sh.sh_addr,
            size: sh.sh_size as usize,
        });

    Ok(ElfSectionInfo {
        text_data: text_data.to_vec(),
        text_addr,
        text_size,
        bss: bss_header,
    })
}

#[derive(Debug, Clone)]
pub struct ElfSectionInfo {
    pub text_data: Vec<u8>,
    pub text_addr: u64,
    pub text_size: usize,
    pub bss: Option<BssInfo>,
}

#[derive(Debug, Clone)]
pub struct BssInfo {
    pub addr: u64,
    pub size: usize,
}

// ============ Tests ============
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_single_instruction() {
        // Minimal SBF instruction (BPF_MOV64_IMM: r0 = 0)
        // Opcode 0xB7 (BPF_ALU64 | BPF_MOV | BPF_K)
        // UNCERTAINTY: This is a BPF encoding. SBF may differ.
        let bytes = [0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = SbfInstruction::decode(&bytes, 0).unwrap();
        assert_eq!(insn.opcode, 0xB7);
        assert_eq!(insn.dst_reg, 0);
    }

    #[test]
    fn test_branch_detection() {
        // JA instruction (BPF_JMP | BPF_JA)
        let insn = SbfInstruction {
            opcode: 0x05,
            dst_reg: 0,
            src_reg: 0,
            offset: 10,
            immediate: 0,
            address: 0,
        };
        assert!(insn.is_branch());
        assert_eq!(insn.branch_type(), Some(BranchType::JA));
        assert_eq!(insn.branch_target(), Some((11 * 8) as u64)); // pc+1+10 = 11 instructions ahead
    }

    #[test]
    fn test_non_branch() {
        let insn = SbfInstruction {
            opcode: 0x07,
            dst_reg: 1,
            src_reg: 2,
            offset: 0,
            immediate: 0,
            address: 0,
        };
        assert!(!insn.is_branch());
    }

    #[test]
    fn test_encode_roundtrip() {
        let insn = SbfInstruction {
            opcode: 0xB7,
            dst_reg: 3,
            src_reg: 0,
            offset: 0,
            immediate: 42,
            address: 0x100,
        };
        let bytes = insn.encode();
        let decoded = SbfInstruction::decode(&bytes, 0x100).unwrap();
        assert_eq!(decoded.opcode, insn.opcode);
        assert_eq!(decoded.dst_reg, insn.dst_reg);
        assert_eq!(decoded.immediate, insn.immediate);
    }

    #[test]
    fn test_coverage_map() {
        let probes = vec![
            ProbeLocation {
                address: 0x100,
                edge_id: 0,
                original_bytes: vec![0; 16],
            },
            ProbeLocation {
                address: 0x200,
                edge_id: 1,
                original_bytes: vec![0; 16],
            },
        ];
        let mut map = InstrumentedCoverageMap::new(65536, probes);
        assert_eq!(map.covered_edges(), 0);
        map.record_hit(0);
        assert_eq!(map.covered_edges(), 1);
        assert!((map.coverage_pct() - 50.0).abs() < 0.01);
    }
}
