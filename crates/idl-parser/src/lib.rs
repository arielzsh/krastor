//! Anchor IDL JSON parser and fuzz harness code generator.
//!
//! Supports Anchor IDL v0.x and v1.0 formats.
//! Generates Rust boilerplate including:
//! - FuzzAccounts struct (one field per IDL-defined account)
//! - Instruction dispatch functions
//! - Invariant function templates
//! - krastor.toml configuration skeleton

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::path::Path;

// ============ IDL Types (Anchor v0.x and v1.0 compatible) ============

/// Top-level Anchor IDL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Idl {
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub metadata: Option<IdlMetadata>,
    pub instructions: Vec<IdlInstruction>,
    #[serde(default)]
    pub accounts: Vec<IdlAccount>,
    #[serde(default)]
    pub types: Vec<IdlTypeDef>,
    #[serde(default)]
    pub events: Vec<IdlEvent>,
    #[serde(default)]
    pub errors: Vec<IdlError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlMetadata {
    pub name: String,
    pub version: String,
    pub spec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlInstruction {
    pub name: String,
    #[serde(default)]
    pub docs: Vec<String>,
    pub accounts: Vec<IdlAccountItem>,
    pub args: Vec<IdlField>,
    #[serde(default)]
    pub discriminator: Option<Vec<u8>>,
    #[serde(default)]
    pub returns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdlAccountItem {
    Named {
        name: String,
        #[serde(default)]
        docs: Vec<String>,
        #[serde(default)]
        is_mut: bool,
        #[serde(default)]
        is_signer: bool,
        #[serde(default)]
        pda: Option<IdlPda>,
    },
    Id(IdlAccountMeta),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountMeta {
    pub name: String,
    #[serde(default)]
    pub is_mut: bool,
    #[serde(default)]
    pub is_signer: bool,
    #[serde(default)]
    pub pda: Option<IdlPda>,
}

/// PDA seeds definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlPda {
    pub seeds: Vec<IdlPdaSeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdlPdaSeed {
    Const { value: String, r#type: String },
    Account { path: String },
    Arg { path: String },
}

/// Instruction argument field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlField {
    pub name: String,
    pub r#type: IdlType,
    #[serde(default)]
    pub docs: Vec<String>,
}

/// Type system (Anchor v0.x / v1.0 compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdlType {
    // v0.x format: just a string
    V0(String),
    // v1.0 format: object with kind + fields
    V1 {
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        vec: Option<Box<IdlType>>,
        #[serde(default)]
        option: Option<Box<IdlType>>,
        #[serde(default)]
        defined: Option<String>,
        #[serde(default)]
        array: Option<(Box<IdlType>, usize)>,
        #[serde(default)]
        fields: Option<Vec<IdlField>>,
    },
}

impl IdlType {
    /// Extract the type name for code generation purposes
    pub fn type_name(&self) -> String {
        match self {
            IdlType::V0(s) => s.clone(),
            IdlType::V1 { kind, vec, option, defined, .. } => {
                if let Some(ref k) = kind { return k.clone(); }
                if let Some(ref v) = vec { return format!("Vec<{}>", v.type_name()); }
                if let Some(ref o) = option { return format!("Option<{}>", o.type_name()); }
                if let Some(ref d) = defined { return d.clone(); }
                "unknown".into()
            }
        }
    }
}

/// Account type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccount {
    pub name: String,
    #[serde(default)]
    pub docs: Vec<String>,
    pub r#type: IdlAccountType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlAccountType {
    pub kind: String,
    pub fields: Vec<IdlField>,
}

/// Type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlTypeDef {
    pub name: String,
    pub r#type: IdlTypeDefBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlTypeDefBody {
    pub kind: String,
    #[serde(default)]
    pub variants: Vec<IdlEnumVariant>,
    #[serde(default)]
    pub fields: Option<Vec<IdlField>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlEnumVariant {
    pub name: String,
    #[serde(default)]
    pub fields: Option<Vec<IdlField>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlEvent {
    pub name: String,
    pub fields: Vec<IdlField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdlError {
    pub code: u32,
    pub name: String,
    #[serde(default)]
    pub msg: String,
}

// ============ IDL Parser ============

/// Parse an Anchor IDL JSON file.
pub fn parse_idl(path: &Path) -> Result<Idl> {
    let content = std::fs::read_to_string(path)?;
    let idl: Idl = serde_json::from_str(&content)?;
    Ok(idl)
}

/// Parse IDL from JSON string.
pub fn parse_idl_str(json: &str) -> Result<Idl> {
    Ok(serde_json::from_str(json)?)
}

/// Check whether IDL version is v0.x or v1.0
pub fn is_v1(idl: &Idl) -> bool {
    idl.version.starts_with("1.")
}

// ============ Harness Code Generator ============

#[derive(Debug, Clone, Default)]
pub struct HarnessConfig {
    pub program_name: String,
    pub program_id: String,
    pub output_dir: String,
    pub max_sequence_length: usize,
}

impl HarnessConfig {
    pub fn from_idl(idl: &Idl, output_dir: &str) -> Self {
        Self {
            program_name: idl.name.clone(),
            program_id: idl.address.clone().unwrap_or_default(),
            output_dir: output_dir.to_string(),
            max_sequence_length: 10,
        }
    }
}

/// Generate a complete Rust fuzz harness file from an IDL.
pub fn generate_harness(idl: &Idl, config: &HarnessConfig) -> String {
    let mut code = String::new();

    code.push_str("// Auto-generated by krastor init — do not edit manually.\n");
    code.push_str(&format!("// Program: {}\n", config.program_name));
    code.push_str("use krastor_fuzz_core::*;\n");
    code.push_str("use krastor_fuzz_core::mutator::*;\n");
    code.push_str("use krastor_fuzz_core::invariant::*;\n");
    code.push_str("use rand::rngs::SmallRng;\n");
    code.push_str("use rand::SeedableRng;\n\n");

    // FuzzAccounts struct
    generate_fuzz_accounts_struct(idl, &mut code);

    // Instruction dispatch functions
    generate_instruction_dispatch(idl, &mut code);

    // Invariant templates
    generate_invariant_templates(idl, &mut code);

    // Main fuzz entry point
    generate_main_function(config, &mut code);

    code
}

fn generate_fuzz_accounts_struct(idl: &Idl, code: &mut String) {
    code.push_str("/// Fuzz accounts derived from Anchor IDL\n");
    code.push_str("#[derive(Debug, Clone, Default)]\n");
    code.push_str("pub struct FuzzAccounts {\n");

    let mut seen = HashMap::new();
    for ix in &idl.instructions {
        for acc in &ix.accounts {
            let name = match acc {
                IdlAccountItem::Named { name, .. } => name,
                IdlAccountItem::Id(meta) => &meta.name,
            };
            if !seen.contains_key(name) {
                seen.insert(name.clone(), true);
                code.push_str(&format!("    pub {}: FuzzAccount,\n", to_snake_case(name)));
            }
        }
    }

    code.push_str("}\n\n");
}

fn generate_instruction_dispatch(idl: &Idl, code: &mut String) {
    code.push_str("/// Dispatch table for all program instructions\n");
    code.push_str("pub fn dispatch_instruction(\n");
    code.push_str("    ix_name: &str,\n");
    code.push_str("    accounts: &mut FuzzAccounts,\n");
    code.push_str("    data: &[u8],\n");
    code.push_str(") {\n");
    code.push_str("    match ix_name {\n");

    for ix in &idl.instructions {
        let fn_name = to_snake_case(&ix.name);
        code.push_str(&format!("        \"{}\" => {}(accounts, data),\n", ix.name, fn_name));
    }

    code.push_str("        _ => eprintln!(\"Unknown instruction: {}\", ix_name),\n");
    code.push_str("    }\n");
    code.push_str("}\n\n");

    // Generate each instruction function
    for ix in &idl.instructions {
        let fn_name = to_snake_case(&ix.name);
        code.push_str(&format!("fn {}(\n", fn_name));
        code.push_str("    _accounts: &mut FuzzAccounts,\n");
        code.push_str("    _data: &[u8],\n");
        code.push_str(") {\n");
        code.push_str("    // Instruction discriminator + args deserialization\n");
        code.push_str(&format!("    // {} accounts: {:?}\n", ix.accounts.len(), ix.accounts.iter().map(|a| match a {
            IdlAccountItem::Named { name, .. } => name.as_str(),
            IdlAccountItem::Id(m) => m.name.as_str(),
        }).collect::<Vec<_>>()));
        code.push_str(&format!("    // args: {:?}\n", ix.args.iter().map(|f| format!("{}: {}", f.name, f.r#type.type_name())).collect::<Vec<_>>()));
        code.push_str("    // TODO: deserialize args from _data using anchor::AnchorDeserialize\n");
        code.push_str("}\n\n");
    }
}

fn generate_invariant_templates(idl: &Idl, code: &mut String) {
    code.push_str("/// Invariant functions — customize these to match your program's invariants\n");
    code.push_str("pub fn register_invariants(fuzzer: &mut Fuzzer) {\n");

    // Always add supply conservation as a template
    code.push_str("    fuzzer.invariants.register(\"supply_conservation\", Box::new(invariant_supply_conservation));\n");
    code.push_str("    fuzzer.invariants.register(\"admin_immutability\", Box::new(invariant_admin_immutability));\n");
    code.push_str("    fuzzer.invariants.register(\"state_machine\", Box::new(invariant_state_machine_paused));\n");

    code.push_str("\n");
    code.push_str(&format!("    // {} instructions available for random selection\n", idl.instructions.len()));
    for ix in &idl.instructions {
        let disc = ix.discriminator.as_ref()
            .map(|d| format!("{:?}", d))
            .unwrap_or_else(|| "// UNCERTAINTY: discriminator not in IDL, must be derived".into());
        code.push_str(&format!("    fuzzer.register_instruction(\"{}\", {});\n", ix.name, disc));
    }

    code.push_str("}\n");
}

fn generate_main_function(config: &HarnessConfig, code: &mut String) {
    code.push_str(&format!(
        r#"
pub fn main() {{
    let program_id = "{}";
    let mut fuzzer = Fuzzer::new(program_id.to_string());

    // Initialize random accounts based on IDL definitions
    let mut rng = SmallRng::from_entropy();
    for _ in 0..20 {{
        fuzzer.accounts.push(FuzzAccount::random(&mut rng));
    }}

    fuzzer.max_sequence_length = {};
    register_invariants(&mut fuzzer);

    // Main fuzz loop
    for _round in 0..100_000 {{
        let result = fuzzer.run_one_round();

        if result.is_crash {{
            eprintln!("CRASH at round {{}}: {{:?}}", result.round, result.execution_error);
        }}

        if result.invariant_results.iter().any(|r| !r.passed) {{
            eprintln!("INVARIANT VIOLATION at round {{}}: {{:?}}", result.round, result.invariant_results);
        }}

        // Periodically report progress
        if result.round % 10_000 == 0 {{
            eprintln!("... round {{}}, {{}} crashes, {{}} covered edges",
                result.round, fuzzer.crash_count, fuzzer.global_coverage.covered_edges);
        }}
    }}
}}
"#,
        config.program_id,
        config.max_sequence_length,
    ));
}

// ============ krastor.toml Generator ============

pub fn generate_krastor_toml(idl: &Idl, config: &HarnessConfig) -> String {
    format!(
        r#"[fuzz]
program_id = "{}"
max_iterations = 100000
max_sequence_length = {}
mutation_config = {{ flip_data = 0.40, replace_owner = 0.10, zero_lamports = 0.10, clear_data = 0.05, swap_signer = 0.15, mutate_seeds = 0.10 }}

[report]
output_dir = "fuzz_reports"
format = "html"

[idl]
path = "target/idl/{}.json"
version = "{}"
"#,
        config.program_id,
        config.max_sequence_length,
        config.program_name,
        idl.version,
    )
}

// ============ Helpers ============

fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_lowercase().next().unwrap_or(c));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_idl_str() {
        let json = r#"{
            "version": "0.1.0",
            "name": "test_program",
            "instructions": [
                {
                    "name": "initialize",
                    "accounts": [],
                    "args": []
                }
            ],
            "accounts": [],
            "types": [],
            "events": [],
            "errors": []
        }"#;
        let idl = parse_idl_str(json).unwrap();
        assert_eq!(idl.name, "test_program");
        assert_eq!(idl.instructions.len(), 1);
    }

    #[test]
    fn test_generate_harness() {
        let json = r#"{
            "version": "0.1.0",
            "name": "test_program",
            "address": "TestProg11111111111111111111111111",
            "instructions": [
                {"name": "initialize", "accounts": [{"name": "admin", "is_signer": true}], "args": []},
                {"name": "transfer", "accounts": [{"name": "from", "is_signer": true}, {"name": "to"}], "args": [{"name": "amount", "type": "u64"}]}
            ],
            "accounts": [],
            "types": [],
            "events": [],
            "errors": []
        }"#;
        let idl = parse_idl_str(json).unwrap();
        let config = HarnessConfig::from_idl(&idl, "tests/");
        let harness = generate_harness(&idl, &config);
        assert!(harness.contains("test_program"));
        assert!(harness.contains("FuzzAccounts"));
        assert!(harness.contains("register_invariants"));
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("initialize"), "initialize");
        assert_eq!(to_snake_case("setAdmin"), "set_admin");
        assert_eq!(to_snake_case("transferTokens"), "transfer_tokens");
    }

    #[test]
    fn test_generate_krastor_toml() {
        let json = r#"{"version":"0.1.0","name":"test","instructions":[],"accounts":[],"types":[],"events":[],"errors":[]}"#;
        let idl = parse_idl_str(json).unwrap();
        let config = HarnessConfig { program_name: "test".into(), program_id: "Test1".into(), output_dir: ".".into(), max_sequence_length: 10 };
        let toml = generate_krastor_toml(&idl, &config);
        assert!(toml.contains("program_id"));
        assert!(toml.contains("mutation_config"));
    }
}