use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "krastor",
    version = "0.1.0",
    about = "Coverage-guided fuzzer for Solana programs"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        idl: Option<PathBuf>,
    },
    Fuzz {
        #[command(subcommand)]
        cmd: FuzzCommand,
    },
    Report {
        #[arg(long)]
        crash: Option<PathBuf>,
        #[arg(long, default_value = "html")]
        format: String,
    },
}

#[derive(Subcommand)]
enum FuzzCommand {
    Run {
        #[arg(short, long, default_value = "100000")]
        iterations: u64,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long)]
        program: Option<PathBuf>,
    },
    Repro {
        crash_file: PathBuf,
    },
    Coverage {
        #[arg(long)]
        bitmap: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Init { path, idl }) => cmd_init(&path, idl),
        Some(Commands::Fuzz { cmd }) => match cmd {
            FuzzCommand::Run {
                iterations,
                output,
                program,
            } => cmd_fuzz_run(iterations, output, program),
            FuzzCommand::Repro { crash_file } => cmd_fuzz_repro(&crash_file),
            FuzzCommand::Coverage { bitmap } => cmd_fuzz_coverage(bitmap),
        },
        Some(Commands::Report { .. }) => cmd_report(),
        None => {
            eprintln!("No command. Try 'krastor init' or 'krastor fuzz run'.");
            Ok(())
        }
    }
}

fn cmd_init(anchor_root: &PathBuf, idl_path: Option<PathBuf>) -> anyhow::Result<()> {
    println!("Initializing Krastor at {:?}", anchor_root);
    let idl_file = idl_path
        .or_else(|| {
            let d = anchor_root.join("target").join("idl");
            if d.is_dir() {
                std::fs::read_dir(&d)
                    .ok()?
                    .filter_map(|e| e.ok())
                    .find(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                    .map(|e| e.path())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("No IDL found. Build Anchor project first."))?;

    let idl = krastor_idl_parser::parse_idl(&idl_file)?;
    println!("  Program: {} (IDL v{})", idl.name, idl.version);
    let config = krastor_idl_parser::HarnessConfig::from_idl(&idl, "fuzz/");
    let harness = krastor_idl_parser::generate_harness(&idl, &config);
    let d = anchor_root.join("fuzz");
    std::fs::create_dir_all(&d)?;
    std::fs::write(d.join("harness.rs"), harness)?;
    let toml = krastor_idl_parser::generate_krastor_toml(&idl, &config);
    std::fs::write(anchor_root.join("krastor.toml"), toml)?;
    println!("Done! Run 'krastor fuzz run --iterations 100000'");
    Ok(())
}

fn cmd_fuzz_run(
    iterations: u64,
    _output: Option<PathBuf>,
    _program: Option<PathBuf>,
) -> anyhow::Result<()> {
    use krastor_fuzz_core::invariant::invariant_supply_conservation;
    use krastor_fuzz_core::FuzzAccount;
    use krastor_fuzz_core::Fuzzer;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;
    println!("Fuzzing {} iterations...", iterations);
    let mut fuzzer = Fuzzer::new("unknown".into());
    let mut rng = SmallRng::from_entropy();
    for _ in 0..20 {
        fuzzer.accounts.push(FuzzAccount::random(&mut rng));
    }
    fuzzer
        .invariants
        .register("supply", Box::new(invariant_supply_conservation));
    fuzzer.max_sequence_length = 10;
    for r in 0..iterations {
        let result = fuzzer.run_one_round();
        if result.is_crash {
            eprintln!("💥 CRASH at round {}", r);
            fuzzer.crash_count += 1;
        }
        if r % 10000 == 0 {
            eprintln!(
                "  round {}/{} | {} crashes",
                r, iterations, fuzzer.crash_count
            );
        }
    }
    println!(
        "Done. {} rounds, {} crashes",
        iterations, fuzzer.crash_count
    );
    Ok(())
}

fn cmd_fuzz_repro(crash_file: &Path) -> anyhow::Result<()> {
    let record = krastor_fuzz_core::crash::CrashRecord::load(crash_file)?;
    println!("Crash: {}", record.description);
    println!(
        "  Type: {}, Round: {}",
        record.crash_type, record.discovered_at_round
    );
    println!(
        "  Actions: {} ({} removed)",
        record.minimal_sequence.actions.len(),
        record.instructions_removed
    );
    for (i, a) in record.minimal_sequence.actions.iter().enumerate() {
        println!("  {}: {} ({} accts)", i + 1, a.ix_name, a.accounts.len());
    }
    Ok(())
}

fn cmd_fuzz_coverage(_bitmap: Option<PathBuf>) -> anyhow::Result<()> {
    println!("Coverage stats: (instrumentor not loaded)");
    Ok(())
}

fn cmd_report() -> anyhow::Result<()> {
    println!("Report generation — coming soon");
    Ok(())
}
