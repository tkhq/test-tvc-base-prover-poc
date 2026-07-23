//! CLI for verifying a live TVC Base block prover deployment, in two labeled
//! phases: [`sequencer`] fetches and verifies the enclave identity and
//! submits an encrypted block witness; [`onchain`] verifies the prove
//! response the way an on-chain verifier contract would. See each module
//! for its step-by-step reference implementation.
//!
//! The default posture assumes live infrastructure with a real NSM.
//! Mock attestation documents cannot chain to the AWS root; pass
//! `--unsafe-skip-root-verification` to skip root verification only, with
//! a loud warning, so every other check still runs locally.

mod attest;
mod onchain;
mod sequencer;

use clap::Parser;

/// Verify a TVC Base block prover deployment: emulate the sequencer submitting a
/// block witness, then an on-chain verifier checking the response.
#[derive(Parser, Debug)]
#[command(
    name = "tvc_base_cli",
    version,
    about = "TVC Base block prover verification CLI"
)]
struct Cli {
    /// Base URL of the TVC app (e.g. http://127.0.0.1:3000)
    #[arg(long, default_value = "http://127.0.0.1:3000")]
    url: String,

    /// UNSAFE: skip verifying attestation doc certificate chains against
    /// the AWS Nitro root. Attestation documents are then NOT
    /// authenticated. Only for local servers running --mock-nsm, whose mock
    /// documents cannot chain to the AWS root. Never use against production
    /// infrastructure.
    #[arg(long)]
    unsafe_skip_root_verification: bool,
}

async fn run(cli: Cli) -> Result<(), String> {
    let base_url = cli.url.trim_end_matches('/').to_string();
    let client = reqwest::Client::new();

    println!("==============================================================");
    println!("PHASE 1: SEQUENCER - fetch identity, encrypt + submit witness");
    println!("==============================================================");
    let (response, pinned) =
        sequencer::emulate_sequencer(&client, &base_url, cli.unsafe_skip_root_verification).await?;

    println!();
    println!("==============================================================");
    println!("PHASE 2: ON-CHAIN VERIFIER - verify the prove response");
    println!("==============================================================");
    println!(
        "\nEach proof is verified independently against values assumed to be\n\
         pinned on chain (here sourced from the verified enclave identity):\n\
         any one of the three suffices on its own."
    );

    println!("\n--- proof 1/3: QK model (pinned quorum public key) ---");
    onchain::verify_qk_proof(&response.block_output, &response.qk_proof, &pinned)?;

    println!("\n--- proof 2/3: EK model (pinned manifest hash + PCRs, boot proof) ---");
    onchain::verify_ek_proof(
        &response.block_output,
        &response.ek_proof,
        &pinned,
        cli.unsafe_skip_root_verification,
    )?;

    println!("\n--- proof 3/3: attestation binding (pinned manifest hash + PCRs) ---");
    onchain::verify_nsm_proof(
        &response.block_output,
        &response.nsm_proof,
        &pinned,
        cli.unsafe_skip_root_verification,
    )?;

    println!("\nall checks passed");
    if cli.unsafe_skip_root_verification {
        println!(
            "(EXCEPT root verification, which was skipped via --unsafe-skip-root-verification)"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}
