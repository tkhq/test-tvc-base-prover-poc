//! Generate a fake JSON encoded QOS `ManifestEnvelopeV2` for local testing.
//!
//! Embeds the public key of the given quorum key file in the manifest
//! namespace so verifiers can cross-check it against the quorum key that
//! signs `/prove_block` responses.

use clap::Parser;

/// Generate a fake JSON encoded QOS v2 manifest envelope for local testing.
#[derive(Parser, Debug)]
#[command(name = "gen_fake_manifest", version)]
struct Cli {
    /// Path to the hex encoded quorum key file (the public key is embedded
    /// in the manifest namespace).
    #[arg(long)]
    quorum_file: String,

    /// Output path for the JSON encoded manifest envelope.
    #[arg(long)]
    out: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let quorum_pair = qos_p256::P256Pair::from_hex_file(&cli.quorum_file)
        .map_err(|e| format!("failed to load quorum key from {}: {e:?}", cli.quorum_file))?;
    let envelope =
        tvc_utils::fake_manifest::fake_manifest_envelope(&quorum_pair.public_key().to_bytes())?;
    std::fs::write(&cli.out, qos_json::to_vec(&envelope)?)?;
    println!("wrote fake manifest envelope to {}", cli.out);
    Ok(())
}
