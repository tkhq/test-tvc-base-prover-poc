//! Base block prover REST server binary.

use base_prover::cli::Cli;
use base_prover::router::{self, AppState};
use clap::Parser;
use metrics::MetricsLayer;
use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_nsm::mock::MockNsm;
use qos_nsm::nitro::{
    LIVE_MANIFEST_COMMITMENT_PCR_INDEX, ManifestCommitmentKind, expected_manifest_commitment_pcr,
};
use qos_nsm::{Nsm, NsmProvider};
use qos_p256::P256Pair;
use std::io;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let metrics_layer = MetricsLayer::builder().namespace("tvc").build()?;
    let collector = metrics_layer.collector();

    let ephemeral_key = P256Pair::from_hex_file(cli.ephemeral_file)
        .map_err(|e| io::Error::other(format!("failed to load ephemeral key: {e:?}")))?;
    let quorum_key = P256Pair::from_hex_file(cli.quorum_file)
        .map_err(|e| io::Error::other(format!("failed to load quorum key: {e:?}")))?;
    // Read the manifest once at startup so handlers serve it from memory
    // and a missing/unreadable manifest fails fast instead of 500-ing
    // every /prove_block request.
    let manifest = std::fs::read(&cli.manifest_file).map_err(|e| {
        io::Error::other(format!(
            "failed to read manifest file {}: {e}",
            cli.manifest_file
        ))
    })?;
    // Decode the manifest envelope once at startup: the manifest hash is
    // attested in identity attestation docs (and committed to PCR17 by the
    // NSM), so the manifest must be a valid encoded envelope (JSON v2 for
    // current deployments).
    let envelope = VersionedManifestEnvelope::try_from_slice_compat(&manifest).map_err(|e| {
        io::Error::other(format!(
            "the manifest file must be an encoded QOS manifest envelope, e.g. a JSON \
             ManifestEnvelopeV2 (generate a local one with the gen_fake_manifest binary): {e}"
        ))
    })?;
    let nsm: Arc<dyn NsmProvider> = if cli.mock_nsm {
        tracing::warn!("using mock NSM - attestation documents are NOT real");
        let live_commitment = expected_manifest_commitment_pcr(
            ManifestCommitmentKind::Live,
            &envelope.manifest_hash(),
            &ephemeral_key.public_key().to_bytes(),
        )
        .map_err(|e| io::Error::other(format!("failed to build mock NSM PCR17: {e}")))?;
        Arc::new(
            MockNsm::new().with_pcr(LIVE_MANIFEST_COMMITMENT_PCR_INDEX, live_commitment.to_vec()),
        )
    } else {
        Arc::new(Nsm)
    };
    let app_state = AppState::new(ephemeral_key, quorum_key, nsm, envelope);
    let app = router::router_with_state(app_state)
        .layer(metrics_layer)
        .route("/metrics", metrics::handler(collector));

    let addr = format!("{}:{}", cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
