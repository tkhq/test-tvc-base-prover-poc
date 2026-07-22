//! Reference implementation of the SEQUENCER role.
//!
//! What a sequencer does to submit a Base block to the enclave:
//!
//! 1. `GET /enclave_identity`, decoded into [`EnclaveIdentityResponse`].
//! 2. Verify the identity attestation doc: root chain, `user_data` ==
//!    manifest hash, and the PCR17 live manifest commitment.
//! 3. Extract the quorum key from the attested manifest.
//! 4. Encrypt the `BlockWitness` to it.
//! 5. `POST /prove_block`, decoded into [`ProveBlockResponse`].
//!    The response is trusted as-is here; the on-chain verifier phase is
//!    responsible for verifying it.

use base_prover::{EnclaveIdentityResponse, ProveBlockRequest, ProveBlockResponse};
use base_stubs::fixtures::example_witness;
use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_core::protocol::services::boot::manifest::canonical_json_hash;
use qos_nsm::nitro::{
    LIVE_MANIFEST_COMMITMENT_PCR_INDEX, ManifestCommitmentKind, unsafe_attestation_doc_from_der,
    verify_attestation_doc_manifest_commitment,
};
use qos_p256::P256Public;

use crate::attest::verify_attestation_doc_root;
use crate::onchain::PinnedValues;

/// Emulate what the SEQUENCER does to submit a Base block to the enclave.
/// Returns the prove response for the on-chain verifier phase, plus the
/// values the on-chain verifier is assumed to have pinned (the CLI has no
/// baked-in expected values, so it sources them from the independently
/// verified enclave identity instead of the response under verification).
pub async fn emulate_sequencer(
    client: &reqwest::Client,
    base_url: &str,
    unsafe_skip_root_verification: bool,
) -> Result<(ProveBlockResponse, PinnedValues), String> {
    // 1. Fetch the enclave identity.
    let identity_url = format!("{base_url}/enclave_identity");
    println!("\nsequencer step 1: GET {identity_url}");
    let identity: EnclaveIdentityResponse = client
        .get(&identity_url)
        .send()
        .await
        .map_err(|e| format!("identity request failed: {e}"))?
        .json()
        .await
        .map_err(|e| {
            format!("identity response does not decode as EnclaveIdentityResponse: {e}")
        })?;
    println!("ok: decoded EnclaveIdentityResponse");

    // 2. Verify the identity attestation doc.
    println!("\nsequencer step 2: verify identity attestation doc");
    let identity_doc = unsafe_attestation_doc_from_der(&identity.attestation_doc)
        .map_err(|e| format!("identity attestation doc does not decode: {e:?}"))?;
    verify_attestation_doc_root(&identity.attestation_doc, unsafe_skip_root_verification)?;
    // The manifest arrives as structured JSON, already decoded into the
    // full manifest envelope type: recompute the attested hash locally.
    let VersionedManifestEnvelope::V2(envelope) = &identity.manifest else {
        return Err("manifest is not a v2 manifest envelope".to_string());
    };
    let manifest_hash = canonical_json_hash(&envelope.manifest);
    let identity_user_data = identity_doc
        .user_data
        .as_ref()
        .ok_or("identity attestation doc has no user_data")?;
    if identity_user_data.as_ref() != manifest_hash {
        return Err(format!(
            "identity attestation user_data does not commit to the manifest:\n  user_data:     {}\n  manifest hash: {}",
            qos_hex::encode(identity_user_data),
            qos_hex::encode(&manifest_hash)
        ));
    }
    verify_attestation_doc_manifest_commitment(
        &identity_doc,
        ManifestCommitmentKind::Live,
        &manifest_hash,
    )
    .map_err(|e| format!("live manifest commitment verification failed: {e:?}"))?;
    if envelope.manifest.namespace.quorum_key != identity.quorum_public_key {
        return Err("manifest quorum key does not match the identity quorum key".to_string());
    }
    println!(
        "ok: user_data == manifest hash, PCR{LIVE_MANIFEST_COMMITMENT_PCR_INDEX} live manifest \
         commitment, manifest quorum key == identity quorum key"
    );
    println!(
        "  pivot (app) hash: {} (compare against a known-good reproducible build)",
        qos_hex::encode(&envelope.manifest.pivot.hash)
    );

    // 3. Extract the quorum key from the attested manifest.
    println!("\nsequencer step 3: extract quorum key from the attested manifest");
    let attested_quorum_key = envelope.manifest.namespace.quorum_key.clone();
    let encrypt_key = P256Public::from_bytes(&attested_quorum_key)
        .map_err(|e| format!("quorum key is not a valid P256 public key: {e:?}"))?;
    println!("ok: quorum key extracted from the attested manifest");

    // 4. Encrypt the witness to the quorum key.
    println!("\nsequencer step 4: encrypt BlockWitness to the quorum key");
    let witness = example_witness();
    let witness_json =
        serde_json::to_vec(&witness).map_err(|e| format!("failed to serialize witness: {e}"))?;
    let encrypted_witness = encrypt_key
        .encrypt(&witness_json)
        .map_err(|e| format!("failed to encrypt witness to the quorum key: {e:?}"))?;
    println!(
        "ok: created synthetic BlockWitness (1 deposit tx, empty pre-state) and encrypted it ({} -> {} bytes)",
        witness_json.len(),
        encrypted_witness.len()
    );

    // 5. Submit the encrypted witness.
    let prove_url = format!("{base_url}/prove_block");
    println!("\nsequencer step 5: POST {prove_url}");
    let resp = client
        .post(&prove_url)
        .json(&ProveBlockRequest { encrypted_witness })
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?;
    if !status.is_success() {
        return Err(format!("unexpected status {status}: {body}"));
    }
    println!("ok: HTTP {status}");
    let response: ProveBlockResponse = serde_json::from_str(&body)
        .map_err(|e| format!("response does not decode as ProveBlockResponse: {e}"))?;
    println!(
        "ok: decoded ProveBlockResponse (verification happens in the on-chain verifier phase)"
    );

    Ok((
        response,
        PinnedValues {
            quorum_public_key: attested_quorum_key,
            manifest_hash,
            pcrs: [
                envelope.manifest.enclave.pcr0.clone(),
                envelope.manifest.enclave.pcr1.clone(),
                envelope.manifest.enclave.pcr2.clone(),
                envelope.manifest.enclave.pcr3.clone(),
            ],
        },
    ))
}
