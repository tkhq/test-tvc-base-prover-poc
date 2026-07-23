use crate::{response::AppError, state::AppState};
use axum::{Json, extract::State};
use base_stubs::{BlockOutput, BlockWitness, prover};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// Request body for `POST /prove_block`.
#[derive(Serialize, Deserialize)]
pub struct ProveBlockRequest {
    /// The JSON serialized block witness, encrypted to the enclave's
    /// quorum public key. Callers fetch the quorum key from the attested
    /// manifest via `GET /enclave_identity` before encrypting.
    #[serde(with = "qos_hex::serde")]
    pub encrypted_witness: Vec<u8>,
}

/// Response body for `POST /prove_block`.
///
/// The block output travels as its canonical QOS JSON bytes — the exact
/// bytes every proof binds — so a verifier (an on-chain contract in
/// particular) hashes and checks the bytes as received, without
/// re-serializing. The three proofs are independent alternatives: each
/// suffices on its own, and each assumes the verifier pins a different
/// value out of band. Nothing in the response is self-authenticating;
/// the manifest body is available from `GET /enclave_identity` for
/// debugging and is deliberately not repeated here.
#[derive(Serialize, Deserialize)]
pub struct ProveBlockResponse {
    /// Canonical QOS JSON (`qos_json`) encoding of the [`BlockOutput`]
    /// produced by the block prover. This is the only authoritative copy:
    /// consumers that need the structured output parse exactly these
    /// bytes. Re-serializing a parsed copy back to canonical QOS JSON
    /// must round-trip to these bytes and can be used as a defensive
    /// cross-check off chain.
    #[serde(with = "qos_hex::serde")]
    pub block_output: Vec<u8>,
    /// Proof for verifiers that pin the deployment-wide quorum public key.
    pub qk_proof: QuorumKeyProof,
    /// Proof for verifiers that pin the manifest hash, via a boot proof
    /// for the per-replica ephemeral key.
    pub ek_proof: EphemeralKeyProof,
    /// Proof for verifiers that pin the manifest hash and known-good PCR
    /// values, via a per-request attestation doc binding the block output.
    pub nsm_proof: NsmProof,
}

/// QK model: the verifier pins the deployment-wide quorum public key and
/// needs nothing else.
#[derive(Serialize, Deserialize)]
pub struct QuorumKeyProof {
    /// The quorum key's signature over the `block_output` bytes.
    #[serde(with = "qos_hex::serde")]
    pub qk_sig: Vec<u8>,
}

/// EK model: the verifier pins the manifest hash. The boot proof is a
/// standard QOS identity attestation doc (`user_data` == manifest hash,
/// `public_key` == ephemeral key, PCR17 live manifest commitment):
/// verifying it against the pinned manifest hash establishes the
/// per-replica ephemeral key, which then verifies `ek_sig`. The boot
/// proof only changes when a replica boots, so a verifier can check it
/// once per replica and cache the ephemeral key.
#[derive(Serialize, Deserialize)]
pub struct EphemeralKeyProof {
    /// Fresh QOS identity attestation doc establishing the ephemeral key.
    #[serde(with = "qos_hex::serde")]
    pub bootproof_att_doc: Vec<u8>,
    /// The ephemeral key's signature over the `block_output` bytes.
    #[serde(with = "qos_hex::serde")]
    pub ek_sig: Vec<u8>,
}

/// Attestation-binding model: the verifier pins the manifest hash and
/// known-good PCR values and checks a per-request attestation doc whose
/// `user_data` binds the block output.
#[derive(Serialize, Deserialize)]
pub struct NsmProof {
    /// COSE Sign1 NSM attestation doc with `user_data ==
    /// sha256(block_output)`.
    #[serde(with = "qos_hex::serde")]
    pub att_doc: Vec<u8>,
}

/// Decrypt the request's witness with the enclave's quorum key and run
/// the prover over it.
fn decrypt_and_prove(
    state: &AppState,
    request: &ProveBlockRequest,
) -> Result<BlockOutput, AppError> {
    let witness_json = state
        .quorum_key
        .decrypt(&request.encrypted_witness)
        .map_err(|e| {
            AppError::bad_request(format!(
                "failed to decrypt witness with the enclave's quorum key: {e:?}"
            ))
        })?;
    let witness: BlockWitness = serde_json::from_slice(&witness_json)
        .map_err(|e| AppError::bad_request(format!("decrypted witness is not valid JSON: {e}")))?;
    prover::prove_block(&witness)
        .map_err(|e| AppError::bad_request(format!("invalid block witness: {e}")))
}

/// Prove a block: decrypt and prove the witness, then attach the
/// three independent proofs over the canonical QOS JSON block output
/// bytes — quorum key signature, ephemeral key signature plus boot proof,
/// and an NSM attestation doc binding `sha256(block_output)`.
pub(crate) async fn prove_block(
    State(state): State<AppState>,
    Json(request): Json<ProveBlockRequest>,
) -> Result<Json<ProveBlockResponse>, AppError> {
    let output = decrypt_and_prove(&state, &request)?;

    // Canonical QOS JSON: the exact bytes every proof binds, sent verbatim
    // in the response.
    let block_output = qos_json::to_vec(&output)
        .map_err(|e| AppError::internal(format!("failed to serialize block output: {e}")))?;
    let qk_sig = state
        .quorum_key
        .sign(&block_output)
        .map_err(|e| AppError::internal(format!("failed to sign with quorum key: {e:?}")))?;
    let ek_sig = state
        .ephemeral_key
        .sign(&block_output)
        .map_err(|e| AppError::internal(format!("failed to sign with ephemeral key: {e:?}")))?;

    // Boot proof: a standard QOS identity attestation doc committing to
    // the manifest hash, establishing the ephemeral key for `ek_sig`.
    let bootproof_att_doc = state.attestation_doc(state.manifest_hash().to_vec())?;
    // Binding doc: bind the hash of the block output.
    let att_doc = state.attestation_doc(sha2::Sha256::digest(&block_output).to_vec())?;

    Ok(Json(ProveBlockResponse {
        block_output,
        qk_proof: QuorumKeyProof { qk_sig },
        ek_proof: EphemeralKeyProof {
            bootproof_att_doc,
            ek_sig,
        },
        nsm_proof: NsmProof { att_doc },
    }))
}
