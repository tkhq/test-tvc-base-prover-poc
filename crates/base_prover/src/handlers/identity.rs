use crate::{response::AppError, state::AppState};
use axum::{Json, extract::State};
use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use serde::{Deserialize, Serialize};

/// Response body for `GET /enclave_identity`.
#[derive(Serialize, Deserialize)]
pub struct EnclaveIdentityResponse {
    /// The QOS v2 manifest envelope loaded at server startup, as structured
    /// JSON. Verifiers recompute the attested manifest hash from this value
    /// with the canonical QOS JSON hash.
    pub manifest: VersionedManifestEnvelope,
    /// The quorum signing public key. Callers encrypt request payloads to
    /// this key after verifying it against the attested manifest.
    #[serde(with = "qos_hex::serde")]
    pub quorum_public_key: Vec<u8>,
    /// The per-instance ephemeral public key, committed to in PCR17 via
    /// the live manifest commitment.
    #[serde(with = "qos_hex::serde")]
    pub ephemeral_public_key: Vec<u8>,
    /// Fresh COSE Sign1 NSM attestation document with the canonical QOS
    /// JSON manifest hash in `user_data` (per the QOS convention).
    #[serde(with = "qos_hex::serde")]
    pub attestation_doc: Vec<u8>,
}

/// Return the enclave's identity: the QOS manifest, the quorum and
/// ephemeral public keys, and a fresh NSM attestation document committing
/// to the manifest hash.
pub(crate) async fn enclave_identity(
    State(state): State<AppState>,
) -> Result<Json<EnclaveIdentityResponse>, AppError> {
    let document = state.attestation_doc(state.manifest_hash().to_vec())?;

    Ok(Json(EnclaveIdentityResponse {
        manifest: state.manifest_envelope(),
        quorum_public_key: state.quorum_key.public_key().to_bytes(),
        ephemeral_public_key: state.ephemeral_key.public_key().to_bytes(),
        attestation_doc: document,
    }))
}
