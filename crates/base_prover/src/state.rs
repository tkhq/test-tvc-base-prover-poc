//! Shared server state.

use crate::response::AppError;
use qos_core::protocol::services::boot::VersionedManifestEnvelope;
use qos_nsm::NsmProvider;
use qos_nsm::types::{NsmRequest, NsmResponse};
use qos_p256::P256Pair;
use std::sync::Arc;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub(crate) ephemeral_key: Arc<P256Pair>,
    pub(crate) quorum_key: Arc<P256Pair>,
    pub(crate) nsm: Arc<dyn NsmProvider>,
    /// Decoded QOS manifest envelope, parsed once at startup.
    pub(crate) manifest: Arc<VersionedManifestEnvelope>,
}

impl AppState {
    /// Create a new application state value.
    #[must_use]
    pub fn new(
        ephemeral_key: P256Pair,
        quorum_key: P256Pair,
        nsm: Arc<dyn NsmProvider>,
        manifest: VersionedManifestEnvelope,
    ) -> Self {
        Self {
            ephemeral_key: Arc::new(ephemeral_key),
            quorum_key: Arc::new(quorum_key),
            nsm,
            manifest: Arc::new(manifest),
        }
    }

    /// The decoded manifest envelope, embedded in responses as structured
    /// JSON so callers can read it directly and re-serialize it locally.
    pub(crate) fn manifest_envelope(&self) -> VersionedManifestEnvelope {
        (*self.manifest).clone()
    }

    /// The schema-specific manifest hash: attested in identity attestation
    /// docs (QOS convention) and committed to PCR17 by the NSM.
    pub(crate) fn manifest_hash(&self) -> [u8; 32] {
        self.manifest.manifest_hash()
    }

    /// Request a fresh NSM attestation doc with the given `user_data` and
    /// the ephemeral public key in `public_key`.
    pub(crate) fn attestation_doc(&self, user_data: Vec<u8>) -> Result<Vec<u8>, AppError> {
        let nsm_response = self.nsm.nsm_process_request(NsmRequest::Attestation {
            user_data: Some(user_data),
            nonce: None,
            public_key: Some(self.ephemeral_key.public_key().to_bytes()),
        });
        let NsmResponse::Attestation { document } = nsm_response else {
            return Err(AppError::internal(format!(
                "unexpected NSM response: {nsm_response:?}"
            )));
        };
        Ok(document)
    }
}
