//! Reference implementation of the ON-CHAIN VERIFIER role.
//!
//! The prove response carries the block output as canonical QOS JSON bytes
//! plus three independent proofs. Each proof has its own verification
//! function and trust model, distinguished by what the chain has pinned
//! out of band — any one of them suffices on its own:
//!
//! - [`verify_qk_proof`] (QK model): pins the deployment-wide quorum
//!   public key. One signature verification; the cheapest on chain.
//! - [`verify_ek_proof`] (EK model): pins the manifest hash and PCRs. A
//!   boot proof attestation doc establishes the per-replica ephemeral key,
//!   which verifies the block output signature. The boot proof only changes when
//!   a replica boots, so it can be verified once and the key cached.
//! - [`verify_nsm_proof`] (attestation-binding model): pins the manifest
//!   hash and PCRs. A per-request attestation doc binds
//!   `sha256(block_output)` directly — no signatures involved.
//!
//! Both attestation-based models must pin PCR0-3 alongside the manifest
//! hash: the PCR17 live commitment is extended by software inside the
//! enclave, so it only carries authority if PCR0-2 prove that software is
//! a known-good QOS release.
//!
//! The verifier never re-serializes: it hashes and verifies the
//! `block_output` bytes exactly as received, and anything that consumes
//! block output fields must parse those same bytes.

use base_prover::{EphemeralKeyProof, NsmProof, QuorumKeyProof};
use qos_nsm::nitro::{
    LIVE_MANIFEST_COMMITMENT_PCR_INDEX, ManifestCommitmentKind, unsafe_attestation_doc_from_der,
    verify_attestation_doc_manifest_commitment,
};
use sha2::Digest as _;

use crate::attest::{doc_pcr, verify_attestation_doc_root, verify_signature};

/// Values the on-chain verifier is assumed to have pinned out of band.
/// The CLI sources them from the sequencer phase's independently verified
/// enclave identity.
pub struct PinnedValues {
    /// The deployment-wide quorum public key (QK model).
    pub quorum_public_key: Vec<u8>,
    /// The canonical QOS JSON manifest hash (EK and attestation-binding
    /// models).
    pub manifest_hash: [u8; 32],
    /// Known-good enclave platform PCR0-3 values (EK and
    /// attestation-binding models).
    pub pcrs: [Vec<u8>; 4],
}

/// Check an attestation doc's platform PCR0-3 against the pinned
/// known-good values.
fn verify_pinned_pcrs(
    doc: &aws_nitro_enclaves_nsm_api::api::AttestationDoc,
    pinned_pcrs: &[Vec<u8>; 4],
) -> Result<(), String> {
    for (index, pinned) in pinned_pcrs.iter().enumerate() {
        let measured = doc_pcr(doc, index)?;
        if &measured != pinned {
            return Err(format!(
                "attestation doc PCR{index} does not match the pinned value:\n  doc:    {}\n  pinned: {}",
                qos_hex::encode(&measured),
                qos_hex::encode(pinned)
            ));
        }
    }
    println!("ok: PCR0/1/2/3 match the pinned known-good values");
    Ok(())
}

/// QK model: verify the quorum key signature over the `block_output`
/// bytes against the pinned quorum public key. Nothing else is needed.
pub fn verify_qk_proof(
    block_output: &[u8],
    proof: &QuorumKeyProof,
    pinned: &PinnedValues,
) -> Result<(), String> {
    verify_signature(
        &pinned.quorum_public_key,
        &proof.qk_sig,
        block_output,
        "qk_sig",
    )?;
    println!(
        "ok: qk_sig verifies over the block output bytes ({} bytes) with the pinned quorum key",
        block_output.len()
    );
    Ok(())
}

/// EK model: verify the boot proof against the pinned manifest hash and
/// PCRs to establish the per-replica ephemeral key, then verify the
/// ephemeral key signature over the `block_output` bytes.
pub fn verify_ek_proof(
    block_output: &[u8],
    proof: &EphemeralKeyProof,
    pinned: &PinnedValues,
    unsafe_skip_root_verification: bool,
) -> Result<(), String> {
    // Authenticate the boot proof doc: cert chain to the AWS Nitro root
    // plus the COSE Sign1 signature.
    verify_attestation_doc_root(&proof.bootproof_att_doc, unsafe_skip_root_verification)?;
    let doc = unsafe_attestation_doc_from_der(&proof.bootproof_att_doc).map_err(|e| {
        format!("bootproof_att_doc is not a COSE Sign1 attestation document: {e:?}")
    })?;
    verify_pinned_pcrs(&doc, &pinned.pcrs)?;

    // A standard QOS identity doc commits to the manifest hash in
    // user_data; check it against the pinned value.
    let user_data = doc
        .user_data
        .as_ref()
        .ok_or("boot proof attestation doc has no user_data")?;
    if user_data.as_ref() != pinned.manifest_hash {
        return Err(format!(
            "boot proof user_data does not commit to the pinned manifest hash:\n  user_data:            {}\n  pinned manifest hash: {}",
            qos_hex::encode(user_data),
            qos_hex::encode(&pinned.manifest_hash)
        ));
    }

    // PCR17 must extend to the (pinned manifest hash, attested ephemeral
    // key) live commitment: this is what binds the ephemeral key to the
    // pinned deployment.
    verify_attestation_doc_manifest_commitment(
        &doc,
        ManifestCommitmentKind::Live,
        &pinned.manifest_hash,
    )
    .map_err(|e| format!("live manifest commitment verification failed: {e:?}"))?;
    let ephemeral_public_key = doc
        .public_key
        .as_ref()
        .ok_or("boot proof attestation doc has no public_key")?;
    println!(
        "ok: boot proof authentic, user_data == pinned manifest hash, \
         PCR{LIVE_MANIFEST_COMMITMENT_PCR_INDEX} live commitment binds the ephemeral key"
    );

    verify_signature(ephemeral_public_key, &proof.ek_sig, block_output, "ek_sig")?;
    println!("ok: ek_sig verifies over the block output bytes with the attested ephemeral key");
    Ok(())
}

/// Attestation-binding model: verify a per-request attestation doc whose
/// `user_data` binds `sha256(block_output)`, with the pinned PCRs and the
/// PCR17 live commitment anchoring the doc to the pinned deployment.
pub fn verify_nsm_proof(
    block_output: &[u8],
    proof: &NsmProof,
    pinned: &PinnedValues,
    unsafe_skip_root_verification: bool,
) -> Result<(), String> {
    // Authenticate the doc: cert chain to the AWS Nitro root plus the
    // COSE Sign1 signature.
    verify_attestation_doc_root(&proof.att_doc, unsafe_skip_root_verification)?;
    let doc = unsafe_attestation_doc_from_der(&proof.att_doc)
        .map_err(|e| format!("att_doc is not a COSE Sign1 attestation document: {e:?}"))?;
    verify_pinned_pcrs(&doc, &pinned.pcrs)?;

    // The one deviation from a standard QOS doc: user_data binds sha256 of
    // the block output bytes instead of the manifest hash.
    let user_data = doc
        .user_data
        .as_ref()
        .ok_or("attestation doc has no user_data")?;
    if user_data.as_ref() != sha2::Sha256::digest(block_output).as_slice() {
        return Err(format!(
            "attestation user_data does not bind the block output:\n  user_data:              {}\n  sha256(block_output):   {}",
            qos_hex::encode(user_data),
            qos_hex::encode(&sha2::Sha256::digest(block_output))
        ));
    }
    println!("ok: attestation binding: user_data == sha256(block_output)");

    // PCR17 anchors the doc to the pinned deployment: it must extend to
    // the (pinned manifest hash, attested ephemeral key) live commitment.
    verify_attestation_doc_manifest_commitment(
        &doc,
        ManifestCommitmentKind::Live,
        &pinned.manifest_hash,
    )
    .map_err(|e| format!("live manifest commitment verification failed: {e:?}"))?;
    println!(
        "ok: PCR{LIVE_MANIFEST_COMMITMENT_PCR_INDEX} live commitment extends the pinned manifest \
         hash"
    );
    Ok(())
}
