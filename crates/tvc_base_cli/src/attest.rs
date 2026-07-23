//! Attestation helpers shared by the sequencer and on-chain verifier roles.

use std::time::{SystemTime, UNIX_EPOCH};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use qos_nsm::nitro::{AWS_ROOT_CERT_PEM, attestation_doc_from_der, cert_from_pem};
use qos_p256::P256Public;

/// Verify a P256 signature over the signed payload bytes. `label` names the
/// signature in error messages.
pub fn verify_signature(
    public_key: &[u8],
    signature: &[u8],
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    let public_key = P256Public::from_bytes(public_key)
        .map_err(|e| format!("{label}: public key is not a valid P256 public key: {e:?}"))?;
    public_key
        .verify(payload, signature)
        .map_err(|e| format!("{label} does not verify over the signed payload: {e:?}"))
}

/// Read a PCR value from a decoded attestation document.
pub fn doc_pcr(doc: &AttestationDoc, index: usize) -> Result<Vec<u8>, String> {
    doc.pcrs
        .get(&index)
        .map(|pcr| pcr.to_vec())
        .ok_or_else(|| format!("attestation doc is missing PCR{index}"))
}

/// Verify an attestation document's authenticity: certificate chain to the
/// pinned AWS Nitro root plus the COSE Sign1 signature. When
/// `unsafe_skip_root_verification` is set, print a loud warning instead.
pub fn verify_attestation_doc_root(
    attestation_doc_bytes: &[u8],
    unsafe_skip_root_verification: bool,
) -> Result<(), String> {
    if unsafe_skip_root_verification {
        println!(
            "!!! WARNING: --unsafe-skip-root-verification is set.\n\
             !!! The certificate chain and COSE Sign1 signature were NOT verified.\n\
             !!! The attestation document is NOT authenticated.\n\
             !!! Only acceptable against a local --mock-nsm server. Never use\n\
             !!! this flag against production infrastructure."
        );
        return Ok(());
    }
    let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM)
        .map_err(|e| format!("failed to decode the pinned AWS Nitro root cert: {e:?}"))?;
    let validation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock is before the unix epoch: {e}"))?
        .as_secs();
    attestation_doc_from_der(attestation_doc_bytes, &root_cert, validation_time).map_err(|e| {
        format!(
            "attestation doc verification against the AWS Nitro root failed: {e:?} \
             (if this is a local --mock-nsm server, pass --unsafe-skip-root-verification)"
        )
    })?;
    println!("ok: attestation doc authentic (cert chain to the AWS Nitro root + COSE Sign1)");
    Ok(())
}
