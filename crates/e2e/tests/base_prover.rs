#![allow(missing_docs, clippy::unwrap_used)]

use e2e::TestArgs;
use qos_p256::P256Public;

#[tokio::test]
async fn test_health() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(json["status"], "healthy");
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_enclave_identity() {
    async fn test(test_args: TestArgs) {
        use qos_core::protocol::services::boot::manifest::canonical_json_hash;

        let client = reqwest::Client::new();
        let identity: serde_json::Value = client
            .get(format!("{}/enclave_identity", test_args.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let hex_field = |field: &str| qos_hex::decode(identity[field].as_str().unwrap()).unwrap();

        // The manifest is returned as structured JSON: decode it into the
        // full ManifestEnvelopeV2 and check it matches the on-disk envelope.
        let envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_value(identity["manifest"].clone()).unwrap();
        let expected_envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_slice(&test_args.manifest).unwrap();
        assert_eq!(envelope, expected_envelope);
        let manifest_hash = canonical_json_hash(&envelope.manifest);
        assert_eq!(
            envelope.manifest.namespace.quorum_key,
            hex_field("quorum_public_key"),
        );

        // Fresh identity attestation doc: manifest hash in user_data (QOS
        // convention), PCR17 commitment.
        let doc =
            qos_nsm::nitro::unsafe_attestation_doc_from_der(&hex_field("attestation_doc")).unwrap();
        assert_eq!(doc.user_data.as_ref().unwrap().as_ref(), manifest_hash);
        assert_eq!(
            doc.public_key.as_ref().unwrap().as_ref(),
            hex_field("ephemeral_public_key"),
        );
        qos_nsm::nitro::verify_attestation_doc_manifest_commitment(
            &doc,
            qos_nsm::nitro::ManifestCommitmentKind::Live,
            &manifest_hash,
        )
        .unwrap();
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_prove_block() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();
        let witness = base_stubs::fixtures::example_witness();
        let expected_output = base_stubs::prover::prove_block(&witness).unwrap();

        // Fetch the enclave identity and encrypt the witness to the
        // quorum key.
        let identity: serde_json::Value = client
            .get(format!("{}/enclave_identity", test_args.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let quorum_public = P256Public::from_bytes(
            &qos_hex::decode(identity["quorum_public_key"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let encrypted_witness = quorum_public
            .encrypt(&serde_json::to_vec(&witness).unwrap())
            .unwrap();

        let resp = client
            .post(format!("{}/prove_block", test_args.base_url))
            .json(&serde_json::json!({ "encrypted_witness": qos_hex::encode(&encrypted_witness) }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();

        let hex_at = |pointer: &str| {
            qos_hex::decode(json.pointer(pointer).unwrap().as_str().unwrap()).unwrap()
        };

        // block_output is the canonical QOS JSON bytes of the expected
        // output; all three proofs bind exactly these bytes.
        let block_output = hex_at("/block_output");
        let output: base_stubs::BlockOutput = serde_json::from_slice(&block_output).unwrap();
        assert_eq!(output, expected_output);
        assert_eq!(qos_json::to_vec(&output).unwrap(), block_output);

        use qos_core::protocol::services::boot::manifest::canonical_json_hash;
        use sha2::Digest as _;
        let envelope: qos_core::protocol::services::boot::ManifestEnvelopeV2 =
            serde_json::from_slice(&test_args.manifest).unwrap();
        let manifest_hash = canonical_json_hash(&envelope.manifest);

        // qk_proof: quorum key signature over the block output bytes.
        let quorum_public =
            P256Public::from_bytes(&envelope.manifest.namespace.quorum_key).unwrap();
        quorum_public
            .verify(&block_output, &hex_at("/qk_proof/qk_sig"))
            .unwrap();

        // ek_proof: boot proof (manifest hash in user_data, PCR17 live
        // commitment) establishing the ephemeral key, which verifies ek_sig.
        let boot_doc =
            qos_nsm::nitro::unsafe_attestation_doc_from_der(&hex_at("/ek_proof/bootproof_att_doc"))
                .unwrap();
        assert_eq!(boot_doc.user_data.as_ref().unwrap().as_ref(), manifest_hash);
        qos_nsm::nitro::verify_attestation_doc_manifest_commitment(
            &boot_doc,
            qos_nsm::nitro::ManifestCommitmentKind::Live,
            &manifest_hash,
        )
        .unwrap();
        let ephemeral_public_key = boot_doc.public_key.as_ref().unwrap().to_vec();
        P256Public::from_bytes(&ephemeral_public_key)
            .unwrap()
            .verify(&block_output, &hex_at("/ek_proof/ek_sig"))
            .unwrap();

        // nsm_proof: attestation doc binding sha256(block_output), anchored
        // to the manifest hash via the PCR17 live commitment.
        let doc =
            qos_nsm::nitro::unsafe_attestation_doc_from_der(&hex_at("/nsm_proof/att_doc")).unwrap();
        assert_eq!(
            doc.user_data.as_ref().unwrap().as_ref(),
            sha2::Sha256::digest(&block_output).as_slice(),
            "attestation user_data should be sha256 of the block output bytes"
        );
        assert_eq!(
            doc.public_key.as_ref().unwrap().as_ref(),
            ephemeral_public_key,
            "attestation public_key should be the ephemeral public key"
        );
        qos_nsm::nitro::verify_attestation_doc_manifest_commitment(
            &doc,
            qos_nsm::nitro::ManifestCommitmentKind::Live,
            &manifest_hash,
        )
        .unwrap();

        assert!(
            json.get("manifest").is_none(),
            "prove response should not carry the manifest"
        );
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn test_metrics() {
    async fn test(test_args: TestArgs) {
        let client = reqwest::Client::new();

        // Hit an endpoint first so the histogram has data
        client
            .get(format!("{}/health", test_args.base_url))
            .send()
            .await
            .unwrap();

        let resp = client
            .get(format!("{}/metrics", test_args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            content_type.starts_with("text/plain"),
            "expected prometheus text format content type, got: {content_type}"
        );

        let body = resp.text().await.unwrap();
        assert!(
            body.contains("tvc_http_request_duration_ms"),
            "should contain the namespaced histogram metric"
        );
        assert!(
            body.contains("method=\"GET\""),
            "should contain method label"
        );
    }
    e2e::Builder::new().execute(test).await;
}

/// The server must fail fast at startup (before binding) when the manifest
/// file is missing, instead of serving requests that 500 on every call.
#[test]
fn test_startup_fails_when_manifest_is_missing() {
    use qos_p256::P256Pair;

    let temp_dir = tempfile::tempdir().unwrap();
    let ephemeral_key_path = temp_dir.path().join("qos.ephemeral.key");
    let quorum_key_path = temp_dir.path().join("qos.quorum.key");
    P256Pair::generate()
        .unwrap()
        .to_hex_file(&ephemeral_key_path)
        .unwrap();
    P256Pair::generate()
        .unwrap()
        .to_hex_file(&quorum_key_path)
        .unwrap();
    let missing_manifest = temp_dir.path().join("nonexistent.manifest");

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin("base_prover"))
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(e2e::find_free_port().unwrap().to_string())
        .arg("--ephemeral-file")
        .arg(&ephemeral_key_path)
        .arg("--quorum-file")
        .arg(&quorum_key_path)
        .arg("--manifest-file")
        .arg(&missing_manifest)
        .arg("--mock-nsm")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "server should exit with an error when the manifest is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read manifest file"),
        "stderr should explain the missing manifest, got: {stderr}"
    );
    assert!(
        stderr.contains(missing_manifest.to_str().unwrap()),
        "stderr should include the manifest path, got: {stderr}"
    );
}
