# Base Block Prover PoC

A proof of concept that statelessly re-executes — "proves" — [Base](https://github.com/base/base)
L2 blocks inside an attested AWS Nitro enclave. The state transition function
is Base's own: `/prove_block` re-executes the block with
[`base-proof-executor`](https://github.com/base/base/tree/main/crates/proof/executor)'s
`StatelessL2Builder` — the same stateless executor Base's fault-proof/TEE
pipeline uses, git-pinned from base/base — resolving all state through the
witness's trie-node/bytecode preimages, and rejecting the witness unless
re-execution reproduces the claimed block hash. Around that executor, the
enclave adds the trust machinery: the witness arrives encrypted to a key that
only an attested enclave holds, and the block output leaves signed and bound
to attestation documents, so a verifier (on-chain or off) can check the
result against a pinned enclave identity. The
[`prove_block` handler](crates/base_prover/src/handlers/prove.rs) is the
heart of what happens inside the enclave: decrypt the witness with the quorum
key, run the stateless STF, sign the canonical QOS JSON block output with the
quorum and ephemeral keys, and attach fresh attestation docs.

The enclave side runs on [Turnkey Verifiable Cloud (TVC)](https://docs.turnkey.com/features/verifiable-cloud/overview)
(see the [glossary](#glossary) for TVC/QOS terms). Based on
[tkhq/tvc-template](https://github.com/tkhq/tvc-template).

## Quickstart (local, no Turnkey account)

```sh
make build   # cargo build --all
make test    # cargo test --all-targets

# terminal 1: run the server locally with generated keys and a mock NSM
make run

# terminal 2: run the full two-phase verification flow against it
cargo run --bin tvc_base_cli -- --url http://127.0.0.1:3000 --unsafe-skip-root-verification
```

The CLI ends with `all checks passed`. Locally the server runs with
`--mock-nsm`, so attestation documents are **not real**, and
`--unsafe-skip-root-verification` disables certificate-chain verification on
the CLI side to match. Both are for local development only — **do not use
either against production infrastructure**. Against a real deployment the
same flow runs with real Nitro attestation and no skip flag; see
[demo.md](demo.md) for the full zero-to-deployed walkthrough (Turnkey org
setup, TVC CLI app creation and deployment, end-to-end verification).

## Repository layout

```
crates/
├── base_prover/   # TVC app server: /health, /enclave_identity, /prove_block, /metrics
├── base_stubs/    # witness/output envelope types + prove_block wrapper over the real base/base stateless executor (git-pinned)
├── tvc_base_cli/  # verification CLI: sequencer + onchain-verifier emulation
├── tvc_utils/     # dev/test utilities: fake manifest generator
├── metrics/       # Prometheus tower layer + /metrics handler
└── e2e/           # end-to-end tests against a spawned server
images/            # stagex Containerfile for the reproducible enclave image
Makefile           # build/test/lint/local-keys/run targets
demo.md            # end-to-end deployment walkthrough
```

## Architecture

One enclave binary (`base_prover`) and one client (`tvc_base_cli`) emulating
the two parties that would interact with it:

1. A **sequencer** (or any witness producer) fetches `/enclave_identity`,
   verifies the enclave's attestation document against the AWS Nitro root,
   extracts the quorum public key from the attested manifest, encrypts a
   `BlockWitness` to it, and posts it to `/prove_block`. The witness is
   readable only inside an enclave provisioned with the quorum key.
2. The **enclave** decrypts the witness, re-executes the block with the
   stateless executor, and — only if the computed block hash equals the
   claimed one — returns a `BlockOutput` signed by the quorum key and the
   per-replica ephemeral key, plus a fresh attestation document binding
   `sha256(block_output)`.
3. An **on-chain verifier** checks any one of the three resulting proofs
   against values it has pinned out of band (quorum key, or manifest hash +
   PCRs). See [Phase 2](#phase-2-on-chain-verifier) below for the three
   proof models.

The trust chain: AWS Nitro root certificate → attestation document → PCR
measurements + manifest hash (PCR17 live commitment) → manifest → quorum /
ephemeral public keys → signatures over the block output bytes.

## Glossary

Turnkey-side terms used throughout:

- **TVC (Turnkey Verifiable Cloud)** — Turnkey's platform for deploying
  attested applications to AWS Nitro enclaves
  ([docs](https://docs.turnkey.com/features/verifiable-cloud/overview)).
- **QOS** — [Turnkey's open-source enclave OS](https://github.com/tkhq/qos)
  that boots the application inside the Nitro enclave, provisions its keys,
  and mediates NSM attestation. "Canonical QOS JSON" is its deterministic
  JSON encoding, used for all signed payloads.
- **Manifest** — the QOS deployment description: application binary digest
  (pivot hash), quorum public key, expected PCRs, deploy metadata. Its hash
  is what attestation documents commit to.
- **Quorum key** — deployment-wide P-256 key provisioned into every replica
  by QOS after manifest approval. Requests are encrypted to it; outputs are
  signed by it.
- **Ephemeral key** — per-replica P-256 key generated inside the enclave at
  boot, bound to the manifest by a boot-time attestation document.
- **NSM** — the AWS Nitro Security Module, which signs attestation documents
  (COSE Sign1) chaining to the AWS Nitro root certificate.
- **PCR17** — the platform configuration register QOS extends with the live
  manifest hash, so every attestation document proves which manifest the
  running enclave was provisioned with. PCR0–2 measure the enclave image
  (i.e. the QOS release) and PCR3 the parent instance's IAM role.

## The witness and the STF

A `BlockWitness` (see [crates/base_stubs/src/lib.rs](crates/base_stubs/src/lib.rs)) carries:

- **public inputs**: parent block hash, block number, and the *claimed*
  block hash the prover must reproduce;
- the RLP parent header and the block's payload attributes (timestamp, fee
  recipient, gas limit, full EIP-2718 transaction list);
- an `ExecutionWitness` (the `debug_executionWitness` RPC shape): trie node
  preimages, contract bytecode, and ancestor headers, all keyed by
  keccak256;
- the `RollupConfig` (embedded for PoC flexibility; production would pin it
  per chain id).

`prove_block` feeds the preimages to `StatelessL2Builder`, re-executes the
block, and emits a `BlockOutput` (parent hash → block hash transition,
block number, state root, receipts root, gas used) only if the computed
sealed header hashes to the claimed block hash — a single equality that
covers every header commitment.

The bundled test fixture is a fully synthetic single-deposit block on an
empty-state parent so the real executor runs offline; see
[crates/base_stubs/src/fixtures.rs](crates/base_stubs/src/fixtures.rs) for
how it was produced and how a real witness would be captured from a Base
node.

## Verification CLI

`tvc_base_cli` exercises a running TVC app in two clearly labeled phases,
emulating the two parties that interact with the enclave.

### Phase 1: sequencer

What a sequencer does to submit a block witness:

1. `GET /enclave_identity` (manifest, quorum key, ephemeral key, fresh
   attestation doc).
2. **Verify the identity attestation doc**: certificate chain to the AWS
   Nitro root, `user_data` == manifest hash, and the PCR17 live manifest
   commitment.
3. **Extract the quorum key** from the attested manifest.
4. **Encrypt the `BlockWitness`** to the quorum key.
5. `POST /prove_block` with the encrypted witness. The response is
   decoded and trusted as-is here; the on-chain verifier phase is
   responsible for verifying it.

> **Why the quorum key and not the ephemeral key?** Ephemeral keys are
> per-replica, and `/enclave_identity` only returns whichever replica the
> load balancer hits. A future TVC endpoint listing all live enclaves for
> an app would let a sequencer encrypt to every relevant ephemeral key.

### Phase 2: on-chain verifier

The prove response carries the block output as canonical QOS JSON bytes —
the exact bytes every proof binds — plus three independent proofs. Any one
proof suffices; they differ in what the chain has pinned out of band:

QOS's QK and EK signing keys are natively P-256 (`secp256r1`). Base supports
native P-256 verification through its `P256VERIFY` precompile, so the typical
path for Options 1 and 2 requires very little integration work and keeps the
common-case on-chain cost to one native signature verification (with the EK
boot proof verified only when a replica is registered). If a protocol prefers
another curve, such as `secp256k1`, the enclave can trivially derive a
domain-separated signing key from the EK or QK secret and emit signatures on
that curve instead; the proof model and key-provenance chain remain the same.

1. **QK model** (`qk_proof`): pins the deployment-wide quorum public key.
   One native P-256 signature verification over the block output bytes; the
   cheapest on chain.
2. **EK model** (`ek_proof`): pins the manifest hash and PCR0-3. A boot
   proof attestation doc (`user_data == manifest hash`, PCR17 live
   manifest commitment, cert chain to the AWS Nitro root) establishes the
   per-replica ephemeral key, which verifies the block output with one native
   P-256 signature check.
   The boot proof only changes when a replica boots, so it can be verified
   once and the key cached.
3. **Attestation-binding model** (`nsm_proof`): pins the manifest hash and
   PCR0-3. A per-request attestation doc binds `sha256(block_output)` in
   `user_data`, anchored to the pinned manifest hash via the PCR17 live
   commitment.

Both attestation-based models pin PCR0-3 alongside the manifest hash: the
PCR17 commitment is extended by software inside the enclave, so it only
carries authority if PCR0-2 prove that software is a known-good QOS
release.

The manifest itself is not part of the response: an on-chain verifier
already knows the manifest hash / quorum key / PCRs, and the manifest body
is available from `GET /enclave_identity` for debugging.

For simplicity there are no baked-in expected values: the CLI sources the
"pinned" values from the sequencer phase's independently verified enclave
identity.

### Against live infrastructure

```sh
cargo run --bin tvc_base_cli -- --url https://your-deployed-tvc-app
```

## Endpoints

```sh
$ curl localhost:3000/health
{"status":"healthy"}

$ curl localhost:3000/enclave_identity
{"manifest":{...},"quorum_public_key":"...","ephemeral_public_key":"...","attestation_doc":"..."}
# manifest is the v2 manifest envelope as structured JSON; attestation_doc is
# a fresh COSE Sign1 doc committing to the manifest.
# Callers verify the doc, then encrypt request payloads to the quorum key
# from the attested manifest.

$ curl -X POST \
  -H 'content-type: application/json' \
  -d '{"encrypted_witness":"<hex-encoded encrypted JSON serialized BlockWitness>"}' \
  localhost:3000/prove_block
{"block_output":"...","qk_proof":{"qk_sig":"..."},"ek_proof":{"bootproof_att_doc":"...","ek_sig":"..."},"nsm_proof":{"att_doc":"..."}}
# block_output is the canonical QOS JSON encoding of the BlockOutput
# commitments, hex-encoded; every proof binds exactly those bytes. See
# crates/base_stubs/src/lib.rs for the full BlockWitness definition.

$ curl localhost:3000/metrics
# Prometheus metrics
```
