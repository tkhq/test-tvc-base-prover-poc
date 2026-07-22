//! Dev/test utilities for the TVC Base block prover PoC.
//!
//! Nothing in this crate is part of the core app logic: it exists so local
//! runs and tests can stand in for enclave-only infrastructure.
//!
//! - [`fake_manifest`] — a fake QOS manifest envelope (plus the
//!   `gen_fake_manifest` binary) so verifiers can exercise the manifest
//!   decode + PCR17 commitment path against a locally run server.

pub mod fake_manifest;
