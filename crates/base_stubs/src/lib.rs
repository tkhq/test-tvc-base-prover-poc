//! Types and re-exports around the Base stateless state transition
//! function, imported directly from Base's Rust monorepo
//! (<https://github.com/base/base>, pinned by rev in the workspace
//! `Cargo.toml`).
//!
//! Despite the crate name, the STF here is NOT a stub:
//! [`prover::prove_block`] wraps the real
//! [`base_proof_executor::StatelessL2Builder`] — the same stateless block
//! executor Base's fault-proof / TEE pipeline uses — re-executing one L2
//! block from a witness and checking the claimed block hash. Only the thin
//! envelope types defined here ([`BlockWitness`], [`BlockOutput`], ...) are
//! PoC-local: they carry the prover's public inputs and signed commitments,
//! which base/base does not define as a standalone type.
//!
//! The exception is [`fixtures`] (behind the `fixtures` feature): PoC-local
//! synthetic block data, never expected from base/base.

pub mod prover;

// Available to this crate's own tests unconditionally; external users opt
// in via the `fixtures` feature.
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;

pub use alloy_primitives;
pub use alloy_primitives::{Address, B256, Bytes, U256};
pub use alloy_rpc_types_debug::ExecutionWitness;
pub use base_common_genesis::RollupConfig;
pub use base_common_rpc_types_engine::BasePayloadAttributes;
pub use base_proof_executor;

use serde::{Deserialize, Serialize};

/// Public inputs committed by the proof system. The verifier passes these
/// in and the proof must be consistent with them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Hash of the parent block the proven block builds on.
    pub parent_block_hash: B256,
    /// Number of the block being proven (must be parent number + 1).
    pub block_number: u64,
    /// Claimed hash of the block being proven. The prover re-executes the
    /// block and rejects the witness if the computed hash differs. This
    /// single equality covers the state root, receipts root, transactions
    /// root, gas used, and every other header field.
    pub claimed_block_hash: B256,
}

/// Complete witness for statelessly re-executing one Base L2 block.
/// Top-level input to the block prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockWitness {
    /// Public inputs committed by the proof system.
    pub public_inputs: PublicInputs,
    /// Rollup configuration (chain parameters and upgrade activation
    /// times). Embedded in the witness for PoC flexibility; production
    /// would pin this per chain id (e.g. `rollup_config!(8453)` from
    /// `base-common-chains`).
    pub rollup_config: RollupConfig,
    /// RLP-encoded parent block header (hashes to
    /// `public_inputs.parent_block_hash`).
    pub parent_header_rlp: Bytes,
    /// Payload attributes reconstructed from the block being proven:
    /// timestamp, fee recipient, gas limit, and the full EIP-2718 encoded
    /// transaction list.
    pub attributes: BasePayloadAttributes,
    /// Pre-state execution witness: trie node preimages (`state`), contract
    /// bytecode (`codes`), and RLP ancestor headers (`headers`), all keyed
    /// by keccak256. Matches the `debug_executionWitness` RPC response
    /// served by base-node.
    pub execution_witness: ExecutionWitness,
}

/// Block hash transition proven by the STF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTransition {
    /// Hash of the parent block.
    pub parent_block_hash: B256,
    /// Hash of the proven block.
    pub block_hash: B256,
}

/// Commitments produced by the state transition function for onchain
/// verification.
///
/// `u64` fields use the QOS string-or-numeric JSON encoding so the type
/// round-trips through canonical QOS JSON, the signed encoding of
/// [`BlockOutput`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockOutput {
    /// `parent_block_hash` to `block_hash` transition.
    pub block_transition: BlockTransition,
    /// Number of the proven block.
    #[serde(with = "qos_json::string_or_numeric")]
    pub block_number: u64,
    /// Post-execution state root of the proven block.
    pub state_root: B256,
    /// Receipts root of the proven block.
    pub receipts_root: B256,
    /// Gas used by the proven block.
    #[serde(with = "qos_json::string_or_numeric")]
    pub gas_used: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn block_output_round_trips_through_canonical_qos_json() {
        let output = BlockOutput {
            block_transition: BlockTransition {
                parent_block_hash: B256::repeat_byte(0x11),
                block_hash: B256::repeat_byte(0x22),
            },
            block_number: 42,
            state_root: B256::repeat_byte(0x33),
            receipts_root: B256::repeat_byte(0x44),
            gas_used: 21_000,
        };
        // Plain serde JSON round trip.
        let json = serde_json::to_string(&output).unwrap();
        let decoded: BlockOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, output);
        // Canonical QOS JSON (the signed encoding) round trip: decode and
        // re-encode must reproduce the exact canonical bytes.
        let canonical = qos_json::to_vec(&output).unwrap();
        let decoded: BlockOutput = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(decoded, output);
        assert_eq!(qos_json::to_vec(&decoded).unwrap(), canonical);
    }
}
