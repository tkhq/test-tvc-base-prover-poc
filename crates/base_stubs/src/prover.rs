//! Block proving over the real Base stateless state transition function.
//!
//! [`prove_block`] wraps [`base_proof_executor::StatelessL2Builder`] — the
//! stateless block executor from base/base's proof pipeline — feeding it
//! trie node preimages, contract bytecode, and ancestor headers from the
//! witness, and checking that re-execution reproduces the claimed block
//! hash.

use std::collections::HashMap;

use alloy_consensus::Header;
use alloy_primitives::{B256, Bytes, Sealable, keccak256};
use alloy_rlp::Decodable;
use base_common_evm::BaseEvmFactory;
use base_proof_executor::{StatelessL2Builder, TrieDBProvider};
use base_proof_mpt::{NoopTrieHinter, TrieNode, TrieProvider};

use crate::{BlockOutput, BlockTransition, BlockWitness, ExecutionWitness};

/// Errors returned by [`prove_block`].
#[derive(Debug, thiserror::Error)]
pub enum BlockProverError {
    /// The witness's parent header RLP could not be decoded.
    #[error("failed to decode parent header RLP: {0}")]
    InvalidParentHeader(String),
    /// The decoded parent header does not hash to the public input.
    #[error("parent header hash {got} does not match parent_block_hash {expected}")]
    ParentHashMismatch {
        /// Expected parent block hash (from the public inputs).
        expected: B256,
        /// Hash of the parent header carried in the witness.
        got: B256,
    },
    /// The public-input block number is not parent number + 1.
    #[error("block number mismatch: expected {expected}, got {got}")]
    BlockNumberMismatch {
        /// Expected block number (parent number + 1).
        expected: u64,
        /// Block number from the public inputs.
        got: u64,
    },
    /// The payload attributes carry no transactions. Base blocks always
    /// contain at least the L1-info deposit transaction; the underlying
    /// executor treats an empty list as a protocol violation, so it is
    /// rejected here first.
    #[error("payload attributes contain no transactions")]
    EmptyTransactions,
    /// Stateless execution failed (missing witness preimages, invalid
    /// transactions, header assembly failure, ...).
    #[error("stateless execution failed: {0}")]
    Execution(String),
    /// Re-execution produced a different block hash than claimed.
    #[error("computed block hash {computed} does not match claimed block hash {claimed}")]
    BlockHashMismatch {
        /// Claimed block hash (from the public inputs).
        claimed: B256,
        /// Block hash computed by re-execution.
        computed: B256,
    },
}

/// In-memory preimage store backing the stateless executor, built from an
/// [`ExecutionWitness`]. Every witness blob (trie nodes, bytecode, RLP
/// headers) is keyed by its keccak256 hash, mirroring how base/base's proof
/// host feeds its oracle (`execution_witness_preimages`).
#[derive(Debug)]
pub struct WitnessProvider {
    preimages: HashMap<B256, Bytes>,
}

impl WitnessProvider {
    /// Build the keccak256-keyed preimage map from the witness's `state`,
    /// `codes`, and `headers` blobs.
    #[must_use]
    pub fn new(witness: &ExecutionWitness) -> Self {
        let preimages = witness
            .state
            .iter()
            .chain(witness.codes.iter())
            .chain(witness.headers.iter())
            .map(|raw| (keccak256(raw), raw.clone()))
            .collect();
        Self { preimages }
    }

    fn preimage(&self, hash: B256) -> Result<&Bytes, String> {
        self.preimages
            .get(&hash)
            .ok_or_else(|| format!("missing witness preimage for {hash}"))
    }
}

impl TrieProvider for WitnessProvider {
    type Error = String;

    fn trie_node_by_hash(&self, key: B256) -> Result<TrieNode, Self::Error> {
        let raw = self.preimage(key)?;
        TrieNode::decode(&mut raw.as_ref()).map_err(|err| format!("invalid trie node {key}: {err}"))
    }
}

impl TrieDBProvider for WitnessProvider {
    fn bytecode_by_hash(&self, code_hash: B256) -> Result<Bytes, Self::Error> {
        self.preimage(code_hash).cloned()
    }

    fn header_by_hash(&self, hash: B256) -> Result<Header, Self::Error> {
        let raw = self.preimage(hash)?;
        Header::decode(&mut raw.as_ref()).map_err(|err| format!("invalid header {hash}: {err}"))
    }
}

/// Run the Base stateless state transition function over the given witness.
///
/// Statelessly re-executes the block described by `witness.attributes` on
/// top of the parent header, resolving all state through the witness's
/// preimages, and verifies the resulting sealed header hashes to
/// `public_inputs.claimed_block_hash`.
///
/// # Errors
///
/// Returns [`BlockProverError`] if the witness is inconsistent with the
/// public inputs, execution fails, or the computed block hash differs from
/// the claimed one.
pub fn prove_block(witness: &BlockWitness) -> Result<BlockOutput, BlockProverError> {
    // Decode and seal the parent header; bind it to the public inputs.
    let parent = Header::decode(&mut witness.parent_header_rlp.as_ref())
        .map_err(|err| BlockProverError::InvalidParentHeader(err.to_string()))?
        .seal_slow();
    if parent.hash() != witness.public_inputs.parent_block_hash {
        return Err(BlockProverError::ParentHashMismatch {
            expected: witness.public_inputs.parent_block_hash,
            got: parent.hash(),
        });
    }

    let expected_number = parent.number.wrapping_add(1);
    if witness.public_inputs.block_number != expected_number {
        return Err(BlockProverError::BlockNumberMismatch {
            expected: expected_number,
            got: witness.public_inputs.block_number,
        });
    }

    // The underlying executor treats an empty transaction list as a severe
    // protocol violation (Base blocks always carry at least the L1-info
    // deposit); reject it here instead of tripping that path.
    if witness
        .attributes
        .transactions
        .as_ref()
        .is_none_or(Vec::is_empty)
    {
        return Err(BlockProverError::EmptyTransactions);
    }

    // Re-execute the block with base/base's stateless executor, resolving
    // all state through the witness preimages.
    let provider = WitnessProvider::new(&witness.execution_witness);
    let mut builder = StatelessL2Builder::new(
        &witness.rollup_config,
        BaseEvmFactory::default(),
        provider,
        NoopTrieHinter,
        parent,
    );
    let outcome = builder
        .build_block(witness.attributes.clone())
        .map_err(|err| BlockProverError::Execution(err.to_string()))?;

    // One equality covers every header commitment (state root, receipts
    // root, transactions root, gas used, ...).
    let computed = outcome.header.hash();
    if computed != witness.public_inputs.claimed_block_hash {
        return Err(BlockProverError::BlockHashMismatch {
            claimed: witness.public_inputs.claimed_block_hash,
            computed,
        });
    }

    Ok(BlockOutput {
        block_transition: BlockTransition {
            parent_block_hash: witness.public_inputs.parent_block_hash,
            block_hash: computed,
        },
        block_number: outcome.header.number,
        state_root: outcome.header.state_root,
        receipts_root: outcome.header.receipts_root,
        gas_used: outcome.execution_result.gas_used,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fixtures::example_witness;

    #[test]
    fn example_witness_proves() {
        let witness = example_witness();
        let output = prove_block(&witness).unwrap();
        assert_eq!(
            output.block_transition.parent_block_hash,
            witness.public_inputs.parent_block_hash
        );
        assert_eq!(
            output.block_transition.block_hash,
            witness.public_inputs.claimed_block_hash
        );
        assert_eq!(output.block_number, witness.public_inputs.block_number);
        // The example block executes one deposit, so gas is consumed and
        // state changes (the minted balance lands in the sender account).
        assert!(output.gas_used > 0);
        assert_ne!(output.state_root, alloy_consensus::EMPTY_ROOT_HASH);
    }

    #[test]
    fn witness_round_trips_through_json() {
        let witness = example_witness();
        let json = serde_json::to_string(&witness).unwrap();
        let decoded: BlockWitness = serde_json::from_str(&json).unwrap();
        let original = prove_block(&witness).unwrap();
        let round_tripped = prove_block(&decoded).unwrap();
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn parent_hash_mismatch_is_rejected() {
        let mut witness = example_witness();
        witness.public_inputs.parent_block_hash = B256::repeat_byte(0xaa);
        assert!(matches!(
            prove_block(&witness),
            Err(BlockProverError::ParentHashMismatch { .. })
        ));
    }

    #[test]
    fn block_number_mismatch_is_rejected() {
        let mut witness = example_witness();
        witness.public_inputs.block_number = 50;
        assert!(matches!(
            prove_block(&witness),
            Err(BlockProverError::BlockNumberMismatch {
                expected: 42,
                got: 50
            })
        ));
    }

    #[test]
    fn empty_transactions_are_rejected() {
        let mut witness = example_witness();
        witness.attributes.transactions = Some(vec![]);
        assert!(matches!(
            prove_block(&witness),
            Err(BlockProverError::EmptyTransactions)
        ));
    }

    #[test]
    fn wrong_claimed_block_hash_is_rejected() {
        let mut witness = example_witness();
        witness.public_inputs.claimed_block_hash = B256::repeat_byte(0xbb);
        assert!(matches!(
            prove_block(&witness),
            Err(BlockProverError::BlockHashMismatch { .. })
        ));
    }

    #[test]
    fn tampered_transaction_changes_block_hash() {
        let mut witness = example_witness();
        // Bump the deposit's mint amount: execution still succeeds but the
        // resulting block (state root, tx root) no longer matches the claim.
        let tx = crate::fixtures::example_deposit_tx_with_mint(2_000_000_000_000_000_000);
        witness.attributes.transactions = Some(vec![tx]);
        assert!(matches!(
            prove_block(&witness),
            Err(BlockProverError::BlockHashMismatch { .. })
        ));
    }
}
