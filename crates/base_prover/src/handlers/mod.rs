//! Route handlers for the block prover REST server.

mod basic;
mod identity;
mod prove;

pub(crate) use basic::health;
pub(crate) use identity::enclave_identity;
pub(crate) use prove::prove_block;

pub use identity::EnclaveIdentityResponse;
pub use prove::{
    EphemeralKeyProof, NsmProof, ProveBlockRequest, ProveBlockResponse, QuorumKeyProof,
};
