//! Base block prover REST server

pub mod cli;
mod handlers;
mod response;
pub mod router;
mod state;

pub use handlers::{
    EnclaveIdentityResponse, EphemeralKeyProof, NsmProof, ProveBlockRequest, ProveBlockResponse,
    QuorumKeyProof,
};
