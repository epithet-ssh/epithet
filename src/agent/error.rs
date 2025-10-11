/// Error types for the agent module
use std::io;
use thiserror::Error;

/// Errors that can occur when working with SSH agents
#[derive(Debug, Error)]
pub enum Error {
    /// No certificate is currently loaded in the agent
    #[error("no certificate loaded")]
    NoCertificate,

    /// Failed to bind to the Unix socket
    #[error("failed to bind to socket: {0}")]
    SocketBind(#[from] io::Error),

    /// Error signing data with the private key
    #[error("signing error: {0}")]
    Signing(#[from] ssh_key::Error),

    /// Error creating signature from signed data
    #[error("signature creation error: {0}")]
    SignatureCreation(String),

    /// Error from the russh-keys agent library
    #[error("agent error: {0}")]
    Agent(#[from] russh_keys::Error),

    /// Error adding identity to agent
    #[error("failed to add identity: {0}")]
    AddIdentity(String),
}
