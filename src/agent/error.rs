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
    Signing(#[from] ssh_agent_lib::ssh_key::Error),

    /// Error creating signature from signed data
    #[error("signature creation error: {0}")]
    SignatureCreation(String),

    /// Error from the SSH agent protocol library
    #[error("agent protocol error: {0}")]
    Protocol(#[from] ssh_agent_lib::error::AgentError),
}

// Conversion from our Error type to AgentError for the Session trait
impl From<Error> for ssh_agent_lib::error::AgentError {
    fn from(err: Error) -> Self {
        match err {
            Error::Protocol(e) => e,
            other => ssh_agent_lib::error::AgentError::other(other),
        }
    }
}
