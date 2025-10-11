/// SSH agent management for epithet
///
/// This module provides functionality for managing per-connection SSH agents.
/// Each agent holds a single certificate that can be atomically replaced when it expires.
use std::path::PathBuf;
use std::sync::Arc;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_agent_lib::ssh_key::public::{KeyData, OpaquePublicKey};
use ssh_agent_lib::ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, Signature};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

pub mod error;
pub mod socket;

pub use error::Error;

/// An SSH agent that holds a single certificate and listens on a Unix socket.
///
/// The certificate can be atomically replaced when it expires. The agent
/// automatically cleans up its socket when dropped.
pub struct Agent {
    /// Path to the Unix socket this agent listens on
    socket_path: PathBuf,
    /// The current certificate and private key (can be replaced atomically)
    credential: Arc<RwLock<Option<Credential>>>,
    /// Handle to the listener task
    listener_handle: Option<JoinHandle<()>>,
}

/// A certificate paired with its private key for signing
#[derive(Clone)]
pub struct Credential {
    pub certificate: Certificate,
    pub private_key: PrivateKey,
}

/// Session implementation for the SSH agent protocol
#[derive(Clone)]
struct AgentSession {
    credential: Arc<RwLock<Option<Credential>>>,
}

#[ssh_agent_lib::async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let credential = self.credential.read().await;

        match credential.as_ref() {
            Some(cred) => {
                // Encode the certificate as an opaque public key
                // SSH certificates have their own algorithm type (e.g., ssh-ed25519-cert-v01@openssh.com)
                let cert_bytes = cred.certificate.to_bytes().map_err(|e| {
                    AgentError::other(e)
                })?;

                // Get the certificate algorithm (e.g., Ed25519)
                let base_algorithm = cred.certificate.algorithm();

                // Create certificate algorithm string
                let cert_algorithm_str =
                    format!("{}-cert-v01@openssh.com", base_algorithm.as_str());
                let cert_algorithm = Algorithm::new(&cert_algorithm_str).map_err(|e| {
                    AgentError::other(e)
                })?;

                // Create an opaque public key with the certificate data
                let opaque_key = OpaquePublicKey::new(cert_bytes, cert_algorithm);
                let key_data = KeyData::Other(opaque_key);

                Ok(vec![Identity {
                    pubkey: key_data,
                    comment: "epithet certificate".to_string(),
                }])
            }
            None => {
                Ok(vec![])
            }
        }
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let credential = self.credential.read().await;

        let cred = credential.as_ref().ok_or(Error::NoCertificate)?;

        // Sign the data using the private key
        // The namespace is typically "file" for SSH signatures
        let ssh_sig = cred
            .private_key
            .sign("file", HashAlg::Sha256, request.data.as_ref())
            .map_err(Error::Signing)?;

        // Convert SshSig to Signature
        // SshSig contains the algorithm and signature data
        let signature = Signature::new(
            ssh_sig.algorithm().clone(),
            ssh_sig.signature_bytes().to_vec(),
        )
        .map_err(|e| Error::SignatureCreation(e.to_string()))?;

        Ok(signature)
    }
}

impl Agent {
    /// Create and start a new SSH agent listening on the specified socket path.
    ///
    /// The socket file will be created if it doesn't exist. If it exists, it will
    /// be removed and recreated.
    ///
    /// # Arguments
    /// * `socket_path` - Path where the Unix domain socket will be created
    ///
    /// # Returns
    /// A new Agent instance that is listening for connections
    pub async fn start(socket_path: PathBuf) -> Result<Self, Error> {
        // Remove existing socket if present
        let _ = std::fs::remove_file(&socket_path);

        let credential = Arc::new(RwLock::new(None));
        let session = AgentSession {
            credential: credential.clone(),
        };

        // Start the agent listener
        let socket_path_clone = socket_path.clone();
        let listener_handle = tokio::spawn(async move {
            if let Err(e) = socket::listen(&socket_path_clone, session).await {
                eprintln!("Agent listener error: {}", e);
            }
        });

        Ok(Agent {
            socket_path,
            credential,
            listener_handle: Some(listener_handle),
        })
    }

    /// Atomically replace the current certificate and private key.
    ///
    /// This allows updating the certificate when it expires without disrupting
    /// the agent or changing its socket path.
    ///
    /// # Arguments
    /// * `credential` - The new certificate and private key pair
    pub async fn set_certificate(&self, credential: Credential) {
        let mut cred = self.credential.write().await;
        *cred = Some(credential);
    }

    /// Get a copy of the current certificate, if one is loaded.
    pub async fn get_certificate(&self) -> Option<Certificate> {
        let cred = self.credential.read().await;
        cred.as_ref().map(|c| c.certificate.clone())
    }

    /// Get the socket path this agent is listening on.
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        // Abort the listener task
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
        }

        // Clean up the socket file
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use assertor::*;

    #[tokio::test]
    async fn test_agent_creation() -> Result<()> {
        let socket_path = PathBuf::from("/tmp/epithet-test-agent.sock");

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        let agent = Agent::start(socket_path.clone()).await?;

        assert_that!(agent.socket_path()).is_equal_to(&socket_path);
        assert_that!(agent.get_certificate().await).is_none();

        // Cleanup happens automatically via Drop
        drop(agent);

        // Give Drop a moment to clean up
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify socket was removed
        assert_that!(socket_path.exists()).is_false();

        Ok(())
    }

    #[tokio::test]
    async fn test_certificate_replacement() -> Result<()> {
        let socket_path = PathBuf::from("/tmp/epithet-test-agent-cert.sock");
        let _ = std::fs::remove_file(&socket_path);

        let agent = Agent::start(socket_path).await?;

        // Initially no certificate
        assert_that!(agent.get_certificate().await).is_none();

        // Note: We'll need actual certificate creation logic to fully test this
        // For now, this tests the structure

        Ok(())
    }
}
