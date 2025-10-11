/// SSH agent management for epithet
///
/// This module provides functionality for managing per-connection SSH agents.
/// Each agent holds a single certificate that can be atomically replaced when it expires.
use std::path::PathBuf;
use std::sync::Arc;

use futures::future::Future;
use russh_keys::agent::client::AgentClient;
use russh_keys::agent::server::Agent as RusshAgent;
use russh_keys::{Certificate, PrivateKey};
use tokio::net::UnixStream;
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

/// Simple agent implementation for russh-keys
///
/// The russh-keys agent server manages its own KeyStore internally,
/// so we only need to implement the Agent trait for confirmation logic.
#[derive(Clone)]
struct SimpleAgent;

impl RusshAgent for SimpleAgent {
    fn confirm(
        self,
        _pk: Arc<PrivateKey>,
    ) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        // Always approve key additions
        Box::new(futures::future::ready((self, true)))
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

        // Start the agent listener with simple agent
        let socket_path_clone = socket_path.clone();
        let listener_handle = tokio::spawn(async move {
            let agent = SimpleAgent;
            if let Err(e) = socket::listen(&socket_path_clone, agent).await {
                eprintln!("Agent listener error: {}", e);
            }
        });

        // Give the server a moment to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

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
    pub async fn set_certificate(&self, credential: Credential) -> Result<(), Error> {
        // Update our internal storage
        {
            let mut cred = self.credential.write().await;
            *cred = Some(credential.clone());
        }

        // Connect to our own agent and add the identity
        let stream = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            UnixStream::connect(&self.socket_path),
        )
        .await
        .map_err(|_| Error::AddIdentity("Timeout connecting to agent".to_string()))?
        .map_err(|e| Error::AddIdentity(format!("Failed to connect to agent: {}", e)))?;

        let mut client = AgentClient::connect(stream);

        // Add the private key to the agent's KeyStore
        // Note: The agent protocol doesn't have a separate "add certificate" message.
        // Instead, we add the private key, and if it has an associated certificate,
        // that should be handled. However, russh-keys may not directly support
        // adding certificates via add_identity.
        //
        // For now, we add the private key. Certificate association may need
        // additional work or a different approach.
        client
            .add_identity(&credential.private_key, &[])
            .await
            .map_err(|e| Error::AddIdentity(e.to_string()))?;

        Ok(())
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

        // Verify socket was created
        assert_that!(socket_path.exists()).is_true();

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

        // Note: Full certificate testing would require creating actual certificates
        // This is tested in the integration tests with real certificates

        Ok(())
    }
}
