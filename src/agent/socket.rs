// Socket management for SSH agents
//
// Handles creating and managing Unix domain sockets for per-connection agents

use ssh_agent_lib::agent::{Session, listen as agent_listen};
use ssh_agent_lib::error::AgentError;
use std::path::Path;

#[cfg(unix)]
use tokio::net::UnixListener;

/// Start listening on a Unix domain socket for SSH agent protocol connections.
///
/// This function will bind to the socket and handle incoming connections using the
/// provided session implementation.
///
/// # Arguments
/// * `socket_path` - Path to the Unix domain socket
/// * `session` - The session handler implementing the SSH agent protocol
#[cfg(unix)]
pub async fn listen<S>(socket_path: &Path, session: S) -> Result<(), AgentError>
where
    S: Session + Clone + Send + Sync + 'static,
{
    // Bind to the Unix socket
    let listener = UnixListener::bind(socket_path)?;

    // The listen function takes (socket, agent) where agent implements Agent<Socket>
    // Session + Clone + Send + Sync + 'static automatically implements Agent
    agent_listen(listener, session).await
}

#[cfg(not(unix))]
pub async fn listen<S>(_socket_path: &Path, _session: S) -> Result<(), AgentError>
where
    S: Session + Clone + Send + Sync + 'static,
{
    // Custom error type that implements std::error::Error
    #[derive(Debug)]
    struct StringError(String);

    impl std::fmt::Display for StringError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for StringError {}

    Err(AgentError::other(StringError(
        "Unix sockets not supported on this platform".to_string(),
    )))
}
