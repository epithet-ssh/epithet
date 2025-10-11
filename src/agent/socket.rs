// Socket management for SSH agents
//
// Handles creating and managing Unix domain sockets for per-connection agents

use russh_keys::agent::server::{Agent, serve};
use std::path::Path;
use tokio_stream::wrappers::UnixListenerStream;

use super::Error;

#[cfg(unix)]
use tokio::net::UnixListener;

/// Start listening on a Unix domain socket for SSH agent protocol connections.
///
/// This function will bind to the socket and handle incoming connections using the
/// provided agent implementation.
///
/// # Arguments
/// * `socket_path` - Path to the Unix domain socket
/// * `agent` - The agent handler implementing the Agent trait
#[cfg(unix)]
pub async fn listen<A>(socket_path: &Path, agent: A) -> Result<(), Error>
where
    A: Agent + Send + Sync + 'static,
{
    // Bind to the Unix socket
    let listener = UnixListener::bind(socket_path)?;

    // Convert UnixListener to a Stream for russh-keys
    let stream = UnixListenerStream::new(listener);

    // Start the russh-keys agent server
    serve(stream, agent).await?;

    Ok(())
}

#[cfg(not(unix))]
pub async fn listen<A>(_socket_path: &Path, _agent: A) -> Result<(), Error>
where
    A: Agent + Send + Sync + 'static,
{
    Err(Error::SocketBind(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix sockets not supported on this platform",
    )))
}
