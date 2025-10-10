use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::sleep;

#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    path: PathBuf,
    user: String,
    process: Option<Child>,
}

impl Server {
    /// Start starts an sshd server as the current user, and returns a Server.
    /// The ssh server will be running in a temporary directory, and will process
    /// requests on a random port.
    pub async fn start(ca_pub_key: &ssh_key::PublicKey) -> Result<Self, anyhow::Error> {
        // Get current user
        let user = whoami::username();

        // Create temporary directory for sshd
        let path = tempfile::tempdir()?.keep();

        // Find a free port
        let port = find_port().await?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

        // Generate configs
        generate_configs(&path, &user, port, ca_pub_key).await?;

        // Start sshd
        let process = start_sshd(&path).await?;

        Ok(Server {
            addr,
            path,
            user,
            process: Some(process),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn user(&self) -> &str {
        &self.user
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Kill the sshd process
        if let Some(mut process) = self.process.take() {
            let _ = process.start_kill();
        }

        // Remove temporary directory
        // Using std::fs instead of tokio::fs since Drop can't be async
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Find an available port by binding to port 0 and getting the assigned port
async fn find_port() -> Result<u16, anyhow::Error> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let listener = TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Generate all configuration files needed for sshd
async fn generate_configs(
    path: &PathBuf,
    user: &str,
    port: u16,
    ca_pub_key: &ssh_key::PublicKey,
) -> Result<(), anyhow::Error> {
    // Generate sshd_config
    let sshd_config = format!(
        r#"Port {port}
PasswordAuthentication no
Protocol 2
IgnoreRhosts yes
AcceptEnv LANG LC_*
UsePAM no
LoginGraceTime 120
PubkeyAuthentication yes
StrictModes no

ForceCommand {path}/command.sh
HostKey {path}/ssh_host_ed25519_key
TrustedUserCAKeys {path}/ca.pub
AuthorizedPrincipalsFile {path}/auth_principals/%u
"#,
        port = port,
        path = path.display()
    );

    fs::write(path.join("sshd_config"), sshd_config).await?;

    // Create auth_principals directory
    fs::create_dir(path.join("auth_principals")).await?;

    // Create principals file for current user
    fs::write(path.join("auth_principals").join(user), "a\nb").await?;

    // Write CA public key
    let ca_pub_str = ca_pub_key.to_openssh()?;
    fs::write(path.join("ca.pub"), ca_pub_str).await?;

    // Generate host keys
    let host_private_key = crate::ssh::generate_private_key()?;
    let host_public_key = host_private_key.public_key();

    let host_private_str = host_private_key.to_openssh(ssh_key::LineEnding::LF)?;
    let host_public_str = host_public_key.to_openssh()?;

    fs::write(
        path.join("ssh_host_ed25519_key"),
        host_private_str.to_string(),
    )
    .await?;
    fs::write(path.join("ssh_host_ed25519_key.pub"), host_public_str).await?;

    // Set proper permissions on private key (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path.join("ssh_host_ed25519_key"))
            .await?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path.join("ssh_host_ed25519_key"), perms).await?;
    }

    // Create command.sh
    let command_sh = "#!/bin/sh\n\necho \"hello from sshd!\"\n";
    fs::write(path.join("command.sh"), command_sh).await?;

    // Set executable permissions on command.sh (0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path.join("command.sh")).await?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(path.join("command.sh"), perms).await?;
    }

    Ok(())
}

/// Start the sshd process and wait for it to be ready
async fn start_sshd(path: &PathBuf) -> Result<Child, anyhow::Error> {
    // Find sshd binary
    let sshd_path =
        which::which("sshd").map_err(|e| anyhow::anyhow!("could not find sshd in PATH: {}", e))?;

    let config_path = path.join("sshd_config");

    // Start sshd with -D (don't daemonize) and -e (log to stderr)
    let mut child = Command::new(sshd_path)
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(config_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .spawn()?;

    // Read stderr to wait for "Server listening on" message
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture sshd stderr"))?;

    let mut reader = BufReader::new(stderr);
    let mut line = String::new();

    // Wait up to 5 seconds for sshd to start
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    let mut listening = false;
    while start.elapsed() < timeout {
        line.clear();

        tokio::select! {
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        eprintln!("sshd: {}", line.trim());
                        if line.contains("Server listening on") {
                            listening = true;
                            break;
                        }
                    }
                    Err(e) => return Err(anyhow::anyhow!("error reading sshd output: {}", e)),
                }
            }
            _ = sleep(Duration::from_millis(100)) => {
                // Continue waiting
            }
        }
    }

    if !listening {
        child.kill().await?;
        return Err(anyhow::anyhow!(
            "sshd did not start listening within timeout"
        ));
    }

    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh;
    use assertor::*;

    #[tokio::test]
    async fn test_server_start() -> Result<(), anyhow::Error> {
        let key = ssh::generate_private_key()?;
        let server = Server::start(key.public_key()).await?;

        assert_that!(server.addr().port()).is_greater_than(1023);
        assert_that!(server.addr().port()).is_less_than(65535);
        assert_that!(server.path().exists()).is_true();
        assert_that!(server.user().len()).is_greater_than(0);

        // Server is cleaned up automatically when dropped

        Ok(())
    }

    #[tokio::test]
    async fn test_config_generation() -> Result<(), anyhow::Error> {
        let key = ssh::generate_private_key()?;
        let server = Server::start(key.public_key()).await?;

        // Verify all required files exist
        assert_that!(server.path().join("sshd_config").exists()).is_true();
        assert_that!(server.path().join("ca.pub").exists()).is_true();
        assert_that!(server.path().join("ssh_host_ed25519_key").exists()).is_true();
        assert_that!(server.path().join("ssh_host_ed25519_key.pub").exists()).is_true();
        assert_that!(server.path().join("command.sh").exists()).is_true();
        assert_that!(server.path().join("auth_principals").exists()).is_true();

        // Server is cleaned up automatically when dropped

        Ok(())
    }

    #[tokio::test]
    async fn test_cleanup_on_drop() -> Result<(), anyhow::Error> {
        let key = ssh::generate_private_key()?;
        let server = Server::start(key.public_key()).await?;

        let path = server.path().clone();
        assert_that!(path.exists()).is_true();

        // Drop the server
        drop(server);

        // Give Drop a moment to clean up
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify the temp directory was removed
        assert_that!(path.exists()).is_false();

        Ok(())
    }
}
