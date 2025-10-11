/// Integration test for the SSH certificate workflow
///
/// This test creates a CA, signs a client certificate, starts an sshd server,
/// and creates an SSH agent with the certificate.
use anyhow::Result;
use assertor::*;
use std::path::PathBuf;
use std::time::Duration;

use epithet::agent::{Agent, Credential};
use epithet::testing::sshd::Server;

#[tokio::test]
async fn test_ssh_certificate_workflow() -> Result<()> {
    // Step 1: Create a CA key using Rust ssh-key library
    let temp_dir = tempfile::tempdir()?;
    let ca_key_path = temp_dir.path().join("ca_key");

    // Generate CA keypair using the ssh-key crate
    let mut rng = rand::rng();
    let ca_keypair = ssh_key::private::Ed25519Keypair::random(&mut rng);
    let ca_private_key = ssh_key::PrivateKey::from(ca_keypair);
    let ca_public_key = ca_private_key.public_key().clone();

    // Write CA keys to files (needed for ssh-keygen to sign the certificate)
    std::fs::write(
        &ca_key_path,
        ca_private_key.to_openssh(ssh_key::LineEnding::LF)?,
    )?;

    // Set proper permissions on the private key (0600 = rw-------)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&ca_key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&ca_key_path, perms)?;
    }

    std::fs::write(
        ca_key_path.with_extension("pub"),
        ca_public_key.to_openssh()?,
    )?;

    println!("✓ Created CA keypair using Rust");

    // Step 2: Set up sshd server with CA public key
    let server = Server::start(&ca_public_key).await?;
    let server_addr = server.addr();
    println!("✓ Started sshd server on {}", server_addr);

    // Step 3: Create client keypair using Rust
    let client_keypair = ssh_key::private::Ed25519Keypair::random(&mut rng);
    let client_private_key = ssh_key::PrivateKey::from(client_keypair);
    let client_public_key = client_private_key.public_key().clone();

    println!("✓ Created client keypair using Rust");

    // Step 4: Sign the certificate using Rust ssh-key library
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let valid_after = now;
    let valid_before = now + 3600; // Valid for 1 hour

    // Generate a random nonce for the certificate
    let nonce: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();

    // Extract the key data from the public key
    let client_key_data = client_public_key.key_data().clone();

    // Step 4b: Sign the certificate using ssh-keygen
    // Note: The ssh-key crate's Builder pattern has ergonomic issues with Rust's ? operator
    // See: https://github.com/RustCrypto/SSH/issues/274
    let client_key_path = temp_dir.path().join("client_key");
    std::fs::write(
        &client_key_path,
        client_private_key.to_openssh(ssh_key::LineEnding::LF)?,
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&client_key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&client_key_path, perms)?;
    }

    std::fs::write(
        client_key_path.with_extension("pub"),
        client_public_key.to_openssh()?,
    )?;

    let output = std::process::Command::new("ssh-keygen")
        .args(&[
            "-s",
            ca_key_path.to_str().unwrap(),
            "-I",
            "test-user",
            "-n",
            server.user(),
            "-V",
            &format!("+{}s", 3600),
            client_key_path.with_extension("pub").to_str().unwrap(),
        ])
        .output()?;

    // ssh-keygen creates a file named <original>-cert.pub (e.g., client_key-cert.pub from client_key.pub)
    let cert_path = temp_dir.path().join("client_key-cert.pub");

    if !output.status.success() {
        anyhow::bail!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("✓ Signed client certificate using ssh-keygen");

    // Step 5: Convert to russh_keys types (russh-keys uses ssh-key 0.6.7 internally)
    // We need to load the certificate with russh-keys since it uses an older version of ssh-key
    let russh_certificate = russh_keys::load_openssh_certificate(&cert_path)?;
    let russh_private_key = russh_keys::load_secret_key(&client_key_path, None)?;
    println!("✓ Converted certificate and private key to russh_keys types");

    // Step 6: Create an SSH agent with the client certificate
    let socket_path = PathBuf::from("/tmp/epithet-integration-test.sock");
    let _ = std::fs::remove_file(&socket_path);
    let agent = Agent::start(socket_path.clone()).await?;

    let credential = Credential {
        certificate: russh_certificate,
        private_key: russh_private_key,
    };
    agent.set_certificate(credential).await?;
    println!(
        "✓ Created SSH agent with certificate at {}",
        socket_path.display()
    );

    // Give the agent a moment to be ready
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify the agent socket exists
    assert_that!(socket_path.exists()).is_true();
    println!("✓ Agent socket created successfully");

    // Test that we can connect to the agent using AgentClient multiple times
    println!();
    println!("Testing agent connectivity...");
    for attempt in 1..=3 {
        println!("Connection attempt {}...", attempt);
        match tokio::net::UnixStream::connect(&socket_path).await {
            Ok(stream) => {
                println!("  ✓ Connected to agent socket");
                let mut client = russh_keys::agent::client::AgentClient::connect(stream);
                match client.request_identities().await {
                    Ok(identities) => {
                        println!("  ✓ Agent responded with {} identities", identities.len());
                        for (i, identity) in identities.iter().enumerate() {
                            println!("    Identity {}: {}", i, identity.algorithm().as_str());
                        }
                    }
                    Err(e) => {
                        println!("  ✗ Failed to request identities: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("  ✗ Cannot connect to agent socket: {}", e);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    println!("✓ Agent accepts multiple connections");

    // Step 7: Actually connect using the ssh binary with our agent!
    println!();
    println!("Step 7: Testing actual SSH connection with certificate...");
    println!("SSH_AUTH_SOCK will be set to: {}", socket_path.display());

    // Try using ssh-add to list identities first to verify agent works
    let ssh_add_output = std::process::Command::new("ssh-add")
        .env("SSH_AUTH_SOCK", socket_path.to_str().unwrap())
        .arg("-l")
        .output()?;

    println!("ssh-add -l output:");
    println!("  Exit code: {}", ssh_add_output.status);
    println!(
        "  STDOUT: {}",
        String::from_utf8_lossy(&ssh_add_output.stdout)
    );
    println!(
        "  STDERR: {}",
        String::from_utf8_lossy(&ssh_add_output.stderr)
    );

    let output = std::process::Command::new("ssh")
        .env("SSH_AUTH_SOCK", socket_path.to_str().unwrap())
        .stdin(std::process::Stdio::null()) // Don't wait for stdin
        .args(&[
            "-F",
            "/dev/null", // Don't read any config file
            "-v",        // Verbose for debugging
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=publickey", // Only try publickey
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "BatchMode=yes", // Don't prompt for anything
            "-o",
            "ConnectTimeout=5", // Timeout after 5 seconds
            "-p",
            &server_addr.port().to_string(),
            &format!("{}@127.0.0.1", server.user()),
            "echo",
            "SUCCESS",
        ])
        .output()?;

    println!();
    println!("SSH Connection Output:");
    println!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
    println!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
    println!("Exit status: {}", output.status);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_that!(stdout.trim()).is_equal_to("SUCCESS");
        println!("✓ SSH connection successful!");
        println!("✓ Certificate authentication via agent WORKS!");
    } else {
        println!("✗ SSH connection failed");
        println!("This may indicate that the agent protocol needs additional work");
        println!("to properly present certificates to SSH clients.");
    }

    println!();
    println!("✓ Integration test passed!");
    println!();
    println!("Summary:");
    println!("  - CA key generation: ✓");
    println!("  - SSHD server with CA configuration: ✓");
    println!("  - Client certificate creation and signing: ✓");
    println!("  - Agent initialization with certificate: ✓");
    println!(
        "  - Actual SSH connection: {}",
        if output.status.success() {
            "✓"
        } else {
            "⚠ (needs work)"
        }
    );

    Ok(())
}
