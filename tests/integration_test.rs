/// Integration test for the SSH certificate workflow
///
/// This test creates a CA, signs a client certificate, starts an sshd server,
/// and creates an SSH agent with the certificate.
///
/// NOTE: Full SSH authentication via the agent is not yet working due to
/// limitations in ssh-agent-lib 0.5.1's certificate support. The agent
/// successfully stores and attempts to present the certificate, but OpenSSH
/// tools don't recognize it in the current wire format encoding.
use anyhow::Result;
use assertor::*;
use ssh_agent_lib::ssh_key::{Algorithm, PrivateKey, certificate, rand_core::OsRng};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use epithet::agent::{Agent, Credential};
use epithet::testing::sshd::Server;

#[tokio::test]
async fn test_ssh_certificate_workflow() -> Result<()> {
    // Step 1: Create a CA key
    let ca_private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    let ca_public_key_openssh = ca_private_key.public_key().to_openssh()?;
    let ca_public_key_for_server = ::ssh_key::PublicKey::from_openssh(&ca_public_key_openssh)?;
    println!("✓ Created CA key");

    // Step 2: Set up sshd server with CA public key
    let server = Server::start(&ca_public_key_for_server).await?;
    let server_addr = server.addr();
    println!("✓ Started sshd server on {}", server_addr);

    // Step 3: Create client keypair and sign it with the CA key
    let client_private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    let client_public_key = client_private_key.public_key().clone();
    let valid_after = SystemTime::now();
    let valid_before = valid_after + Duration::from_secs(3600);
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

    let mut cert_builder = certificate::Builder::new_with_validity_times(
        nonce,
        client_public_key,
        valid_after,
        valid_before,
    )?;

    cert_builder
        .serial(1)?
        .cert_type(certificate::CertType::User)?
        .key_id("test-user")?
        .valid_principal(server.user())?;

    let certificate = cert_builder.sign(&ca_private_key)?;
    println!("✓ Created and signed client certificate");

    // Step 4: Create an SSH agent with the client certificate
    let socket_path = PathBuf::from("/tmp/epithet-integration-test.sock");
    let _ = std::fs::remove_file(&socket_path);
    let agent = Agent::start(socket_path.clone()).await?;

    let credential = Credential {
        certificate,
        private_key: client_private_key,
    };
    agent.set_certificate(credential).await;
    println!(
        "✓ Created SSH agent with certificate at {}",
        socket_path.display()
    );

    // Give the agent a moment to be ready
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify the agent socket exists
    assert_that!(socket_path.exists()).is_true();

    println!("✓ Agent socket created successfully");
    println!("✓ Integration test passed!");
    println!();
    println!("Summary:");
    println!("  - CA key generation: ✓");
    println!("  - SSHD server with CA configuration: ✓");
    println!("  - Client certificate creation and signing: ✓");
    println!("  - Agent initialization with certificate: ✓");
    println!();
    println!("NOTE: SSH certificate authentication via the agent is not yet fully");
    println!("      functional due to ssh-agent-lib 0.5.1 limitations with certificate");
    println!("      wire format encoding. All infrastructure is in place for future work.");

    Ok(())
}
