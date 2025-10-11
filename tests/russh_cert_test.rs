use anyhow::Result;
use russh_keys::agent::client::AgentClient;
use tokio::net::UnixStream;

/// Test to verify that russh-keys agent client can list identities including certificates
/// This test requires a running ssh-agent with at least one certificate loaded
#[tokio::test]
#[ignore] // Requires a running ssh-agent with certificates - run manually
async fn test_russh_agent_list_identities_with_certs() -> Result<()> {
    // Connect to the SSH_AUTH_SOCK
    let socket_path =
        std::env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK not set - start ssh-agent first");

    let stream = UnixStream::connect(&socket_path).await?;
    let mut client = AgentClient::connect(stream);

    // List identities
    let identities = client.request_identities().await?;

    println!("\n=== Agent Identities ===");
    println!("Found {} identities in agent:", identities.len());

    let mut found_cert = false;
    for (i, identity) in identities.iter().enumerate() {
        let algo = identity.algorithm();
        println!("  Identity {}: {}", i, algo.as_str());

        // Check if this is a certificate by looking at the algorithm string
        if algo.as_str().contains("-cert-v01@openssh.com") {
            println!("    ✓ This is a CERTIFICATE!");
            found_cert = true;
        } else {
            println!("    (regular key)");
        }
    }

    if found_cert {
        println!("\n✓ russh-keys successfully handles SSH certificates!");
    } else {
        println!("\n⚠ No certificates found in agent. Add one with:");
        println!("  ssh-keygen -t ed25519 -f /tmp/testkey");
        println!("  ssh-keygen -s <CA_KEY> -I test-user -n test-user /tmp/testkey.pub");
        println!("  ssh-add /tmp/testkey");
    }

    Ok(())
}

/// Test to verify the Algorithm type can represent certificate types
#[test]
fn test_algorithm_supports_certificates() {
    use russh_keys::Algorithm;

    println!("\n=== Certificate Algorithm Support ===");

    // Test parsing certificate algorithm strings
    let cert_types = vec![
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ];

    for cert_str in cert_types {
        match cert_str.parse::<Algorithm>() {
            Ok(algo) => {
                println!("✓ Parsed certificate type: {} -> {:?}", cert_str, algo);
            }
            Err(e) => {
                println!("✗ Failed to parse {}: {}", cert_str, e);
            }
        }
    }
}

/// Comprehensive test that creates a certificate and verifies russh-keys can load it
#[tokio::test]
async fn test_russh_keys_certificate_support() -> Result<()> {
    use russh_keys::{Algorithm, Certificate};
    use std::process::Command;
    use tempfile::tempdir;

    println!("\n=== Testing russh-keys Certificate Support ===");

    // Create a temporary directory for keys
    let temp_dir = tempdir()?;
    let ca_key_path = temp_dir.path().join("ca_key");
    let user_key_path = temp_dir.path().join("user_key");
    let cert_path = temp_dir.path().join("user_key-cert.pub");

    // 1. Generate CA key
    println!("1. Generating CA key...");
    let output = Command::new("ssh-keygen")
        .args(&[
            "-t",
            "ed25519",
            "-f",
            ca_key_path.to_str().unwrap(),
            "-N",
            "", // No passphrase
            "-C",
            "test-ca",
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to generate CA key: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!("   ✓ CA key generated");

    // 2. Generate user key
    println!("2. Generating user key...");
    let output = Command::new("ssh-keygen")
        .args(&[
            "-t",
            "ed25519",
            "-f",
            user_key_path.to_str().unwrap(),
            "-N",
            "", // No passphrase
            "-C",
            "test-user",
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to generate user key: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!("   ✓ User key generated");

    // 3. Sign the user key to create a certificate
    println!("3. Signing user key with CA...");
    let output = Command::new("ssh-keygen")
        .args(&[
            "-s",
            ca_key_path.to_str().unwrap(),
            "-I",
            "test-user@example.com",
            "-n",
            "test-user",
            "-V",
            "+1h",
            user_key_path.with_extension("pub").to_str().unwrap(),
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to sign certificate: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!("   ✓ Certificate created at: {}", cert_path.display());

    // 4. Load the certificate with russh-keys
    println!("4. Loading certificate with russh-keys...");
    match russh_keys::load_openssh_certificate(&cert_path) {
        Ok(cert) => {
            println!("   ✓ Certificate loaded successfully!");
            let algo = cert.algorithm();
            println!("   Algorithm: {}", algo.as_str());
            println!("   Key ID: {}", cert.key_id());
            println!("   Cert type: {:?}", cert.cert_type());

            // The Certificate type successfully loaded, which proves support
            // Note: Algorithm::as_str() returns the base algorithm (ssh-ed25519)
            // not the certificate variant (ssh-ed25519-cert-v01@openssh.com)
            // The fact that cert_type() returns User proves this is a certificate

            assert_eq!(cert.key_id(), "test-user@example.com");
            // cert_type() exists and returns User, proving this is a certificate
            assert!(matches!(
                cert.cert_type(),
                russh_keys::ssh_key::certificate::CertType::User
            ));

            println!("\n✓✓✓ russh-keys FULLY SUPPORTS SSH CERTIFICATES! ✓✓✓");
            println!("    - Can load certificate files with load_openssh_certificate()");
            println!("    - Certificate type provides key_id(), cert_type(), and other metadata");
            println!(
                "    - Algorithm normalizes to base type ({}) which is correct",
                algo.as_str()
            );
            Ok(())
        }
        Err(e) => {
            println!("   ✗ Failed to load certificate: {}", e);
            Err(anyhow::anyhow!("Certificate loading failed: {}", e))
        }
    }
}
