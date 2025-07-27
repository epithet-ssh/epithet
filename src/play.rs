#[cfg(test)]
mod tests {
    use anyhow::Result;
    use assertor::*;

    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    #[test]
    fn test_key_generation() -> Result<()> {
        // Generate SSH Ed25519 private key
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;

        // Convert to OpenSSH format
        let openssh_private_key = private_key.to_openssh(ssh_key::LineEnding::CRLF)?;
        let openssh_public_key = private_key.public_key().to_openssh()?;

        // Get the string content for assertions and printing
        let private_key_str = openssh_private_key.as_str();
        let public_key_str = openssh_public_key.as_str();

        // Verify the private key has proper OpenSSH format
        assert_that!(private_key_str).contains("-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_that!(private_key_str).contains("-----END OPENSSH PRIVATE KEY-----");

        // Verify the public key has proper SSH format
        assert_that!(public_key_str).starts_with("ssh-ed25519 ");

        // Verify the algorithm is Ed25519
        assert_that!(private_key.algorithm()).is_equal_to(Algorithm::Ed25519);

        // Verify we can get the key fingerprint
        let fingerprint = private_key.fingerprint(ssh_key::HashAlg::Sha256);
        let fingerprint_str = fingerprint.to_string();
        assert_that!(fingerprint_str.len()).is_greater_than(0);

        println!("Generated SSH Ed25519 private key:\n{private_key_str}");
        println!("Generated SSH Ed25519 public key:\n{public_key_str}");
        println!("Key fingerprint (SHA256): {fingerprint_str}");

        // Test that we can parse the generated key back
        let parsed_private_key = PrivateKey::from_openssh(private_key_str)?;
        assert_that!(parsed_private_key.algorithm()).is_equal_to(Algorithm::Ed25519);
        Ok(())
    }

    #[test]
    fn test_generate_pubkey_from_privkey() -> Result<()> {
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;

        let pubkey = private_key.public_key();
        let ossh_pubkey = pubkey.to_openssh()?;

        assert_that!(ossh_pubkey).starts_with("ssh-ed25519");
        Ok(())
    }
}
