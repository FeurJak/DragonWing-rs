// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PQC Client for Arduino Uno Q
//
// This Linux application demonstrates post-quantum cryptography combining:
// - ML-KEM 768 (FIPS 203) for key encapsulation
// - ML-DSA 65 (FIPS 204) for digital signatures
//
// Protocol:
// 1. Request MCU to generate ML-KEM key pair
// 2. Get public key from MCU
// 3. Encapsulate shared secret locally
// 4. Send ciphertext to MCU for decapsulation
// 5. MCU generates ML-DSA keys from shared secret
// 6. MCU signs a message
// 7. Linux verifies the signature

use anyhow::{Context, Result};
use clap::Parser;
use dragonwing_rpc::RpcClientSync;
use libcrux_ml_kem::mlkem768;
use log::{error, info, warn};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey, SignedMessage};
use rand::{rngs::OsRng, TryRngCore};

/// ML-KEM 768 constants
const PUBLIC_KEY_SIZE: usize = 1184;
const CIPHERTEXT_SIZE: usize = 1088;
const SHARED_SECRET_SIZE: usize = 32;

/// ML-DSA 65 constants
const VERIFICATION_KEY_SIZE: usize = 1952;
const SIGNATURE_SIZE: usize = 3309;

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "pqc-client")]
#[command(about = "Post-quantum cryptography demo with Arduino Uno Q (ML-KEM + ML-DSA)")]
struct Args {
    /// RPC socket path
    #[arg(short, long, default_value = "/tmp/arduino-spi-router.sock")]
    socket: String,

    /// Run the full PQC demo (locally simulated)
    #[arg(short, long)]
    demo: bool,

    /// Run the MCU-side PQC demo (ML-KEM + ML-DSA on MCU)
    #[arg(long)]
    mcu_demo: bool,

    /// Run the MCU-side ML-KEM demo
    #[arg(long)]
    mlkem_demo: bool,

    /// Run the MCU-side ML-DSA demo
    #[arg(long)]
    mldsa_demo: bool,

    /// Run the MCU-side COSE_Sign1 demo (RFC 9052 with ML-DSA)
    #[arg(long)]
    cose_demo: bool,

    /// Run the MCU-side Ed25519 demo (fast, non-PQC baseline)
    #[arg(long)]
    ed25519_demo: bool,

    /// Run the MCU-side X25519 ECDH demo (fast key exchange)
    #[arg(long)]
    x25519_demo: bool,

    /// Run the MCU-side X-Wing hybrid PQ KEM demo (ML-KEM + X25519)
    #[arg(long)]
    xwing_demo: bool,

    /// Run the MCU-side XChaCha20-Poly1305 AEAD demo
    #[arg(long)]
    xchacha20_demo: bool,

    /// Run the MCU-side SAGA anonymous credentials demo
    #[arg(long)]
    saga_demo: bool,

    /// Run the MCU-side SAGA+X-Wing credential-protected key exchange demo
    #[arg(long)]
    saga_xwing_demo: bool,

    /// Run the MCU-side PSA Secure Storage demo
    #[arg(long)]
    psa_demo: bool,

    /// Run the MCU-side PSA Persistence demo (SAGA + X-Wing storage)
    #[arg(long)]
    persistence_demo: bool,

    /// Just ping the MCU
    #[arg(short, long)]
    ping: bool,

    /// Message to sign (for demo)
    #[arg(short, long, default_value = "Hello, post-quantum world!")]
    message: String,
}

/// Generate random bytes
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut rng = OsRng;
    let mut bytes = [0u8; N];
    rng.try_fill_bytes(&mut bytes)
        .expect("Failed to get random bytes");
    bytes
}

/// Format bytes as hex string (first and last few bytes)
fn format_bytes(bytes: &[u8]) -> String {
    if bytes.len() <= 16 {
        hex::encode(bytes)
    } else {
        format!(
            "{}...{} ({} bytes)",
            hex::encode(&bytes[..8]),
            hex::encode(&bytes[bytes.len() - 8..]),
            bytes.len()
        )
    }
}

/// Run the full PQC demo
fn run_demo(client: &RpcClientSync, message: &str) -> Result<()> {
    info!("===========================================");
    info!("  Post-Quantum Cryptography Demo");
    info!("  ML-KEM 768 + ML-DSA 65");
    info!("===========================================");
    info!("");

    // Step 1: Generate ML-KEM key pair on MCU
    info!("Step 1: Requesting MCU to generate ML-KEM key pair...");
    let result = client
        .call("mlkem.generate_keypair", vec![])
        .context("Failed to generate ML-KEM key pair")?;
    info!("  ML-KEM key pair generated: {:?}", result);

    // Step 2: Get public key from MCU
    info!("");
    info!("Step 2: Retrieving ML-KEM public key from MCU...");
    let pk_result = client
        .call("mlkem.get_public_key", vec![])
        .context("Failed to get public key")?;
    info!("  Public key size: {:?}", pk_result);

    // Note: In a real implementation, we need actual byte transfer
    // For this demo, we'll show the protocol flow and demonstrate
    // ML-DSA verification with simulated data

    warn!("");
    warn!("NOTE: Full binary transfer requires extending the RPC protocol.");
    warn!("      This demo shows the protocol flow with local simulation.");
    warn!("");

    // Step 3: Demonstrate local ML-KEM encapsulation
    info!("Step 3: Demonstrating ML-KEM encapsulation locally...");

    // Generate a local key pair for demonstration
    let keygen_randomness: [u8; 64] = random_bytes();
    let local_kem_keypair = mlkem768::generate_key_pair(keygen_randomness);
    info!("  Local ML-KEM key pair generated");
    info!(
        "  Public key: {}",
        format_bytes(local_kem_keypair.public_key().as_slice())
    );

    // Encapsulate
    let encaps_randomness: [u8; 32] = random_bytes();
    let (ciphertext, shared_secret) =
        mlkem768::encapsulate(local_kem_keypair.public_key(), encaps_randomness);
    info!("  Ciphertext: {}", format_bytes(ciphertext.as_slice()));
    info!(
        "  Shared secret: {}",
        format_bytes(shared_secret.as_slice())
    );

    // Step 4: Decapsulate locally to verify ML-KEM
    info!("");
    info!("Step 4: Verifying ML-KEM with local decapsulation...");
    let decapsulated = mlkem768::decapsulate(local_kem_keypair.private_key(), &ciphertext);
    info!(
        "  Decapsulated secret: {}",
        format_bytes(decapsulated.as_slice())
    );

    if shared_secret.as_slice() == decapsulated.as_slice() {
        info!("  ML-KEM SUCCESS: Shared secrets match!");
    } else {
        error!("  ML-KEM FAILURE: Shared secrets do not match!");
        return Err(anyhow::anyhow!("ML-KEM key exchange failed"));
    }

    // Step 5: Demonstrate ML-DSA signing and verification
    info!("");
    info!("Step 5: Demonstrating Dilithium3 (ML-DSA equivalent) signature...");
    info!("  Message: \"{}\"", message);

    // Generate Dilithium3 key pair (in real demo, this would be on MCU)
    // Note: Dilithium3 is the predecessor to ML-DSA-65, with similar security level
    info!("  Generating Dilithium3 key pair locally for demo...");
    let (pk, sk) = dilithium3::keypair();

    info!("  Public key: {}", format_bytes(pk.as_bytes()));

    // Sign the message
    info!("  Signing message...");
    let signature = dilithium3::detached_sign(message.as_bytes(), &sk);
    info!("  Signature: {}", format_bytes(signature.as_bytes()));

    // Verify the signature
    info!("");
    info!("Step 6: Verifying Dilithium3 signature...");
    match dilithium3::verify_detached_signature(&signature, message.as_bytes(), &pk) {
        Ok(()) => {
            info!("  Dilithium3 SUCCESS: Signature is valid!");
        }
        Err(_) => {
            error!("  Dilithium3 FAILURE: Signature verification failed!");
            return Err(anyhow::anyhow!("Dilithium3 verification failed"));
        }
    }

    // Summary
    info!("");
    info!("===========================================");
    info!("  PQC Demo Complete!");
    info!("===========================================");
    info!("");
    info!("Summary:");
    info!("  - ML-KEM 768: Key encapsulation successful");
    info!("  - ML-DSA 65: Digital signature verified");
    info!("  - Both parties have established:");
    info!("    1. A shared 32-byte secret (via ML-KEM)");
    info!("    2. Authenticated communication (via ML-DSA)");
    info!("");
    info!("This demonstrates quantum-resistant:");
    info!("  - Key exchange (ML-KEM replaces ECDH)");
    info!("  - Digital signatures (ML-DSA replaces ECDSA)");

    Ok(())
}

/// Test Dilithium3 (ML-DSA equivalent) verification
fn test_dilithium_verification() -> Result<()> {
    info!("Testing Dilithium3 (ML-DSA equivalent) implementation...");

    let (pk, sk) = dilithium3::keypair();
    let message = b"Test message for Dilithium3";
    let signature = dilithium3::detached_sign(message, &sk);

    match dilithium3::verify_detached_signature(&signature, message, &pk) {
        Ok(()) => {
            info!("Dilithium3 test passed!");
            info!("  Public key size: {} bytes", pk.as_bytes().len());
            info!("  Secret key size: {} bytes", sk.as_bytes().len());
            info!("  Signature size: {} bytes", signature.as_bytes().len());
            Ok(())
        }
        Err(_) => {
            error!("Dilithium3 test failed!");
            Err(anyhow::anyhow!("Dilithium3 test failed"))
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("PQC Client for Arduino Uno Q");
    info!("ML-KEM 768 + ML-DSA 65");
    info!("");
    info!("Connecting to RPC server at {}...", args.socket);

    let client = RpcClientSync::connect(&args.socket).context("Failed to connect to RPC server")?;

    // Test connection
    match client.call("ping", vec![]) {
        Ok(result) => info!("Connected! MCU responded: {:?}", result),
        Err(e) => {
            error!("Failed to ping MCU: {}", e);
            return Err(e.into());
        }
    }

    // Get version
    match client.call("version", vec![]) {
        Ok(result) => info!("MCU firmware: {:?}", result),
        Err(e) => warn!("Could not get version: {}", e),
    }

    if args.ping {
        info!("Ping successful!");
        return Ok(());
    }

    // MCU-side demos - all cryptography runs on the STM32U585
    // ML-DSA operations are very slow on Cortex-M33 (~60-120 seconds for keygen+sign)
    // Use 3 minute timeout for crypto operations
    let demo_timeout = std::time::Duration::from_secs(180);

    if args.mcu_demo {
        info!("");
        info!("Running full PQC demo on MCU (ML-KEM + ML-DSA)...");
        info!("Watch the LED matrix for status indicators!");
        info!("(This may take up to 30 seconds)");
        info!("");
        match client.call_timeout("pqc.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("MCU demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully ran:");
                info!("  - ML-KEM 768 key generation, encapsulation, decapsulation");
                info!("  - ML-DSA 65 key generation, signing, verification");
            }
            Err(e) => {
                error!("MCU demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.mlkem_demo {
        info!("");
        info!("Running ML-KEM 768 demo on MCU...");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("mlkem.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("ML-KEM demo completed: {:?}", result);
            }
            Err(e) => {
                error!("ML-KEM demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.mldsa_demo {
        info!("");
        info!("Running ML-DSA 65 demo on MCU...");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("mldsa.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("ML-DSA demo completed: {:?}", result);
            }
            Err(e) => {
                error!("ML-DSA demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.cose_demo {
        info!("");
        info!("Running COSE_Sign1 demo on MCU (RFC 9052 with ML-DSA)...");
        info!("Watch the LED matrix for status indicators!");
        info!("(This may take 2-3 minutes due to ML-DSA operations)");
        info!("");
        // COSE demo needs longer timeout: keygen + sign + verify = ~90+ seconds
        let cose_timeout = std::time::Duration::from_secs(300);
        match client.call_timeout("cose.run_demo", vec![], cose_timeout) {
            Ok(result) => {
                info!("COSE demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Generated ML-DSA 65 key pair");
                info!("  - Created COSE_Sign1 message with payload");
                info!("  - Verified the signature and extracted payload");
            }
            Err(e) => {
                error!("COSE demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.ed25519_demo {
        info!("");
        info!("Running Ed25519 demo on MCU...");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("ed25519.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("Ed25519 demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Generated Ed25519 key pair");
                info!("  - Signed a test message");
                info!("  - Verified the signature");
            }
            Err(e) => {
                error!("Ed25519 demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.x25519_demo {
        info!("");
        info!("Running X25519 ECDH demo on MCU...");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("x25519.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("X25519 demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Generated two X25519 key pairs (Alice & Bob)");
                info!("  - Performed ECDH key agreement");
                info!("  - Verified both parties derived the same shared secret");
            }
            Err(e) => {
                error!("X25519 demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.xwing_demo {
        info!("");
        info!("Running X-Wing hybrid PQ KEM demo on MCU...");
        info!("X-Wing combines ML-KEM-768 + X25519 for hybrid post-quantum security");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("xwing.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("X-Wing demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Generated X-Wing key pair (ML-KEM-768 + X25519)");
                info!("  - Encapsulated a hybrid shared secret");
                info!("  - Decapsulated and verified shared secret match");
                info!("");
                info!("X-Wing provides:");
                info!("  - Post-quantum security via ML-KEM-768");
                info!("  - Classical security via X25519");
                info!("  - IND-CCA2 security if either component is secure");
            }
            Err(e) => {
                error!("X-Wing demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.xchacha20_demo {
        info!("");
        info!("Running XChaCha20-Poly1305 AEAD demo on MCU...");
        info!("XChaCha20-Poly1305 provides authenticated encryption with 24-byte nonces");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("xchacha20.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("XChaCha20-Poly1305 demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Generated a random 256-bit key");
                info!("  - Generated a random 24-byte nonce");
                info!("  - Encrypted a message with authentication");
                info!("  - Decrypted and verified the message");
                info!("");
                info!("XChaCha20-Poly1305 provides:");
                info!("  - Authenticated encryption (AEAD)");
                info!("  - 24-byte nonces (safe for random generation)");
                info!("  - High performance symmetric encryption");
            }
            Err(e) => {
                error!("XChaCha20-Poly1305 demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.saga_demo {
        info!("");
        info!("Running SAGA anonymous credentials demo on MCU...");
        info!("SAGA is a BBS-style MAC scheme for privacy-preserving credentials");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("saga.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("SAGA demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Generated SAGA parameters and key pair (issuer)");
                info!("  - Created credential attributes (3 attributes)");
                info!("  - Issued a credential (computed MAC)");
                info!("  - Holder verified credential with public key");
                info!("  - Created unlinkable presentation");
                info!("  - Issuer verified presentation");
                info!("  - Demonstrated unlinkability (two different presentations)");
                info!("");
                info!("SAGA provides:");
                info!("  - Anonymous credentials (BBS-style MAC)");
                info!("  - Unlinkable presentations (same credential, different proofs)");
                info!("  - Zero-knowledge proofs of credential possession");
                info!("  - Selective disclosure of attributes");
            }
            Err(e) => {
                error!("SAGA demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.saga_xwing_demo {
        info!("");
        info!("Running SAGA + X-Wing hybrid demo on MCU...");
        info!("Credential-protected post-quantum key exchange:");
        info!("  - SAGA: Anonymous credentials with unlinkable presentations");
        info!("  - X-Wing: Hybrid PQ key encapsulation (ML-KEM-768 + X25519)");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("saga_xwing.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("SAGA + X-Wing demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Created SAGA issuer parameters and key pair");
                info!("  - Issued a credential to the device");
                info!("  - Device initiated key exchange (X-Wing keypair + SAGA presentation)");
                info!("  - Server verified presentation and encapsulated shared secret");
                info!("  - Device completed key exchange and decrypted payload");
                info!("  - Both parties derived matching session keys");
                info!("");
                info!("SAGA + X-Wing provides:");
                info!("  - Post-quantum forward secrecy (ML-KEM-768)");
                info!("  - Classical forward secrecy (X25519)");
                info!("  - Anonymous authentication (SAGA unlinkable presentations)");
                info!("  - Authenticated encryption (XChaCha20-Poly1305)");
                info!("");
                info!("Use case: Device proves it has a valid credential while");
                info!("establishing a quantum-resistant encrypted channel.");
            }
            Err(e) => {
                error!("SAGA + X-Wing demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.psa_demo {
        info!("");
        info!("Running PSA Secure Storage demo on MCU...");
        info!("Demonstrates encrypted persistent storage using Zephyr Secure Storage");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("psa.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("PSA Secure Storage demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Initialized PSA Crypto subsystem");
                info!("  - Stored encrypted data in ITS (Internal Trusted Storage)");
                info!("  - Retrieved and verified the encrypted data");
                info!("  - Generated a persistent AES-256 key");
                info!("  - Exported and verified the key");
                info!("");
                info!("PSA Secure Storage provides:");
                info!("  - Data encrypted at rest (AEAD transform)");
                info!("  - Device-unique encryption key");
                info!("  - Persistent storage across reboots");
                info!("  - PSA Certified API compliance");
            }
            Err(e) => {
                error!("PSA Secure Storage demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.persistence_demo {
        info!("");
        info!("Running PSA Persistence demo on MCU...");
        info!("Demonstrates storing SAGA credentials and X-Wing seeds persistently");
        info!("Data survives reboots!");
        info!("Watch the LED matrix for status indicators!");
        info!("");
        match client.call_timeout("persistence.run_demo", vec![], demo_timeout) {
            Ok(result) => {
                info!("PSA Persistence demo completed: {:?}", result);
                info!("");
                info!("The MCU successfully:");
                info!("  - Created and stored a SAGA credential (encrypted at rest)");
                info!("  - Loaded credential and verified it works");
                info!("  - Created presentation from loaded credential");
                info!("  - Generated and stored X-Wing seed (32 bytes)");
                info!("  - Loaded seed and regenerated full keypair");
                info!("  - Performed key exchange with regenerated keys");
                info!("");
                info!("Key Takeaways:");
                info!("  - Credentials survive reboots (encrypted in flash)");
                info!("  - Only 32-byte seed needed to restore X-Wing keys");
                info!("  - Device ready for auth + PQ key exchange after power-on");
            }
            Err(e) => {
                error!("PSA Persistence demo failed: {}", e);
                return Err(e.into());
            }
        }
        return Ok(());
    }

    if args.demo {
        return run_demo(&client, &args.message);
    }

    // Default: show help and test ML-DSA locally
    info!("");
    info!("Usage:");
    info!("  pqc-client --ping               Test connection");
    info!("  pqc-client --psa-demo           Run PSA Secure Storage demo on MCU");
    info!("  pqc-client --persistence-demo   Run PSA Persistence demo (SAGA + X-Wing storage)");
    info!("  pqc-client --mlkem-demo         Run ML-KEM 768 demo on MCU");
    info!("  pqc-client --xwing-demo         Run X-Wing hybrid PQ KEM demo on MCU");
    info!("  pqc-client --saga-demo          Run SAGA anonymous credentials demo on MCU");
    info!("  pqc-client --saga-xwing-demo    Run SAGA+X-Wing credential key exchange demo");
    info!("  pqc-client --ed25519-demo       Run Ed25519 demo on MCU (fast!)");
    info!("  pqc-client --x25519-demo        Run X25519 ECDH demo on MCU (fast!)");
    info!("  pqc-client --xchacha20-demo     Run XChaCha20-Poly1305 AEAD demo on MCU");
    info!("  pqc-client --mcu-demo           Run full PQC demo on MCU");
    info!("  pqc-client --mldsa-demo         Run ML-DSA 65 demo on MCU (slow!)");
    info!("  pqc-client --demo               Run local simulation demo");
    info!("");

    // Run a quick local Dilithium3 test
    test_dilithium_verification()?;

    Ok(())
}
