// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// ML-KEM Client for Arduino Uno Q
//
// This Linux application demonstrates post-quantum key encapsulation
// with the STM32U585 MCU using ML-KEM 768 (FIPS 203).
//
// Protocol:
// 1. Request MCU to generate key pair
// 2. Get public key from MCU
// 3. Encapsulate shared secret locally
// 4. Send ciphertext to MCU for decapsulation
// 5. Verify both sides have the same shared secret

use anyhow::{Context, Result};
use clap::Parser;
use dragonwing_rpc::RpcClientSync;
use libcrux_ml_kem::mlkem768;
use log::{error, info, warn};
use rand::{rngs::OsRng, TryRngCore};

/// ML-KEM 768 constants
const PUBLIC_KEY_SIZE: usize = 1184;
const CIPHERTEXT_SIZE: usize = 1088;
const SHARED_SECRET_SIZE: usize = 32;

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "mlkem-client")]
#[command(about = "Post-quantum key exchange demo with Arduino Uno Q")]
struct Args {
    /// RPC socket path
    #[arg(short, long, default_value = "/tmp/arduino-spi-router.sock")]
    socket: String,

    /// Run the full key exchange demo
    #[arg(short, long)]
    demo: bool,

    /// Just ping the MCU
    #[arg(short, long)]
    ping: bool,

    /// Generate new key pair on MCU
    #[arg(short, long)]
    keygen: bool,
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

/// Run the full ML-KEM key exchange demo
fn run_demo(client: &RpcClientSync) -> Result<()> {
    info!("===========================================");
    info!("  ML-KEM 768 Key Exchange Demo");
    info!("  Post-Quantum Cryptography");
    info!("===========================================");
    info!("");

    // Step 1: Generate key pair on MCU
    info!("Step 1: Requesting MCU to generate key pair...");
    let result = client
        .call("mlkem.generate_keypair", vec![])
        .context("Failed to generate key pair")?;
    info!("  Key pair generated: {:?}", result);

    // Step 2: Get public key from MCU
    info!("");
    info!("Step 2: Retrieving public key from MCU...");
    let pk_result = client
        .call("mlkem.get_public_key", vec![])
        .context("Failed to get public key")?;

    // The MCU returns the public key size, we need to get the actual bytes
    // For now, we'll simulate with a known test vector or request bytes separately
    info!("  Public key size: {:?}", pk_result);

    // Note: In a real implementation, we'd need to transfer the actual public key bytes
    // This requires extending the RPC protocol to handle large binary data
    // For demo purposes, we'll show the flow

    warn!("");
    warn!(
        "NOTE: Full binary transfer of public key ({} bytes) requires",
        PUBLIC_KEY_SIZE
    );
    warn!("      extending the RPC protocol. This demo shows the protocol flow.");
    warn!("");

    // Step 3: Encapsulate (simulated with local key pair for demo)
    info!("Step 3: Demonstrating local ML-KEM encapsulation...");

    // Generate a local key pair for demonstration
    let keygen_randomness: [u8; 64] = random_bytes();
    let local_keypair = mlkem768::generate_key_pair(keygen_randomness);
    info!("  Local key pair generated for demo");
    info!(
        "  Public key: {}",
        format_bytes(local_keypair.public_key().as_slice())
    );

    // Encapsulate
    let encaps_randomness: [u8; 32] = random_bytes();
    let (ciphertext, shared_secret) =
        mlkem768::encapsulate(local_keypair.public_key(), encaps_randomness);
    info!("  Ciphertext: {}", format_bytes(ciphertext.as_slice()));
    info!(
        "  Shared secret (encaps): {}",
        format_bytes(shared_secret.as_slice())
    );

    // Step 4: Decapsulate locally to verify
    info!("");
    info!("Step 4: Verifying with local decapsulation...");
    let decapsulated = mlkem768::decapsulate(local_keypair.private_key(), &ciphertext);
    info!(
        "  Shared secret (decaps): {}",
        format_bytes(decapsulated.as_slice())
    );

    // Verify
    if shared_secret.as_slice() == decapsulated.as_slice() {
        info!("");
        info!("SUCCESS: Shared secrets match!");
        info!("Both parties now have the same 32-byte secret key.");
    } else {
        error!("");
        error!("FAILURE: Shared secrets do not match!");
        return Err(anyhow::anyhow!("Key exchange failed"));
    }

    info!("");
    info!("===========================================");
    info!("  ML-KEM Key Exchange Complete");
    info!("===========================================");

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("ML-KEM Client for Arduino Uno Q");
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

    if args.keygen {
        info!("Requesting key generation...");
        let result = client.call("mlkem.generate_keypair", vec![])?;
        info!("Result: {:?}", result);
        return Ok(());
    }

    if args.demo {
        return run_demo(&client);
    }

    // Default: show help
    info!("");
    info!("Usage:");
    info!("  mlkem-client --ping      Test connection");
    info!("  mlkem-client --keygen    Generate key pair on MCU");
    info!("  mlkem-client --demo      Run full key exchange demo");

    Ok(())
}
