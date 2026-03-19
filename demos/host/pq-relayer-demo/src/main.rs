// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! PQ-Ratchet Relayer Demo
//!
//! CLI tool for testing the Secure-Relayer crate.
//! Connects to the MPU proxy and sends encrypted data to the MCU.
//!
//! # Usage
//!
//! ```bash
//! # Send a text message
//! pq-relayer-demo --mpu ws://localhost:8080 --send "Hello, MCU!"
//!
//! # Send a file
//! pq-relayer-demo --mpu ws://localhost:8080 --file image.bin
//!
//! # Interactive mode
//! pq-relayer-demo --mpu ws://localhost:8080 --interactive
//! ```

use std::fs;
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};

use dragonwing_secure_relayer::{Config, SecureRelayer};

/// PQ-Ratchet Relayer Demo
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// MPU proxy WebSocket address
    #[arg(short, long, default_value = "ws://localhost:8080")]
    mpu: String,

    /// Text message to send
    #[arg(short, long)]
    send: Option<String>,

    /// File to send
    #[arg(short, long)]
    file: Option<String>,

    /// Interactive mode (read from stdin)
    #[arg(short, long)]
    interactive: bool,

    /// Perform handshake only (test connection)
    #[arg(long)]
    handshake_only: bool,

    /// Number of times to send the message (for load testing)
    #[arg(short, long, default_value = "1")]
    count: u32,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    info!("PQ-Ratchet Relayer Demo");
    info!("  MPU: {}", args.mpu);

    // Create relayer config
    let config = Config {
        mpu_address: args.mpu.clone(),
        connect_timeout_secs: 10,
        max_message_size: 128 * 1024,
    };

    // Create and connect relayer
    let mut relayer = SecureRelayer::new(config);

    info!("Connecting to MPU proxy...");
    relayer.connect().await.context("Failed to connect")?;
    info!("Connected!");

    info!("Performing PQ-Ratchet handshake...");
    relayer.handshake().await.context("Handshake failed")?;
    info!("Handshake complete! Session established.");
    info!("  Epoch: {}", relayer.epoch().unwrap_or(0));

    if args.handshake_only {
        info!("Handshake-only mode, closing connection.");
        relayer.close().await?;
        return Ok(());
    }

    // Determine what to send
    if let Some(message) = args.send {
        // Send text message
        send_data(&mut relayer, message.as_bytes(), args.count).await?;
    } else if let Some(file_path) = args.file {
        // Send file
        info!("Reading file: {}", file_path);
        let data = fs::read(&file_path).context("Failed to read file")?;
        info!("File size: {} bytes", data.len());
        send_data(&mut relayer, &data, args.count).await?;
    } else if args.interactive {
        // Interactive mode
        interactive_mode(&mut relayer).await?;
    } else {
        // Default: send a test message
        let test_msg = b"Hello from PQ-Ratchet Relayer Demo!";
        send_data(&mut relayer, test_msg, args.count).await?;
    }

    // Close connection
    info!("Closing connection...");
    relayer.close().await?;
    info!("Done!");

    Ok(())
}

/// Send data through the relayer
async fn send_data(relayer: &mut SecureRelayer, data: &[u8], count: u32) -> Result<()> {
    for i in 0..count {
        if count > 1 {
            info!("Sending message {}/{}", i + 1, count);
        }

        info!("Encrypting {} bytes...", data.len());
        relayer
            .send_encrypted(data)
            .await
            .context("Failed to send encrypted data")?;

        info!("Message sent successfully!");

        if data.len() <= 64 {
            // Show content for small messages
            if let Ok(s) = std::str::from_utf8(data) {
                info!("  Content: \"{}\"", s);
            } else {
                info!("  Content (hex): {}", hex::encode(data));
            }
        } else {
            info!("  Size: {} bytes", data.len());
            info!("  First 32 bytes: {}", hex::encode(&data[..32.min(data.len())]));
        }
    }

    Ok(())
}

/// Interactive mode - read lines from stdin and send them
async fn interactive_mode(relayer: &mut SecureRelayer) -> Result<()> {
    info!("Interactive mode. Type messages and press Enter to send.");
    info!("Commands: /quit, /epoch, /help");
    info!("---");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("> ");
        stdout.flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            // EOF
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Check for commands
        if line.starts_with('/') {
            match line {
                "/quit" | "/exit" | "/q" => {
                    info!("Exiting...");
                    break;
                }
                "/epoch" => {
                    info!("Current epoch: {}", relayer.epoch().unwrap_or(0));
                    continue;
                }
                "/status" => {
                    info!("Connected: {}", relayer.is_connected());
                    info!("Epoch: {}", relayer.epoch().unwrap_or(0));
                    continue;
                }
                "/help" => {
                    println!("Commands:");
                    println!("  /quit, /exit, /q - Exit interactive mode");
                    println!("  /epoch          - Show current ratchet epoch");
                    println!("  /status         - Show connection status");
                    println!("  /help           - Show this help");
                    println!();
                    println!("Any other input is sent as an encrypted message.");
                    continue;
                }
                _ => {
                    warn!("Unknown command: {}", line);
                    continue;
                }
            }
        }

        // Send the message
        match relayer.send_encrypted(line.as_bytes()).await {
            Ok(()) => {
                info!("Sent: \"{}\" ({} bytes)", line, line.len());
            }
            Err(e) => {
                error!("Send failed: {}", e);
            }
        }
    }

    Ok(())
}
