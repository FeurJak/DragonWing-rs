// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Remote IoT Demo - Arduino IoT Companion App integration
//
// This demo shows how to use the dragonwing-remote-iot crate to connect
// a phone via the Arduino IoT Remote app and receive video frames.
//
// Usage:
//   remote-iot-demo [OPTIONS]
//
// The demo will:
// 1. Start a WebSocket camera server with BPP protocol
// 2. Display a QR code for the Arduino IoT Remote app to scan
// 3. Wait for phone to connect using the shared secret
// 4. Receive and count video frames from the phone

use anyhow::Result;
use clap::Parser;
use dragonwing_remote_iot::{
    CameraEvent, CameraServerBuilder, QrGenerator, DEFAULT_CAMERA_PORT,
};
use std::net::SocketAddr;

/// Arduino IoT Remote App Demo
#[derive(Parser, Debug)]
#[command(name = "remote-iot-demo")]
#[command(about = "Connect phone via Arduino IoT Companion App")]
struct Args {
    /// Server port for WebSocket camera
    #[arg(short, long, default_value_t = DEFAULT_CAMERA_PORT)]
    port: u16,

    /// Use signing only (no encryption) - less secure but works with older apps
    #[arg(long)]
    no_encryption: bool,

    /// Custom secret (6 digits) - auto-generated if not specified
    #[arg(short, long)]
    secret: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║       DragonWing Remote IoT - Camera Demo                 ║");
    println!("║       Compatible with Arduino IoT Companion App           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    // Build camera server
    let mut builder = CameraServerBuilder::new()
        .port(args.port)
        .use_encryption(!args.no_encryption);

    if let Some(secret) = args.secret {
        if secret.len() != 6 || !secret.chars().all(|c| c.is_ascii_digit()) {
            eprintln!("Error: Secret must be exactly 6 digits");
            std::process::exit(1);
        }
        builder = builder.secret(&secret);
    }

    let camera = builder.build();

    // Print connection info
    log::info!("Camera server configuration:");
    log::info!("  IP:       {}", camera.ip());
    log::info!("  Port:     {}", camera.port());
    log::info!("  Protocol: {}", camera.protocol());
    log::info!("  Security: {}", camera.security_mode());
    log::info!("  Secret:   {}", camera.secret());

    // Print QR code
    let qr_display = QrGenerator::generate_camera_pairing_display(&camera);
    println!("{}", qr_display);

    // Subscribe to events
    let mut events = camera.subscribe();

    // Spawn event handler
    tokio::spawn(async move {
        let mut frame_count = 0u64;
        let mut last_report = std::time::Instant::now();

        while let Ok(event) = events.recv().await {
            match event {
                CameraEvent::Connected { client_address, client_name } => {
                    println!();
                    log::info!("Phone connected!");
                    log::info!("  Address: {}", client_address);
                    log::info!("  Name:    {}", client_name);
                    println!();
                }

                CameraEvent::Disconnected { client_address, client_name } => {
                    println!();
                    log::info!("Phone disconnected: {} ({})", client_name, client_address);
                    log::info!("Total frames received: {}", frame_count);
                    frame_count = 0;
                    println!();
                }

                CameraEvent::Streaming => {
                    log::info!("Video streaming started!");
                    last_report = std::time::Instant::now();
                }

                CameraEvent::Paused => {
                    log::info!("Video streaming paused");
                }

                CameraEvent::FrameReceived { size, timestamp_ms: _ } => {
                    frame_count += 1;
                    
                    // Report every second
                    if last_report.elapsed().as_secs() >= 1 {
                        let fps = frame_count as f64 / last_report.elapsed().as_secs_f64();
                        log::info!(
                            "Receiving video: {} frames ({:.1} fps, last frame: {} bytes)",
                            frame_count,
                            fps,
                            size
                        );
                        last_report = std::time::Instant::now();
                    }
                }

                CameraEvent::Error { message } => {
                    log::error!("Camera error: {}", message);
                }
            }
        }
    });

    // Print instructions
    println!("Instructions:");
    println!("1. Install 'Arduino IoT Remote' app on your phone");
    println!("2. Ensure phone and this device are on the same WiFi network");
    println!("3. Open the app and scan the QR code above");
    println!("4. When prompted, enter the password: {}", camera.secret());
    println!();
    println!("Press Ctrl+C to stop the server");
    println!();

    // Run the camera server
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", camera.port()).parse()?;
    camera.run(bind_addr).await?;

    Ok(())
}
