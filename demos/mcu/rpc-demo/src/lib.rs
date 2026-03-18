// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC Demo for Arduino Uno Q (STM32U585)
//
// Ultra-simplified demo to verify UART communication

#![no_std]
#![allow(unexpected_cfgs)]

use zephyr::time::{sleep, Duration};

// FFI to directly test UART
extern "C" {
    fn rpc_uart_init(baud_rate: u32) -> i32;
    fn rpc_uart_write(data: *const u8, len: usize) -> usize;
}

/// Main entry point called from C/Zephyr.
#[no_mangle]
extern "C" fn rust_main() {
    // Wait a bit for system to stabilize
    sleep(Duration::millis_at_least(500));

    // Initialize UART
    let result = unsafe { rpc_uart_init(115200) };

    if result != 0 {
        // Failed - just loop forever
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }

    // Simple MessagePack notification: [2, "test", [1]]
    // 93 = fixarray(3)
    // 02 = int 2 (type: NOTIFY)
    // a4 = fixstr(4) "test"
    // 91 = fixarray(1)
    // 01 = int 1
    let test_msg: [u8; 9] = [
        0x93, // fixarray(3)
        0x02, // int 2 (NOTIFY)
        0xa4, 0x74, 0x65, 0x73, 0x74, // fixstr(4) "test"
        0x91, // fixarray(1)
        0x01, // int 1
    ];

    let delay = Duration::millis_at_least(1000);

    loop {
        // Send the test message
        unsafe { rpc_uart_write(test_msg.as_ptr(), test_msg.len()) };

        sleep(delay);
    }
}

/// Main entry point called from C/Zephyr.
#[no_mangle]
extern "C" fn rust_main() {
    // Initialize the Zephyr logger
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("===========================================");
    warn!("  RPC Demo - Arduino Uno Q (Simplified)");
    warn!("  Testing direct UART communication");
    warn!("===========================================");

    // Initialize UART directly
    warn!("Initializing UART at 115200 baud...");
    let result = unsafe { rpc_uart_init(115200) };

    if result != 0 {
        warn!("Failed to initialize UART! Result: {}", result);
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }

    warn!("UART initialized successfully!");

    let delay = Duration::millis_at_least(2000);
    let mut counter: i32 = 0;

    loop {
        counter += 1;
        warn!("--- Iteration {} ---", counter);

        // Build a simple notification: [2, "test", [counter]]
        let mut packer = MsgPackPacker::new();
        packer.pack_rpc_notify("test", &[MsgPackValue::Int(counter as i64)]);

        let bytes = packer.as_bytes();
        warn!(
            "Sending {} bytes: {:02x?}",
            bytes.len(),
            &bytes[..bytes.len().min(20)]
        );

        // Send directly via FFI
        let written = unsafe { rpc_uart_write(bytes.as_ptr(), bytes.len()) };
        warn!("Wrote {} bytes", written);

        warn!("Sleeping for 2 seconds...");
        sleep(delay);
    }
}
