// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// UART driver for RPC communication on Arduino Uno Q
//
// This provides the low-level UART access for the Rust RPC library.
// Uses LPUART1 (Serial1) which is connected to the Linux MPU.

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <string.h>

// LPUART1 is used for communication with the Linux MPU
#define RPC_UART_NODE DT_NODELABEL(lpuart1)

// Ring buffer for received data
#define RX_BUFFER_SIZE 1024
static uint8_t rx_buffer[RX_BUFFER_SIZE];
static volatile size_t rx_head = 0;
static volatile size_t rx_tail = 0;

// UART device
static const struct device *uart_dev = NULL;
static bool uart_initialized = false;

// UART interrupt callback
static void uart_isr_callback(const struct device *dev, void *user_data) {
    ARG_UNUSED(user_data);
    
    while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
        if (uart_irq_rx_ready(dev)) {
            uint8_t c;
            while (uart_fifo_read(dev, &c, 1) == 1) {
                size_t next_head = (rx_head + 1) % RX_BUFFER_SIZE;
                if (next_head != rx_tail) {
                    rx_buffer[rx_head] = c;
                    rx_head = next_head;
                }
                // If buffer full, drop the byte
            }
        }
    }
}

// Initialize UART for RPC communication
int rpc_uart_init(uint32_t baud_rate) {
    if (uart_initialized) {
        return 0;  // Already initialized
    }
    
    uart_dev = DEVICE_DT_GET(RPC_UART_NODE);
    if (!device_is_ready(uart_dev)) {
        printk("RPC UART device not ready\n");
        return -1;
    }
    
    // Configure UART (baud rate is typically set in device tree)
    // For runtime baud rate changes, would need uart_configure()
    
    // Set up interrupt-driven receive
    uart_irq_callback_set(uart_dev, uart_isr_callback);
    uart_irq_rx_enable(uart_dev);
    
    uart_initialized = true;
    printk("RPC UART initialized\n");
    
    return 0;
}

// Write bytes to UART
size_t rpc_uart_write(const uint8_t *data, size_t len) {
    if (!uart_initialized || data == NULL || len == 0) {
        printk("rpc_uart_write: failed (init=%d, data=%p, len=%zu)\n", 
               uart_initialized, data, len);
        return 0;
    }
    
    printk("rpc_uart_write: sending %zu bytes\n", len);
    for (size_t i = 0; i < len; i++) {
        uart_poll_out(uart_dev, data[i]);
    }
    printk("rpc_uart_write: done\n");
    
    return len;
}

// Read bytes from UART (non-blocking)
size_t rpc_uart_read(uint8_t *buffer, size_t max_len) {
    if (!uart_initialized || buffer == NULL || max_len == 0) {
        return 0;
    }
    
    size_t count = 0;
    while (count < max_len && rx_tail != rx_head) {
        buffer[count++] = rx_buffer[rx_tail];
        rx_tail = (rx_tail + 1) % RX_BUFFER_SIZE;
    }
    
    return count;
}

// Check if data is available
int rpc_uart_available(void) {
    if (!uart_initialized) {
        return 0;
    }
    
    if (rx_head >= rx_tail) {
        return rx_head - rx_tail;
    } else {
        return RX_BUFFER_SIZE - rx_tail + rx_head;
    }
}

// Flush TX buffer (wait for transmission complete)
void rpc_uart_flush(void) {
    if (!uart_initialized) {
        return;
    }
    
    // Poll-based TX doesn't need explicit flush
    // If using interrupt TX, would wait for TX complete here
    k_usleep(100);  // Small delay to ensure bytes are sent
}
