// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// SPI Peripheral Driver for Arduino Uno Q
//
// The MCU acts as SPI peripheral (slave), with the Linux MPU as controller (master).
// Based on the ArduinoCore-zephyr PR #383 implementation.

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/drivers/spi.h>
#include <string.h>

// SPI peripheral node from device tree
#define SPI_PERIPHERAL_NODE DT_COMPAT_GET_ANY_STATUS_OKAY(zephyr_spi_slave)

// Buffer size for SPI transfers (must match Linux side)
// Increased to 2KB to support X-Wing key exchange (pub key: 1216 bytes, ciphertext: 1120 bytes)
#define SPI_BUFFER_SIZE 2048

// Frame header
#define FRAME_MAGIC 0xAA55
#define FRAME_HEADER_SIZE 4

// Buffers
static uint8_t rx_buffer[SPI_BUFFER_SIZE];
static uint8_t tx_buffer[SPI_BUFFER_SIZE];

// SPI configuration
static const struct device *spi_dev = NULL;
static struct spi_config spi_cfg;
static struct spi_buf rx_buf;
static struct spi_buf_set rx_bufs;
static struct spi_buf tx_buf;
static struct spi_buf_set tx_bufs;

static bool spi_initialized = false;

// Initialize SPI peripheral
int spi_peripheral_init(void) {
    if (spi_initialized) {
        return 0;
    }

    // Get the SPI device from device tree
    spi_dev = DEVICE_DT_GET(DT_BUS(SPI_PERIPHERAL_NODE));
    if (!device_is_ready(spi_dev)) {
        printk("SPI peripheral device not ready\n");
        return -1;
    }

    // Initialize the device
    int ret = device_init(spi_dev);
    if (ret != 0 && ret != -EALREADY) {
        printk("Failed to init SPI device: %d\n", ret);
        return ret;
    }

    // Configure as SPI peripheral (slave)
    spi_cfg.frequency = 1000000; // 1MHz (actual speed set by controller)
    spi_cfg.operation = SPI_WORD_SET(8) | SPI_OP_MODE_SLAVE;

    // Set up buffers
    rx_buf.buf = rx_buffer;
    rx_buf.len = SPI_BUFFER_SIZE;
    rx_bufs.buffers = &rx_buf;
    rx_bufs.count = 1;

    tx_buf.buf = tx_buffer;
    tx_buf.len = SPI_BUFFER_SIZE;
    tx_bufs.buffers = &tx_buf;
    tx_bufs.count = 1;

    // Clear buffers
    memset(rx_buffer, 0, SPI_BUFFER_SIZE);
    memset(tx_buffer, 0, SPI_BUFFER_SIZE);

    spi_initialized = true;
    printk("SPI peripheral initialized\n");

    return 0;
}

// Populate TX buffer with data to send
// Returns number of bytes that can be written (payload area only)
size_t spi_peripheral_populate(const uint8_t *data, size_t len) {
    if (!spi_initialized || data == NULL) {
        return 0;
    }

    // Max payload size
    size_t max_payload = SPI_BUFFER_SIZE - FRAME_HEADER_SIZE;
    size_t to_copy = (len > max_payload) ? max_payload : len;

    // Write frame header
    tx_buffer[0] = (FRAME_MAGIC >> 8) & 0xFF;
    tx_buffer[1] = FRAME_MAGIC & 0xFF;
    tx_buffer[2] = (to_copy >> 8) & 0xFF;
    tx_buffer[3] = to_copy & 0xFF;

    // Copy payload
    memcpy(&tx_buffer[FRAME_HEADER_SIZE], data, to_copy);

    // Zero-pad the rest
    if (to_copy < max_payload) {
        memset(&tx_buffer[FRAME_HEADER_SIZE + to_copy], 0, max_payload - to_copy);
    }

    return to_copy;
}

// Wait for SPI transaction (blocking)
// This blocks until the Linux controller initiates a transfer
// Returns 0 on success, negative on error
int spi_peripheral_transceive(void) {
    if (!spi_initialized) {
        return -ENODEV;
    }

    // This blocks until controller starts a transfer
    int ret = spi_transceive(spi_dev, &spi_cfg, &tx_bufs, &rx_bufs);
    if (ret < 0) {
        printk("SPI transceive error: %d\n", ret);
    }

    return ret;
}

// Get received data (after transceive)
// Returns pointer to RX buffer
const uint8_t* spi_peripheral_get_rx(void) {
    return rx_buffer;
}

// Get RX payload (skips header)
const uint8_t* spi_peripheral_get_rx_payload(size_t *len) {
    if (!spi_initialized || len == NULL) {
        return NULL;
    }

    // Check magic
    uint16_t magic = (rx_buffer[0] << 8) | rx_buffer[1];
    if (magic != FRAME_MAGIC) {
        *len = 0;
        return NULL;
    }

    // Get length
    *len = (rx_buffer[2] << 8) | rx_buffer[3];
    if (*len > SPI_BUFFER_SIZE - FRAME_HEADER_SIZE) {
        *len = 0;
        return NULL;
    }

    return &rx_buffer[FRAME_HEADER_SIZE];
}

// Get buffer size
size_t spi_peripheral_buffer_size(void) {
    return SPI_BUFFER_SIZE;
}

// Get max payload size
size_t spi_peripheral_max_payload(void) {
    return SPI_BUFFER_SIZE - FRAME_HEADER_SIZE;
}
