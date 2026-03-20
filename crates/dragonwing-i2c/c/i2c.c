/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * DragonWing I2C - Zephyr I2C bindings for Rust
 *
 * This file implements the C functions that wrap Zephyr's I2C API
 * for use from Rust FFI on the Arduino Uno Q (STM32U585).
 */

#include "i2c.h"

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(dragonwing_i2c, CONFIG_LOG_DEFAULT_LEVEL);

/*
 * Arduino Uno Q I2C mapping:
 * - Wire  (bus 0) = I2C2: Arduino header SDA/SCL pins (PB10/PB11)
 * - Wire1 (bus 1) = I2C4: Camera/internal connector (PD12/PD13)
 *
 * From the device tree overlay:
 *   i2cs = <&i2c2>, <&i2c4>;
 */

/* I2C device references from device tree */
#if DT_NODE_HAS_STATUS(DT_NODELABEL(i2c2), okay)
static const struct device *i2c_bus_0 = DEVICE_DT_GET(DT_NODELABEL(i2c2));
#else
static const struct device *i2c_bus_0 = NULL;
#endif

#if DT_NODE_HAS_STATUS(DT_NODELABEL(i2c4), okay)
static const struct device *i2c_bus_1 = DEVICE_DT_GET(DT_NODELABEL(i2c4));
#else
static const struct device *i2c_bus_1 = NULL;
#endif

/* Helper to get device by bus index */
static const struct device *get_i2c_dev(uint8_t bus_index)
{
    switch (bus_index) {
    case 0:
        return i2c_bus_0;
    case 1:
        return i2c_bus_1;
    default:
        return NULL;
    }
}

/* Convert Zephyr error codes to our error codes */
static int zephyr_to_dw_error(int zephyr_err)
{
    if (zephyr_err == 0) {
        return DW_I2C_OK;
    }
    
    switch (-zephyr_err) {
    case ENODEV:
    case EIO:
        return DW_I2C_ERR_NACK;
    case EBUSY:
        return DW_I2C_ERR_BUSY;
    case ETIMEDOUT:
        return DW_I2C_ERR_TIMEOUT;
    case EINVAL:
        return DW_I2C_ERR_INVALID;
    default:
        return DW_I2C_ERR_BUS;
    }
}

int dw_i2c_init(uint8_t bus_index)
{
    const struct device *dev = get_i2c_dev(bus_index);
    
    if (dev == NULL) {
        LOG_ERR("I2C bus %d not available", bus_index);
        return DW_I2C_ERR_INVALID;
    }
    
    if (!device_is_ready(dev)) {
        LOG_ERR("I2C bus %d device not ready", bus_index);
        return DW_I2C_ERR_BUS;
    }
    
    LOG_INF("I2C bus %d initialized", bus_index);
    return DW_I2C_OK;
}

void dw_i2c_deinit(uint8_t bus_index)
{
    /* Zephyr doesn't have explicit I2C deinit, just log */
    LOG_INF("I2C bus %d deinitialized", bus_index);
}

int dw_i2c_set_clock(uint8_t bus_index, uint32_t freq_hz)
{
    const struct device *dev = get_i2c_dev(bus_index);
    
    if (dev == NULL) {
        return DW_I2C_ERR_INVALID;
    }
    
    uint32_t dev_config;
    
    /* Map frequency to Zephyr I2C speed setting */
    if (freq_hz <= 100000) {
        dev_config = I2C_SPEED_SET(I2C_SPEED_STANDARD) | I2C_MODE_CONTROLLER;
    } else if (freq_hz <= 400000) {
        dev_config = I2C_SPEED_SET(I2C_SPEED_FAST) | I2C_MODE_CONTROLLER;
    } else {
        dev_config = I2C_SPEED_SET(I2C_SPEED_FAST_PLUS) | I2C_MODE_CONTROLLER;
    }
    
    int ret = i2c_configure(dev, dev_config);
    if (ret != 0) {
        LOG_ERR("Failed to configure I2C bus %d: %d", bus_index, ret);
        return zephyr_to_dw_error(ret);
    }
    
    LOG_DBG("I2C bus %d clock set to %u Hz", bus_index, freq_hz);
    return DW_I2C_OK;
}

int dw_i2c_write(uint8_t bus_index, uint8_t addr, const uint8_t *data, size_t len)
{
    const struct device *dev = get_i2c_dev(bus_index);
    
    if (dev == NULL || data == NULL) {
        return DW_I2C_ERR_INVALID;
    }
    
    int ret = i2c_write(dev, data, len, addr);
    if (ret != 0) {
        LOG_DBG("I2C write to 0x%02x failed: %d", addr, ret);
        return zephyr_to_dw_error(ret);
    }
    
    return DW_I2C_OK;
}

int dw_i2c_read(uint8_t bus_index, uint8_t addr, uint8_t *data, size_t len)
{
    const struct device *dev = get_i2c_dev(bus_index);
    
    if (dev == NULL || data == NULL) {
        return DW_I2C_ERR_INVALID;
    }
    
    int ret = i2c_read(dev, data, len, addr);
    if (ret != 0) {
        LOG_DBG("I2C read from 0x%02x failed: %d", addr, ret);
        return zephyr_to_dw_error(ret);
    }
    
    return DW_I2C_OK;
}

int dw_i2c_write_read(uint8_t bus_index, uint8_t addr,
                      const uint8_t *wr_data, size_t wr_len,
                      uint8_t *rd_data, size_t rd_len)
{
    const struct device *dev = get_i2c_dev(bus_index);
    
    if (dev == NULL || wr_data == NULL || rd_data == NULL) {
        return DW_I2C_ERR_INVALID;
    }
    
    int ret = i2c_write_read(dev, addr, wr_data, wr_len, rd_data, rd_len);
    if (ret != 0) {
        LOG_DBG("I2C write_read to 0x%02x failed: %d", addr, ret);
        return zephyr_to_dw_error(ret);
    }
    
    return DW_I2C_OK;
}

bool dw_i2c_probe(uint8_t bus_index, uint8_t addr)
{
    const struct device *dev = get_i2c_dev(bus_index);
    
    if (dev == NULL) {
        return false;
    }
    
    /* Use burst read with 0 bytes to probe - this is the standard way */
    struct i2c_msg msg = {
        .buf = NULL,
        .len = 0,
        .flags = I2C_MSG_WRITE | I2C_MSG_STOP,
    };
    
    int ret = i2c_transfer(dev, &msg, 1, addr);
    return (ret == 0);
}

int dw_i2c_scan(uint8_t bus_index, uint8_t start_addr, uint8_t end_addr,
                uint8_t *found, size_t max_found)
{
    if (found == NULL || max_found == 0) {
        return 0;
    }
    
    int count = 0;
    
    for (uint8_t addr = start_addr; addr <= end_addr && count < (int)max_found; addr++) {
        if (dw_i2c_probe(bus_index, addr)) {
            found[count++] = addr;
            LOG_INF("I2C device found at 0x%02x", addr);
        }
    }
    
    return count;
}
