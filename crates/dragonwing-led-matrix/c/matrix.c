// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// LED Matrix driver for Arduino Uno Q
// 
// This is adapted from the ArduinoCore-zephyr matrix.inc implementation.
// It provides the low-level charlieplexing driver that is called from Rust.

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/device.h>
#include <zephyr/drivers/counter.h>
#include <string.h>

// Pin mapping for charlieplexing 104 LEDs using 11 pins (PF0-PF10)
// Each LED is addressed by a pair of pins: one high, one low
static const uint8_t pins[][2] = {
    { 0, 1 }, // 0
    { 1, 0 },
    { 0, 2 },
    { 2, 0 },
    { 1, 2 },
    { 2, 1 },
    { 0, 3 },
    { 3, 0 },
    { 1, 3 },
    { 3, 1 },
    { 2, 3 }, // 10
    { 3, 2 },
    { 0, 4 },
    { 4, 0 },
    { 1, 4 },
    { 4, 1 },
    { 2, 4 },
    { 4, 2 },
    { 3, 4 },
    { 4, 3 },
    { 0, 5 }, // 20
    { 5, 0 },
    { 1, 5 },
    { 5, 1 },
    { 2, 5 },
    { 5, 2 },
    { 3, 5 },
    { 5, 3 },
    { 4, 5 },
    { 5, 4 },
    { 0, 6 }, // 30
    { 6, 0 },
    { 1, 6 },
    { 6, 1 },
    { 2, 6 },
    { 6, 2 },
    { 3, 6 },
    { 6, 3 },
    { 4, 6 },
    { 6, 4 },
    { 5, 6 }, // 40
    { 6, 5 },
    { 0, 7 },
    { 7, 0 },
    { 1, 7 },
    { 7, 1 },
    { 2, 7 },
    { 7, 2 },
    { 3, 7 },
    { 7, 3 },
    { 4, 7 }, // 50
    { 7, 4 },
    { 5, 7 },
    { 7, 5 },
    { 6, 7 },
    { 7, 6 },
    { 0, 8 },
    { 8, 0 },
    { 1, 8 },
    { 8, 1 },
    { 2, 8 }, // 60
    { 8, 2 },
    { 3, 8 },
    { 8, 3 },
    { 4, 8 },
    { 8, 4 },
    { 5, 8 },
    { 8, 5 },
    { 6, 8 },
    { 8, 6 },
    { 7, 8 }, // 70
    { 8, 7 },
    { 0, 9 },
    { 9, 0 },
    { 1, 9 },
    { 9, 1 },
    { 2, 9 },
    { 9, 2 },
    { 3, 9 },
    { 9, 3 },
    { 4, 9 }, // 80
    { 9, 4 },
    { 5, 9 },
    { 9, 5 },
    { 6, 9 },
    { 9, 6 },
    { 7, 9 },
    { 9, 7 },
    { 8, 9 },
    { 9, 8 },
    { 0, 10 }, // 90
    { 10, 0 },
    { 1, 10 },
    { 10, 1 },
    { 2, 10 },
    { 10, 2 },
    { 3, 10 },
    { 10, 3 },
    { 4, 10 },
    { 10, 4 },
    { 5, 10 }, // 100
    { 10, 5 },
    { 6, 10 },
    { 10, 6 },
};

#define NUM_MATRIX_LEDS 104

// Framebuffers
static uint8_t __attribute__((aligned)) framebuffer[NUM_MATRIX_LEDS / 8];
static uint8_t __attribute__((aligned)) framebuffer_color[NUM_MATRIX_LEDS];

// Mode flags
static bool color = false;
static uint8_t _max_grayscale_bits = 3;

// Turn on or off a specific LED using charlieplexing
static void turnLed(int idx, bool on) {
    // Get GPIOF base address - this is STM32-specific
    // GPIOF is at 0x42021400 for STM32U5
    volatile uint32_t *GPIOF_MODER = (volatile uint32_t *)0x42021400;
    volatile uint32_t *GPIOF_BSRR = (volatile uint32_t *)0x42021418;
    
    // Reset all pins to input (high-impedance)
    *GPIOF_MODER &= 0xFFC00000U;  // Clear lower 11 pin modes (PF0-PF10)
    
    if (on && idx < NUM_MATRIX_LEDS) {
        uint8_t pin0 = pins[idx][0];
        uint8_t pin1 = pins[idx][1];
        
        // Set pin0 high, pin1 low using BSRR
        *GPIOF_BSRR = (1U << pin0) | (1U << (pin1 + 16));
        
        // Configure both pins as outputs
        *GPIOF_MODER |= (1U << (pin0 << 1)) | (1U << (pin1 << 1));
    }
}

// Timer interrupt handler - called at high frequency to multiplex LEDs
static void timer_irq_handler_fn(const struct device *counter_dev, void *user_data) {
    static volatile int i_isr = 0;
    
    if (color) {
        // Grayscale mode
        static volatile int counter = 0;
        uint8_t brightness = (framebuffer_color[i_isr] * 8) / (1 << _max_grayscale_bits);
        
        switch (brightness) {
            case 0:
                turnLed(i_isr, false);
                break;
            case 1:
                turnLed(i_isr, counter % 23 == 0);
                break;
            case 2:
                turnLed(i_isr, counter % 15 == 0);
                break;
            case 3:
                turnLed(i_isr, counter % 5 == 0);
                break;
            case 4:
                turnLed(i_isr, counter % 3 == 0);
                break;
            case 5:
            case 6:
            case 7:
            default:
                turnLed(i_isr, true);
                break;
        }
        counter++;
    } else {
        // Binary mode
        turnLed(i_isr, ((framebuffer[i_isr >> 3] & (1 << (i_isr % 8))) != 0));
    }
    
    i_isr = (i_isr + 1) % NUM_MATRIX_LEDS;
}

// Write binary frame data
void matrixWrite(const uint32_t* buf) {
    memcpy(framebuffer, buf, NUM_MATRIX_LEDS / 8);
    color = false;
}

// Write grayscale frame data
void matrixGrayscaleWrite(const uint8_t* buf) {
    memcpy(framebuffer_color, buf, NUM_MATRIX_LEDS);
    color = true;
}

// Set grayscale bit depth
void matrixSetGrayscaleBits(uint8_t _max) {
    _max_grayscale_bits = _max;
}

#define TIMER DT_NODELABEL(counter_matrix)

// Initialize the matrix driver
void matrixBegin(void) {
    const struct device *const counter_dev = DEVICE_DT_GET(TIMER);
    
    if (!device_is_ready(counter_dev)) {
        printk("Matrix counter device not ready!\n");
        return;
    }
    
    counter_start(counter_dev);

    struct counter_top_cfg top_cfg;
    top_cfg.ticks = counter_us_to_ticks(counter_dev, 10);  // 10us period = 100kHz
    top_cfg.callback = timer_irq_handler_fn;
    top_cfg.user_data = &top_cfg;
    top_cfg.flags = 0;

    int err = counter_set_top_value(counter_dev, &top_cfg);
    if (err) {
        printk("Failed to set counter_set_top_value: %d\n", err);
    }
}

// Stop the matrix driver
void matrixEnd(void) {
    const struct device *const counter_dev = DEVICE_DT_GET(TIMER);
    counter_stop(counter_dev);
    
    // Turn off all LEDs
    turnLed(0, false);
}

// Play a grayscale video sequence
void matrixPlay(const uint8_t* buf, uint32_t len) {
    int i = 0;
    while (i < (len / NUM_MATRIX_LEDS)) {
        matrixGrayscaleWrite(&buf[i * NUM_MATRIX_LEDS]);
        i++;
        k_msleep(16);  // ~60fps
    }
}
