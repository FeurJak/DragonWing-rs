// SPDX-License-Identifier: Apache-2.0 OR MIT
// Build script for SSD1306 Demo

fn main() {
    // Tell Zephyr build system about our dependencies
    zephyr_build::export_bool_kconfig();
}
