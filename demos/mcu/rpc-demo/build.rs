// SPDX-License-Identifier: Apache-2.0 OR MIT
// Build script for RPC Demo

fn main() {
    // This call makes config entries available in the code for every device tree node.
    zephyr_build::dt_cfgs();
}
