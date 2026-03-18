// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// QR code generation for Arduino IoT Companion App pairing

use qrcode::render::unicode;
use qrcode::QrCode;

use crate::camera_server::CameraServer;
use crate::otp::Otp;

/// QR code generator for device pairing.
///
/// Generates QR codes that the Arduino IoT Remote app can scan
/// to connect to this device.
pub struct QrGenerator;

impl QrGenerator {
    /// Build the pairing URL that will be encoded in the QR code.
    ///
    /// Format: `https://cloud.arduino.cc/installmobileapp?otp=XXXXXX&protocol=ws&ip=X.X.X.X&port=YYYY`
    ///
    /// Note: Despite the "cloud.arduino.cc" domain, this URL is only used by the app
    /// to parse connection parameters - no actual cloud connection is made. The app
    /// connects directly to the local IP/port specified.
    ///
    /// Parameters:
    /// - `otp` / `secret`: The 6-digit secret for BPP authentication (called "otp" in URL for compatibility)
    /// - `protocol`: "ws" or "wss" for WebSocket connection
    /// - `ip`: Local IP address of the server
    /// - `port`: WebSocket server port (typically 8080)
    pub fn build_pairing_url(otp: &Otp, local_ip: &str, websocket_port: u16) -> String {
        format!(
            "https://cloud.arduino.cc/installmobileapp?otp={}&protocol=ws&ip={}&port={}",
            otp.value(),
            local_ip,
            websocket_port
        )
    }

    /// Build the pairing URL from a secret string (for use with CameraServer)
    pub fn build_pairing_url_from_secret(
        secret: &str,
        protocol: &str,
        local_ip: &str,
        port: u16,
    ) -> String {
        format!(
            "https://cloud.arduino.cc/installmobileapp?otp={}&protocol={}&ip={}&port={}",
            secret, protocol, local_ip, port
        )
    }

    /// Build pairing URL directly from a CameraServer
    pub fn build_pairing_url_from_camera(camera: &CameraServer) -> String {
        Self::build_pairing_url_from_secret(
            camera.secret(),
            camera.protocol(),
            &camera.ip(),
            camera.port(),
        )
    }

    /// Generate a QR code for terminal display.
    ///
    /// Returns a string containing Unicode block characters that render
    /// the QR code when printed to a terminal.
    pub fn generate_terminal_qr(otp: &Otp, local_ip: &str, websocket_port: u16) -> String {
        let url = Self::build_pairing_url(otp, local_ip, websocket_port);
        Self::url_to_terminal_qr(&url)
    }

    /// Generate a terminal QR code from a secret string
    pub fn generate_terminal_qr_from_secret(
        secret: &str,
        protocol: &str,
        local_ip: &str,
        port: u16,
    ) -> String {
        let url = Self::build_pairing_url_from_secret(secret, protocol, local_ip, port);
        Self::url_to_terminal_qr(&url)
    }

    /// Generate a terminal QR code from a CameraServer
    pub fn generate_terminal_qr_from_camera(camera: &CameraServer) -> String {
        let url = Self::build_pairing_url_from_camera(camera);
        Self::url_to_terminal_qr(&url)
    }

    /// Convert a URL to a terminal-displayable QR code.
    pub fn url_to_terminal_qr(url: &str) -> String {
        let code = QrCode::new(url.as_bytes()).expect("Failed to create QR code");

        code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build()
    }

    /// Generate a formatted pairing display for the terminal.
    ///
    /// Includes the QR code, OTP, and connection details in a nice format.
    pub fn generate_pairing_display(
        otp: &Otp,
        local_ip: &str,
        websocket_port: u16,
        data_port: u16,
    ) -> String {
        let qr = Self::generate_terminal_qr(otp, local_ip, websocket_port);
        let url = Self::build_pairing_url(otp, local_ip, websocket_port);

        let remaining = otp
            .remaining_time()
            .map(|d| format!("{}s", d.as_secs()))
            .unwrap_or_else(|| "expired".to_string());

        format!(
            r#"
{qr}


Scan the QR code above with the Arduino IoT Remote app:


Or enter manually:
─────────────────
OTP:        {otp}
IP:         {ip:<15}
WS Port:    {ws_port:<5}
Data Port:  {data_port:<5} (video stream)

OTP expires in: {remaining:<10}

URL: {url}
Waiting for phone to connect...
"#,
            qr = qr,
            otp = otp.value(),
            ip = local_ip,
            ws_port = websocket_port,
            data_port = data_port,
            remaining = remaining,
            url = url,
        )
    }

    /// Generate a formatted pairing display for the CameraServer
    ///
    /// This is the preferred method when using the BPP-compatible camera server.
    pub fn generate_camera_pairing_display(camera: &CameraServer) -> String {
        let qr = Self::generate_terminal_qr_from_camera(camera);
        let url = Self::build_pairing_url_from_camera(camera);

        format!(
            r#"
{qr}

Scan the QR code above with the Arduino IoT Remote app

Connection Details:
───────────────────
Password:   {secret}
IP:         {ip:<15}
Port:       {port:<5}
Protocol:   {protocol}
Security:   {security}

URL: {url}
Waiting for phone to connect...
"#,
            qr = qr,
            secret = camera.secret(),
            ip = camera.ip(),
            port = camera.port(),
            protocol = camera.protocol(),
            security = camera.security_mode(),
            url = url,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_url() {
        let otp = Otp::generate();
        let url = QrGenerator::build_pairing_url(&otp, "192.168.1.100", 8080);

        assert!(url.contains("otp="));
        assert!(url.contains("protocol=ws"));
        assert!(url.contains("ip=192.168.1.100"));
        assert!(url.contains("port=8080"));
    }

    #[test]
    fn test_terminal_qr_generation() {
        let otp = Otp::generate();
        let qr = QrGenerator::generate_terminal_qr(&otp, "192.168.1.100", 8080);

        // QR code should contain unicode block characters
        assert!(!qr.is_empty());
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
    }
}
