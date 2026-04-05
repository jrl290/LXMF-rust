pub mod client;
pub mod cffi;
pub mod handlers;
pub mod lx_message;
pub mod lx_stamper;
pub mod lxmf;
pub mod lxm_peer;
pub mod lxm_router;
pub mod utilities;
pub mod version;
pub mod cli_util;
pub mod ffi;

pub use lx_message::LXMessage;
pub use lxm_router::LXMRouter;
pub use client::{LxmfClient, ClientConfig, ClientCallbacks};

/// Decode a base32-or-hex identity key string into raw bytes.
///
/// If the input looks like pure hex (even length, all hex digits), it is
/// decoded as hex. Otherwise it is treated as unpadded base32 (RFC 4648,
/// no-lowercase variant used by Reticulum).
pub fn decode_key(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    // Try hex first
    if !trimmed.is_empty()
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        && trimmed.len() % 2 == 0
    {
        return reticulum_rust::decode_hex(trimmed)
            .ok_or_else(|| "Hex decode failed".to_string());
    }
    // Fall back to base32 with auto-padding
    let mut padded = trimmed.to_string();
    while padded.len() % 8 != 0 {
        padded.push('=');
    }
    data_encoding::BASE32
        .decode(padded.as_bytes())
        .map_err(|e| format!("Base32 decode failed: {e}"))
}
