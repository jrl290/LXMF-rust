//! Shared CLI utility functions used by both `lxmf_send` and `lxmf_recv` binaries.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format bytes as lowercase hex using `reticulum_rust::hexrep`.
pub fn to_hex(bytes: &[u8]) -> String {
    reticulum_rust::hexrep(bytes, false)
}

/// Current UNIX timestamp as `"seconds.millis"` string.
pub fn unix_timestamp_string() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

/// Look up `--name <value>` style CLI arguments.
pub fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|pos| args.get(pos + 1))
        .map(|s| s.as_str())
}

/// Look up `--name <value>` or `--name=value` style CLI arguments.
pub fn arg_value_flexible(args: &[String], name: &str) -> Option<String> {
    if let Some(value) = arg_value(args, name) {
        return Some(value.to_string());
    }
    let prefix = format!("{name}=");
    args.iter()
        .find_map(|arg| arg.strip_prefix(&prefix).map(|v| v.to_string()))
}

/// Check whether a boolean flag like `--verbose` is present.
pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}
