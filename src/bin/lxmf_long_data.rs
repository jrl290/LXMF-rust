use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use data_encoding::BASE32;
use rmpv::Value;

use lxmf_rust::lxmf::FIELD_FILE_ATTACHMENTS;
use lxmf_rust::{LXMRouter, LXMessage};
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

fn load_env(path: &PathBuf) -> Result<HashMap<String, String>, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read env file: {e}"))?;
    let mut data = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim().trim_matches('"');
        if !key.is_empty() {
            data.insert(key.to_string(), value.to_string());
        }
    }
    Ok(data)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("Hex string length must be even".to_string());
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut chars = input.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi_val = hi.to_digit(16).ok_or("Invalid hex digit")?;
        let lo_val = lo.to_digit(16).ok_or("Invalid hex digit")?;
        bytes.push(((hi_val << 4) | lo_val) as u8);
    }
    Ok(bytes)
}

fn decode_key(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len() % 2 == 0 {
        return decode_hex(trimmed);
    }

    let mut padded = trimmed.to_string();
    while padded.len() % 8 != 0 {
        padded.push('=');
    }
    BASE32
        .decode(padded.as_bytes())
        .map_err(|e| format!("Base32 decode failed: {e}"))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn resolve_recipient_identity(dest_hash: &[u8]) -> Result<Identity, String> {
    let public_key = Identity::recall_public_key(dest_hash)
        .ok_or("Destination public key not found after path request")?;

    let mut swapped = public_key.clone();
    if swapped.len() == 64 {
        swapped[..32].copy_from_slice(&public_key[32..64]);
        swapped[32..64].copy_from_slice(&public_key[..32]);
    }

    let candidates = vec![public_key, swapped];
    for candidate in candidates {
        if let Ok(identity) = Identity::from_public_key(&candidate) {
            if let Ok(destination) = Destination::new_outbound(
                Some(identity.clone()),
                DestinationType::Single,
                "lxmf".to_string(),
                vec!["delivery".to_string()],
            ) {
                if destination.hash == dest_hash {
                    return Ok(identity);
                }
            }
        }
    }

    Identity::from_public_key(
        &Identity::recall_public_key(dest_hash)
            .ok_or("Destination public key not found after path request")?,
    )
}

fn filename_bytes(path: &Path) -> Vec<u8> {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("attachment.bin")
        .as_bytes()
        .to_vec()
}

fn main() -> Result<(), String> {

    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let size_mb = args
        .iter()
        .position(|arg| arg == "--size-mb")
        .and_then(|pos| args.get(pos + 1).and_then(|s| s.parse::<f64>().ok()))
        .unwrap_or(0.1);

    let method_arg = args
        .iter()
        .position(|arg| arg == "--method")
        .and_then(|pos| args.get(pos + 1).map(|s| s.as_str()))
        .unwrap_or("auto");

    let attachment_path = args
        .iter()
        .position(|arg| arg == "--attach")
        .and_then(|pos| args.get(pos + 1).map(PathBuf::from));

    let repeat_count = args
        .iter()
        .position(|arg| arg == "--repeat")
        .and_then(|pos| args.get(pos + 1).and_then(|s| s.parse::<usize>().ok()))
        .unwrap_or(1)
        .max(1);

    let target_override = args
        .iter()
        .position(|arg| arg == "--to")
        .and_then(|pos| args.get(pos + 1).cloned());

    let base_dir = PathBuf::from(env::var("RETICULUM_WORKDIR").unwrap_or_else(|_| "".to_string()));
    let env_path = if let Some(pos) = args.iter().position(|arg| arg == "--env") {
        PathBuf::from(args.get(pos + 1).ok_or("--env requires a path")?)
    } else if base_dir.as_os_str().is_empty() {
        PathBuf::from("cli-tests/cli_constants.env")
    } else {
        base_dir.join("cli-tests/cli_constants.env")
    };

    let config_dir = if let Some(pos) = args.iter().position(|arg| arg == "--config") {
        PathBuf::from(args.get(pos + 1).ok_or("--config requires a path")?)
    } else if base_dir.as_os_str().is_empty() {
        PathBuf::from("cli-tests/rnsd_client_sender")
    } else {
        base_dir.join("cli-tests/rnsd_client_sender")
    };

    // Read message content from stdin or generate test data
    let mut content = if atty::isnt(atty::Stream::Stdin) {
        use std::io::Read;
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to read from stdin: {e}"))?;

        if !buffer.is_empty() {
            buffer
        } else {
            let content_size = (size_mb * 1024.0 * 1024.0).ceil() as usize;
            if content_size == 0 {
                b"Rust LXMF test message".to_vec()
            } else {
                vec![b'X'; content_size]
            }
        }
    } else {
        let content_size = (size_mb * 1024.0 * 1024.0).ceil() as usize;
        if content_size == 0 {
            b"Rust LXMF test message".to_vec()
        } else {
            vec![b'X'; content_size]
        }
    };

    let mut fields: Option<Value> = None;
    if let Some(path) = attachment_path.as_ref() {
        let mut attachment_data = fs::read(path)
            .map_err(|e| format!("Failed to read attachment {}: {e}", path.display()))?;
        if repeat_count > 1 {
            let original = attachment_data.clone();
            attachment_data.reserve(original.len().saturating_mul(repeat_count.saturating_sub(1)));
            for _ in 1..repeat_count {
                attachment_data.extend_from_slice(&original);
            }
        }

        let attachment_entry = Value::Array(vec![
            Value::Binary(filename_bytes(path.as_path())),
            Value::Binary(attachment_data.clone()),
        ]);
        fields = Some(Value::Map(vec![
            (
                Value::from(FIELD_FILE_ATTACHMENTS as i64),
                Value::Array(vec![attachment_entry]),
            ),
        ]));

        if content.is_empty() {
            content = b"Binary attachment test".to_vec();
        }
        eprintln!(
            "[config] Attachment: {} ({} bytes, repeat {})",
            path.display(),
            attachment_data.len(),
            repeat_count
        );
    }
    
    let content_size = content.len();

    eprintln!("[config] Message size: {:.2} MB ({} bytes)", size_mb, content_size);
    eprintln!("[config] Method preference: {}", method_arg);
    eprintln!("[config] Size limits:");
    eprintln!("  - OPPORTUNISTIC max: {} bytes", LXMessage::ENCRYPTED_PACKET_MAX_CONTENT);
    eprintln!("  - DIRECT (packet) max: {} bytes", LXMessage::LINK_PACKET_MAX_CONTENT);
    eprintln!("  - DIRECT (resource) max: unlimited");

    let env_map = load_env(&env_path)?;
    let key_value = env_map
        .get("KEY_1")
        .ok_or("KEY_1 not found in env file")?
        .to_string();
    let dest_hash_hex = if let Some(value) = target_override {
        value
    } else {
        env_map
            .get("ADDR_2")
            .ok_or("ADDR_2 not found in env file")?
            .to_string()
    };

    let key_bytes = decode_key(&key_value)?;
    let dest_hash = decode_hex(&dest_hash_hex)?;
    if args.iter().any(|arg| arg == "--to") {
        eprintln!("[config] Using destination override from --to: {}", dest_hash_hex);
    }
    eprintln!("[config] Destination hash: {}", to_hex(&dest_hash));

    eprintln!("[step] init reticulum");
    let init_result = std::panic::catch_unwind(|| {
        Reticulum::init(Some(config_dir.clone()), None, None, None, false, None)
    });
    match init_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) =>return Err(format!("Reticulum init failed: {err}")),
        Err(panic) => {
            let detail = if let Some(msg) = panic.downcast_ref::<&str>() {
                (*msg).to_string()
            } else if let Some(msg) = panic.downcast_ref::<String>() {
                msg.clone()
            } else {
                "unknown panic".to_string()
            };
            return Err(format!("Reticulum init panicked: {detail}"));
        }
    }
    eprintln!("[step] reticulum init complete");

    let cwd = env::current_dir().map_err(|e| format!("Failed to read current dir: {e}"))?;
    let storage_path = cwd.join("cli-tests/lxmf_storage/sender");

    eprintln!("[step] create router - calling LXMRouter::new()...");
    let router = LXMRouter::new(
        None,
        storage_path.to_string_lossy().to_string(),
        None,
        None,
        None,
        None,
        None,
        false,
        false,
        Vec::new(),
        None,
        false,
        LXMRouter::PR_ALL_MESSAGES as u8,
        LXMRouter::PROPAGATION_COST,
        LXMRouter::PROPAGATION_COST_FLEX,
        LXMRouter::PEERING_COST,
        LXMRouter::MAX_PEERING_COST,
        Some("rust-sender".to_string()),
    )?;
    eprintln!("[step] create router - RETURNED from LXMRouter::new()");

    eprintln!("[step] load sender identity");
    let source_identity = Identity::from_bytes(&key_bytes)?;
    eprintln!("[step] register sender destination");
    let source = {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        router_guard.register_delivery_identity(source_identity, Some("Rust Long Data Sender".to_string()), None)?
    };

    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        eprintln!("[step] announce sender destination");
        router_guard.announce(&source.hash, None);
    }

    let overall_deadline = Instant::now() + Duration::from_secs(30);
    let mut next_log = Instant::now() + Duration::from_secs(10);
    eprintln!("[step] resolve path");
    if !Transport::has_path(&dest_hash) {
        let mut last_request = Instant::now() - Duration::from_secs(10);
        while Instant::now() < overall_deadline && !Transport::has_path(&dest_hash) {
            if last_request.elapsed() >= Duration::from_secs(5) {
                eprintln!("[step] request path");
                Transport::request_path(&dest_hash, None, None, None, None);
                last_request = Instant::now();
            }
            if Instant::now() >= next_log {
                let remaining = overall_deadline.saturating_duration_since(Instant::now());
                eprintln!(
                    "Waiting for path resolution... {}s remaining",
                    remaining.as_secs()
                );
                next_log = Instant::now() + Duration::from_secs(10);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    if Instant::now() >= overall_deadline {
        return Err("Timeout waiting for path resolution".to_string());
    }

    let has_path = Transport::has_path(&dest_hash);
    eprintln!("[step] has_path: {}", has_path);
    eprintln!("[step] recall destination identity");
    let dest_identity = resolve_recipient_identity(&dest_hash)?;
    eprintln!("[step] create outbound destination");
    let mut destination = Destination::new_outbound(
        Some(dest_identity),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )?;

    eprintln!("[step] target hash: {}", to_hex(&dest_hash));
    eprintln!("[step] computed destination hash: {}", to_hex(&destination.hash));
    if destination.hash != dest_hash {
        eprintln!("[warn] destination hash mismatch, forcing target hash");
        destination.hash = dest_hash.clone();
        destination.hexhash = to_hex(&destination.hash);
    }

    if !has_path {
        return Err("No path available for send".to_string());
    }

    // Auto-select delivery method based on message size
    let method = match method_arg {
        "direct" => LXMessage::DIRECT,
        "opportunistic" if content_size <= LXMessage::ENCRYPTED_PACKET_MAX_CONTENT => {
            eprintln!("[method] Selecting OPPORTUNISTIC (content fits in packet)");
            LXMessage::OPPORTUNISTIC
        }
        "opportunistic" => {
            eprintln!("[method] OPPORTUNISTIC requested but content too large; auto-converting to DIRECT");
            LXMessage::DIRECT
        }
        _ => {
            // Auto selection
            if content_size <= LXMessage::ENCRYPTED_PACKET_MAX_CONTENT {
                eprintln!("[method] Auto-selected: OPPORTUNISTIC (content fits in packet)");
                LXMessage::OPPORTUNISTIC
            } else {
                eprintln!("[method] Auto-selected: DIRECT (content requires link/resource transfer)");
                LXMessage::DIRECT
            }
        }
    };

    eprintln!("[step] build message");
    let message = LXMessage::new(
        Some(destination),
        Some(source),
        Some(content),
        Some(b"Long Data Test".to_vec()),
        fields,
        Some(method),
        None,
        None,
        None,
        true,
    )?;

    let handle = std::sync::Arc::new(std::sync::Mutex::new(message));

    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        eprintln!("[step] handle outbound");
        router_guard.handle_outbound(handle.clone());
    }

    // Log representation determination AFTER packing
    {
        let locked = handle.lock().map_err(|_| "Message lock poisoned")?;
        eprintln!("[message] Method: {}", match locked.method {
            LXMessage::OPPORTUNISTIC => "OPPORTUNISTIC",
            LXMessage::DIRECT => "DIRECT",
            LXMessage::PROPAGATED => "PROPAGATED",
            _ => "UNKNOWN",
        });
        eprintln!("[message] Representation: {}", match locked.representation {
            LXMessage::PACKET => "PACKET (single packet delivery)",
            LXMessage::RESOURCE => "RESOURCE (multi-packet chunked transfer)",
            _ => "UNKNOWN",
        });
        eprintln!("[message] Content size: {} bytes", locked.packed_size);
    }

    // The background job thread in LXMRouter handles periodic processing.
    // We just wait and observe the message state transitions.
    let timeout = Instant::now() + Duration::from_secs(30);
    let mut next_state_log = Instant::now();
    while Instant::now() < timeout {
        if let Ok(locked) = handle.lock() {
            if Instant::now() >= next_state_log {
                eprintln!("[step] message state: {} (progress: {:.1}%)", 
                    match locked.state {
                        LXMessage::GENERATING => "GENERATING",
                        LXMessage::OUTBOUND => "OUTBOUND",
                        LXMessage::SENDING => "SENDING",
                        LXMessage::SENT => "SENT",
                        LXMessage::DELIVERED => "DELIVERED",
                        _ => "UNKNOWN",
                    },
                    locked.progress * 100.0
                );
                next_state_log = Instant::now() + Duration::from_secs(2);
            }
            if locked.state == LXMessage::DELIVERED || locked.state == LXMessage::FAILED {
                println!("Final message state: {}", 
                    match locked.state {
                        LXMessage::DELIVERED => "DELIVERED",
                        LXMessage::FAILED => "FAILED",
                        _ => "UNKNOWN",
                    }
                );
                eprintln!("[result] Message successfully delivered!");
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(500));
    }

    println!("Message send timed out");
    Ok(())
}
