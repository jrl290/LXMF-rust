use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::BASE32;
use rmpv::Value;

use lxmf_rust::lxmf::FIELD_FILE_ATTACHMENTS;
use lxmf_rust::{LXMRouter, LXMessage};
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

const DEBUG_KEY_1: &str = "KJKBJI4QZNTBOWDDUS6JIHIOMNCZ747L3G2A4453PLDYLHBSKDD5TV7IHYMEB7HXUX6Z74XEDVYYZQLNHTXMBGZP6BSRUOT6YGCC4BI";
const DEBUG_ADDR_1: &str = "99e5aebb4ac27f05695c98e8e22540ca";
const DEBUG_ADDR_2: &str = "4c0c6c7f420da5df5203554462cbb3bc";
const DEBUG_ADDR_3: &str = "29b00f4f93eb95c08f1c67eb31c5f9f6";
const DEBUG_MC_RECV_ADDR: &str = "13f4b14dd364a672e853a37fb534678c";
const PY_SENDER_POST_SEND_SECONDS: u64 = 30;

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

fn unix_timestamp_string() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

fn state_name(state: u8) -> &'static str {
    match state {
        LXMessage::GENERATING => "GENERATING",
        LXMessage::OUTBOUND => "OUTBOUND",
        LXMessage::SENDING => "SENDING",
        LXMessage::SENT => "SENT",
        LXMessage::DELIVERED => "DELIVERED",
        LXMessage::PAPER => "PAPER",
        LXMessage::PROPAGATED => "PROPAGATED",
        LXMessage::FAILED => "FAILED",
        LXMessage::CANCELLED => "CANCELLED",
        LXMessage::REJECTED => "REJECTED",
        _ => "UNKNOWN",
    }
}

fn filename_bytes(path: &Path) -> Vec<u8> {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("attachment.bin")
        .as_bytes()
        .to_vec()
}

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|pos| args.get(pos + 1))
        .map(|s| s.as_str())
}

fn arg_value_flexible(args: &[String], name: &str) -> Option<String> {
    if let Some(value) = arg_value(args, name) {
        return Some(value.to_string());
    }
    let prefix = format!("{name}=");
    args.iter()
        .find_map(|arg| arg.strip_prefix(&prefix).map(|v| v.to_string()))
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn main() -> Result<(), String> {
    let run_start = Instant::now();
    eprintln!("[time] started: {}", unix_timestamp_string());
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let interrupted_flag = interrupted.clone();
        if let Err(err) = ctrlc::set_handler(move || {
            interrupted_flag.store(true, Ordering::SeqCst);
        }) {
            eprintln!("[warn] Failed to install SIGINT handler: {}", err);
        }
    }

    let args: Vec<String> = env::args().collect();

    if has_flag(&args, "--mc")
        || has_flag(&args, "--sb")
        || has_flag(&args, "--rust-config")
        || has_flag(&args, "--sender-config")
    {
        return Err(
            "Legacy flags are removed. Use --dest=mc|sd|test2|test3|custom and --net=local|rpi"
                .to_string(),
        );
    }

    let base_dir = PathBuf::from(env::var("RETICULUM_WORKDIR").unwrap_or_else(|_| "".to_string()));
    let env_path = if let Some(path) = arg_value_flexible(&args, "--env") {
        PathBuf::from(path)
    } else if base_dir.as_os_str().is_empty() {
        PathBuf::from("cli-tests/cli_constants.env")
    } else {
        base_dir.join("cli-tests/cli_constants.env")
    };

    let net_selector = arg_value_flexible(&args, "--net").unwrap_or_else(|| "rpi".to_string());

    let config_dir = if let Some(path) = arg_value_flexible(&args, "--config") {
        PathBuf::from(path)
    } else if net_selector.eq_ignore_ascii_case("local") {
        if base_dir.as_os_str().is_empty() {
            PathBuf::from("cli-tests/rnsd_client_sender")
        } else {
            base_dir.join("cli-tests/rnsd_client_sender")
        }
    } else if net_selector.eq_ignore_ascii_case("rpi") {
        if base_dir.as_os_str().is_empty() {
            PathBuf::from("cli-tests/rnsd_client_rust")
        } else {
            base_dir.join("cli-tests/rnsd_client_rust")
        }
    } else {
        return Err(format!(
            "Invalid --net value: {}. Use local|rpi",
            net_selector
        ));
    };

    let mode_arg = if let Some(mode) = arg_value(&args, "--mode").or_else(|| arg_value(&args, "--method")) {
        mode
    } else if has_flag(&args, "--direct") {
        "direct"
    } else if has_flag(&args, "--opportunistic") || has_flag(&args, "--opp") {
        "opportunistic"
    } else if has_flag(&args, "--auto") {
        "auto"
    } else {
        "opportunistic"
    };

    let size_mb = arg_value(&args, "--size-mb")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    let repeat_count = arg_value(&args, "--repeat")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);

    let attachment_path = arg_value(&args, "--attach").map(PathBuf::from);

    let message_text = arg_value(&args, "--message")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Hello from Rust".to_string());

    let mut content = if atty::isnt(atty::Stream::Stdin) {
        use std::io::Read;
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to read from stdin: {e}"))?;
        if buffer.is_empty() {
            message_text.as_bytes().to_vec()
        } else {
            buffer
        }
    } else if size_mb > 0.0 {
        let content_size = (size_mb * 1024.0 * 1024.0).ceil() as usize;
        vec![b'X'; content_size]
    } else {
        message_text.as_bytes().to_vec()
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

        let filename_str = path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("attachment.bin")
            .to_string();
        let attachment_entry = Value::Array(vec![
            Value::String(filename_str.into()),
            Value::Binary(attachment_data.clone()),
        ]);

        fields = Some(Value::Map(vec![(
            Value::from(FIELD_FILE_ATTACHMENTS as i64),
            Value::Array(vec![attachment_entry]),
        )]));

        if content.is_empty() {
            content = b"Binary attachment from Rust send CLI".to_vec();
        }

        eprintln!(
            "[config] Attachment: {} ({} bytes, repeat {})",
            path.display(),
            attachment_data.len(),
            repeat_count
        );
    }

    let target_override = arg_value_flexible(&args, "--to");
    let custom_dest = arg_value_flexible(&args, "--custom");
    let dest_selector = arg_value_flexible(&args, "--dest").unwrap_or_else(|| {
        "mc".to_string()
    });

    let key_value = DEBUG_KEY_1.to_string();
    let (dest_hash_hex, dest_source) = if let Some(value) = target_override {
        (value, "--to".to_string())
    } else {
        match dest_selector.to_ascii_lowercase().as_str() {
            "mc" => (DEBUG_MC_RECV_ADDR.to_string(), "dest:mc".to_string()),
            "sd" => (DEBUG_ADDR_1.to_string(), "dest:sd".to_string()),
            "test2" => (DEBUG_ADDR_2.to_string(), "dest:test2".to_string()),
            "test3" => (DEBUG_ADDR_3.to_string(), "dest:test3".to_string()),
            "custom" => {
                if let Some(custom) = custom_dest {
                    (custom, "dest:custom(--custom)".to_string())
                } else {
                    return Err("--dest custom requires --custom <hex> (or use --to <hex>)".to_string());
                }
            }
            other => {
                if !other.is_empty() && other.chars().all(|c| c.is_ascii_hexdigit()) && other.len() % 2 == 0 {
                    (other.to_string(), "dest:inline-hex".to_string())
                } else {
                    return Err(format!(
                        "Invalid --dest value: {}. Use mc|sd|test2|test3|custom",
                        other
                    ));
                }
            }
        }
    };

    let key_bytes = decode_key(&key_value)?;
    let dest_hash = decode_hex(&dest_hash_hex)?;
    eprintln!("[config] Destination source: {}", dest_source);
    eprintln!("[config] Destination hash: {}", to_hex(&dest_hash));
    eprintln!("[config] Config dir: {}", config_dir.display());
    eprintln!("[config] Env file (optional): {}", env_path.display());
    eprintln!("[config] Net profile: {}", net_selector);
    eprintln!("[config] Content size: {} bytes", content.len());
    eprintln!("[config] Delivery mode: {}", mode_arg);

    eprintln!("[step] init reticulum");
    let reticulum_init_start = Instant::now();
    let init_result = std::panic::catch_unwind(|| {
        Reticulum::init(Some(config_dir.clone()), None, None, None, false, None)
    });
    match init_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(format!("Reticulum init failed: {err}")),
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
    eprintln!(
        "[timing] reticulum_init: {:.3}s",
        reticulum_init_start.elapsed().as_secs_f64()
    );

    let cwd = env::current_dir().map_err(|e| format!("Failed to read current dir: {e}"))?;
    let storage_path = cwd.join("cli-tests/lxmf_storage/sender");

    eprintln!("[step] create router");
    let router_create_start = Instant::now();
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
    eprintln!(
        "[timing] router_create: {:.3}s",
        router_create_start.elapsed().as_secs_f64()
    );

    eprintln!("[step] load sender identity");
    let identity_register_start = Instant::now();
    let source_identity = Identity::from_bytes(&key_bytes)?;
    eprintln!("[step] register sender destination");
    let source = {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        router_guard.register_delivery_identity(source_identity, Some("Python Sender".to_string()), None)?
    };

    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        eprintln!("[step] announce sender destination");
        router_guard.announce(&source.hash, None);
    }
    eprintln!(
        "[timing] identity_register_announce: {:.3}s",
        identity_register_start.elapsed().as_secs_f64()
    );

    eprintln!("[step] resolve path");
    if !Transport::has_path(&dest_hash) {
        eprintln!("[step] request path");
        Transport::request_path(&dest_hash, None, None, None, None);
        let path_wait_start = Instant::now();
        let mut last_wait_log = Instant::now();
        let mut last_retry = Instant::now();
        let mut wait_checks: u64 = 0;
        let mut retry_count: u64 = 0;
        let path_retry_interval = Duration::from_secs(15);
        let path_timeout = Duration::from_secs(120);
        while !Transport::has_path(&dest_hash) {
            wait_checks += 1;
            if last_wait_log.elapsed() >= Duration::from_secs(2) {
                eprintln!(
                    "[path_wait] waiting_for_path={}s checks={} retries={} dest={}",
                    path_wait_start.elapsed().as_secs(),
                    wait_checks,
                    retry_count,
                    to_hex(&dest_hash)
                );
                last_wait_log = Instant::now();
            }
            if last_retry.elapsed() >= path_retry_interval {
                retry_count += 1;
                eprintln!(
                    "[path_wait] retrying request_path retry={} elapsed={}s dest={}",
                    retry_count,
                    path_wait_start.elapsed().as_secs(),
                    to_hex(&dest_hash)
                );
                Transport::request_path(&dest_hash, None, None, None, None);
                last_retry = Instant::now();
            }
            if path_wait_start.elapsed() >= path_timeout {
                eprintln!(
                    "[path_wait] TIMEOUT after {}s retries={} dest={}",
                    path_wait_start.elapsed().as_secs(),
                    retry_count,
                    to_hex(&dest_hash)
                );
                break;
            }
            if interrupted.load(Ordering::SeqCst) {
                eprintln!("[signal] SIGINT received, stopping during path resolution");
                eprintln!("[timing] total_elapsed: {:.3}s", run_start.elapsed().as_secs_f64());
                eprintln!("[time] finished: {}", unix_timestamp_string());
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "[path_wait] path_resolved_after={}s checks={} retries={} dest={}",
            path_wait_start.elapsed().as_secs(),
            wait_checks,
            retry_count,
            to_hex(&dest_hash)
        );
    }

    let has_path = Transport::has_path(&dest_hash);
    eprintln!("[step] has_path: {}", has_path);
    eprintln!("[step] recall destination identity");
    let destination_setup_start = Instant::now();
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
    eprintln!(
        "[timing] destination_setup: {:.3}s",
        destination_setup_start.elapsed().as_secs_f64()
    );

    if !has_path {
        return Err("No path available for send".to_string());
    }

    let has_attachment = attachment_path.is_some();

    let method = match mode_arg {
        "direct" => LXMessage::DIRECT,
        "opportunistic" => {
            if has_attachment {
                eprintln!("[method] opportunistic requested with attachment; using DIRECT");
                LXMessage::DIRECT
            } else if content.len() <= LXMessage::ENCRYPTED_PACKET_MAX_CONTENT {
                LXMessage::OPPORTUNISTIC
            } else {
                eprintln!("[method] opportunistic requested but payload is too large; using DIRECT");
                LXMessage::DIRECT
            }
        }
        "auto" => {
            if has_attachment {
                LXMessage::DIRECT
            } else if content.len() <= LXMessage::ENCRYPTED_PACKET_MAX_CONTENT {
                LXMessage::OPPORTUNISTIC
            } else {
                LXMessage::DIRECT
            }
        }
        other => return Err(format!("Invalid --mode/--method value: {other}. Use direct|opportunistic|auto")),
    };

    eprintln!(
        "[method] selected: {}",
        match method {
            LXMessage::DIRECT => "DIRECT",
            LXMessage::OPPORTUNISTIC => "OPPORTUNISTIC",
            _ => "UNKNOWN",
        }
    );

    let wait_seconds = PY_SENDER_POST_SEND_SECONDS;
    eprintln!("[config] Post-send wait: {}s", wait_seconds);

    eprintln!("[step] build message");
    let message_build_start = Instant::now();
    let message = LXMessage::new(
        Some(destination),
        Some(source),
        Some(content),
        Some(b"Python Test".to_vec()),
        fields,
        Some(method),
        None,
        None,
        None,
        true,
    )?;
    eprintln!(
        "[timing] message_build: {:.3}s",
        message_build_start.elapsed().as_secs_f64()
    );

    let handle = std::sync::Arc::new(std::sync::Mutex::new(message));
    let enqueue_start = Instant::now();
    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        eprintln!("[step] handle outbound");
        router_guard.handle_outbound(handle.clone());
    }
    eprintln!("[timing] enqueue_outbound: {:.3}s", enqueue_start.elapsed().as_secs_f64());

    {
        let locked = handle.lock().map_err(|_| "Message lock poisoned")?;
        eprintln!(
            "[message] representation: {}",
            match locked.representation {
                LXMessage::PACKET => "PACKET",
                LXMessage::RESOURCE => "RESOURCE",
                _ => "UNKNOWN",
            }
        );
    }

    let wait_loop_start = Instant::now();
    let mut next_state_log = Instant::now() + Duration::from_secs(2);
    for _ in 0..wait_seconds * 5 {
        if let Ok(locked) = handle.try_lock() {
            if Instant::now() >= next_state_log {
                eprintln!(
                    "[step] message state: {} ({}) progress {:.1}%",
                    locked.state,
                    state_name(locked.state),
                    locked.progress * 100.0
                );
                next_state_log = Instant::now() + Duration::from_secs(2);
            }
            if locked.state == LXMessage::DELIVERED || locked.state == LXMessage::FAILED {
                println!("Final message state: {} ({})", locked.state, state_name(locked.state));
                eprintln!(
                    "[timing] send_wait: {:.3}s",
                    wait_loop_start.elapsed().as_secs_f64()
                );
                eprintln!("[timing] total_elapsed: {:.3}s", run_start.elapsed().as_secs_f64());
                eprintln!("[time] finished: {}", unix_timestamp_string());
                return Ok(());
            }
        }
        if interrupted.load(Ordering::SeqCst) {
            eprintln!("[signal] SIGINT received, stopping during send wait");
            eprintln!(
                "[timing] send_wait: {:.3}s",
                wait_loop_start.elapsed().as_secs_f64()
            );
            eprintln!("[timing] total_elapsed: {:.3}s", run_start.elapsed().as_secs_f64());
            eprintln!("[time] finished: {}", unix_timestamp_string());
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }

    println!("Message send wait complete");
    eprintln!("[timing] send_wait: {:.3}s", wait_loop_start.elapsed().as_secs_f64());
    eprintln!("[timing] total_elapsed: {:.3}s", run_start.elapsed().as_secs_f64());
    eprintln!("[time] finished: {}", unix_timestamp_string());
    Ok(())
}
