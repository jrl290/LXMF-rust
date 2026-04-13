use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use lxmf_rust::{LXMRouter, LXMessage};
use lxmf_rust::cli_util::{to_hex, unix_timestamp_string, arg_value, arg_value_flexible, has_flag};
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

const DEBUG_KEY_1: &str = "KJKBJI4QZNTBOWDDUS6JIHIOMNCZ747L3G2A4453PLDYLHBSKDD5TV7IHYMEB7HXUX6Z74XEDVYYZQLNHTXMBGZP6BSRUOT6YGCC4BI";
const DEBUG_ADDR_1: &str = "99e5aebb4ac27f05695c98e8e22540ca";
const DEBUG_ADDR_2: &str = "4c0c6c7f420da5df5203554462cbb3bc";
const DEBUG_ADDR_3: &str = "29b00f4f93eb95c08f1c67eb31c5f9f6";
const DEBUG_MC_RECV_ADDR: &str = "13f4b14dd364a672e853a37fb534678c";
const DEFAULT_SEND_WAIT_SECONDS: u64 = 60;

fn main() -> Result<(), String> {
    let run_start = Instant::now();
    eprintln!("[time] started: {}", unix_timestamp_string());
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let interrupted_flag = interrupted.clone();
        if let Err(err) = ctrlc::set_handler(move || {
            interrupted_flag.store(true, Ordering::Relaxed);
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

    let prop_node_hex = arg_value_flexible(&args, "--prop-node");
    let dest_key_hex = arg_value_flexible(&args, "--dest-key");
    let prop_stamp_cost: Option<u32> = arg_value(&args, "--prop-stamp-cost")
        .and_then(|s| s.parse().ok());
    let mode_arg = if let Some(mode) = arg_value(&args, "--mode").or_else(|| arg_value(&args, "--method")) {
        mode
    } else if has_flag(&args, "--direct") {
        "direct"
    } else if has_flag(&args, "--opportunistic") || has_flag(&args, "--opp") {
        "opportunistic"
    } else if has_flag(&args, "--propagated") || prop_node_hex.is_some() {
        "propagated"
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

    let mut attachment_info: Option<(String, Vec<u8>)> = None;
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

        if content.is_empty() {
            content = b"Binary attachment from Rust send CLI".to_vec();
        }

        eprintln!(
            "[config] Attachment: {} ({} bytes, repeat {})",
            path.display(),
            attachment_data.len(),
            repeat_count
        );

        attachment_info = Some((filename_str, attachment_data));
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

    let key_bytes = lxmf_rust::decode_key(&key_value)?;
    let dest_hash = reticulum_rust::decode_hex(&dest_hash_hex)
        .ok_or_else(|| format!("Invalid hex destination hash: {dest_hash_hex}"))?;
    eprintln!("[config] Destination source: {}", dest_source);
    eprintln!("[config] Destination hash: {}", to_hex(&dest_hash));
    eprintln!("[config] Config dir: {}", config_dir.display());
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

    let cwd_storage = env::current_dir().map_err(|e| format!("Failed to read current dir: {e}"))?;
    let storage_path = if let Some(path) = arg_value_flexible(&args, "--storage") {
        PathBuf::from(path)
    } else if !base_dir.as_os_str().is_empty() {
        base_dir.join("cli-tests/lxmf_storage/sender")
    } else {
        cwd_storage.join("cli-tests/lxmf_storage/sender")
    };

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
        let dest = router_guard.register_delivery_identity(source_identity, Some("Python Sender".to_string()), None)?;
        eprintln!("[step] announce sender destination");
        let _ = router_guard.announce(&dest.hash, None);
        dest
    };
    eprintln!(
        "[timing] identity_register_announce: {:.3}s",
        identity_register_start.elapsed().as_secs_f64()
    );

    let destination_setup_start = Instant::now();
    let destination = if let Some(ref key_hex) = dest_key_hex {
        eprintln!("[step] loading destination identity from --dest-key (offline)");
        let key_bytes = reticulum_rust::decode_hex(key_hex)
            .ok_or_else(|| "Invalid hex --dest-key".to_string())?;
        let dest_identity = Identity::from_bytes(&key_bytes)?;
        let derived_hash = Destination::hash_from_name_and_identity(
            "lxmf.delivery",
            Some(&dest_identity),
        );
        eprintln!("[step] derived destination hash: {}", to_hex(&derived_hash));
        if derived_hash != dest_hash {
            eprintln!(
                "[warn] --dest-key hash {} does not match --to {}",
                to_hex(&derived_hash),
                to_hex(&dest_hash),
            );
        }
        Destination::new_outbound(
            Some(dest_identity),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["delivery".to_string()],
        )?
    } else {
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
                if interrupted.load(Ordering::Relaxed) {
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
        eprintln!("[step] resolve destination from hash");
        let dest = Destination::from_destination_hash(&dest_hash, "lxmf", &["delivery"])?;
        eprintln!("[step] destination hash: {}", to_hex(&dest.hash));
        if !has_path {
            return Err("No path available for send".to_string());
        }
        dest
    };
    eprintln!("[step] destination ready: {}", to_hex(&destination.hash));
    eprintln!(
        "[timing] destination_setup: {:.3}s",
        destination_setup_start.elapsed().as_secs_f64()
    );

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
        "propagated" => LXMessage::PROPAGATED,
        other => return Err(format!("Invalid --mode/--method value: {other}. Use direct|opportunistic|auto|propagated")),
    };

    eprintln!("[method] selected: {}", LXMessage::method_name(method));

    // For propagated sends, ensure we have the prop node's announce data (stamp cost).
    // The stamp-generation thread calls get_outbound_propagation_cost() which needs
    // Identity::recall_app_data for the prop node to be populated with valid PN announce data.
    if let Some(ref pn_hex) = prop_node_hex {
        use reticulum_rust::identity::Identity;
        use lxmf_rust::lxmf::pn_announce_data_is_valid;
        let pn_bytes = reticulum_rust::decode_hex(pn_hex)
            .ok_or_else(|| format!("Invalid --prop-node hex: {pn_hex}"))?;
        let has_valid_data = || Identity::recall_app_data(&pn_bytes)
            .map(|d| pn_announce_data_is_valid(&d))
            .unwrap_or(false);
        if !has_valid_data() {
            eprintln!("[step] prop node valid announce not cached, requesting path and waiting...");
            Transport::request_path(&pn_bytes, None, None, None, None);
            let pn_wait_start = Instant::now();
            let pn_wait_timeout = Duration::from_secs(30);
            while !has_valid_data() {
                if pn_wait_start.elapsed() >= pn_wait_timeout {
                    eprintln!("[warn] prop node valid announce not received after 30s; stamp gen may fail");
                    break;
                }
                if interrupted.load(Ordering::Relaxed) {
                    eprintln!("[signal] SIGINT received while waiting for prop node announce");
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(500));
            }
            if has_valid_data() {
                eprintln!("[step] prop node valid announce received ({:.1}s)", pn_wait_start.elapsed().as_secs_f64());
            }
        } else {
            eprintln!("[step] prop node valid announce already cached");
        }
    }

    let wait_seconds = arg_value(&args, "--wait")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEND_WAIT_SECONDS);
    eprintln!("[config] Post-send wait: {}s", wait_seconds);

    eprintln!("[step] build message");
    let message_build_start = Instant::now();
    let mut message = LXMessage::new(
        Some(destination),
        Some(source),
        Some(content),
        Some(b"Python Test".to_vec()),
        None,
        Some(method),
        None,
        None,
        None,
        true,
    )?;
    if let Some((filename, data)) = attachment_info {
        message.add_file_attachment(&filename, data);
    }
    eprintln!(
        "[timing] message_build: {:.3}s",
        message_build_start.elapsed().as_secs_f64()
    );

    let handle = std::sync::Arc::new(std::sync::Mutex::new(message));
    let enqueue_start = Instant::now();
    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        if let Some(ref pn_hex) = prop_node_hex {
            let pn_bytes = reticulum_rust::decode_hex(pn_hex)
                .ok_or_else(|| format!("Invalid --prop-node hex: {pn_hex}"))?;
            eprintln!("[step] setting outbound propagation node: {}", pn_hex);
            router_guard.set_outbound_propagation_node(pn_bytes)
                .map_err(|e| format!("set_outbound_propagation_node: {e}"))?;
        }
        eprintln!("[step] handle outbound");
        router_guard.handle_outbound(handle.clone());
    }
    eprintln!("[timing] enqueue_outbound: {:.3}s", enqueue_start.elapsed().as_secs_f64());

    {
        let locked = handle.lock().map_err(|_| "Message lock poisoned")?;
        eprintln!("[message] representation: {}", LXMessage::representation_name(locked.representation));
    }

    let wait_loop_start = Instant::now();
    let mut next_state_log = Instant::now() + Duration::from_secs(2);
    for _ in 0..wait_seconds * 5 {
        if let Ok(locked) = handle.try_lock() {
            if Instant::now() >= next_state_log {
                eprintln!(
                    "[step] message state: {} ({}) progress {:.1}%",
                    locked.state,
                    LXMessage::state_name(locked.state),
                    locked.progress * 100.0
                );
                next_state_log = Instant::now() + Duration::from_secs(2);
            }
            if locked.state == LXMessage::DELIVERED || locked.state == LXMessage::SENT {
                println!("Final message state: {} ({})", locked.state, LXMessage::state_name(locked.state));
                eprintln!(
                    "[timing] send_wait: {:.3}s",
                    wait_loop_start.elapsed().as_secs_f64()
                );
                eprintln!("[timing] total_elapsed: {:.3}s", run_start.elapsed().as_secs_f64());
                eprintln!("[time] finished: {}", unix_timestamp_string());
                return Ok(());
            }
            if locked.state == LXMessage::FAILED {
                println!("Final message state: {} ({})", locked.state, LXMessage::state_name(locked.state));
                eprintln!(
                    "[timing] send_wait: {:.3}s",
                    wait_loop_start.elapsed().as_secs_f64()
                );
                eprintln!("[timing] total_elapsed: {:.3}s", run_start.elapsed().as_secs_f64());
                eprintln!("[time] finished: {}", unix_timestamp_string());
                std::process::exit(1);
            }
        }
        if interrupted.load(Ordering::Relaxed) {
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

    eprintln!("[error] send wait timed out after {}s", wait_seconds);
    if let Ok(locked) = handle.try_lock() {
        eprintln!(
            "[error] final state: {} ({}) progress {:.1}%",
            locked.state,
            LXMessage::state_name(locked.state),
            locked.progress * 100.0
        );
    }
    eprintln!("[timing] send_wait: {:.3}s", wait_loop_start.elapsed().as_secs_f64());
    eprintln!("[timing] total_elapsed: {:.3}s", run_start.elapsed().as_secs_f64());
    eprintln!("[time] finished: {}", unix_timestamp_string());
    std::process::exit(2)
}
