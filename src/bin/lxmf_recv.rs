use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lxmf_rust::{LXMRouter, LXMessage};
use reticulum_rust::destination::PROVE_ALL;
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;

// Default receiver identity: KEY_2 / ADDR_2 from cli_constants.env
const DEFAULT_KEY: &str = "GVQDBB7XDWV3OFVM76ZY7QGBJVFMTJP5UKCDPD6M5UCCQBCEG7MVCLNQDPKG4HJ77GOAVZMKLSLWQDYYF33KEZFBXPQA6V4UUMUBYZY";

fn to_hex(bytes: &[u8]) -> String {
    reticulum_rust::hexrep(bytes, false)
}

fn unix_timestamp_string() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
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
        let flag = interrupted.clone();
        if let Err(err) = ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
        }) {
            eprintln!("[warn] Failed to install SIGINT handler: {}", err);
        }
    }

    let args: Vec<String> = env::args().collect();
    let base_dir = PathBuf::from(env::var("RETICULUM_WORKDIR").unwrap_or_default());

    // --config: override Reticulum config directory
    let config_dir = if let Some(path) = arg_value_flexible(&args, "--config") {
        PathBuf::from(path)
    } else if base_dir.as_os_str().is_empty() {
        PathBuf::from("cli-tests/rnsd_client_rust_recv")
    } else {
        base_dir.join("cli-tests/rnsd_client_rust_recv")
    };

    // --key: override receiver identity key (base32 or hex)
    let key_value = arg_value_flexible(&args, "--key")
        .unwrap_or_else(|| DEFAULT_KEY.to_string());

    // --name: display name announced on the network
    let display_name = arg_value_flexible(&args, "--name")
        .unwrap_or_else(|| "Rust Receiver".to_string());

    // --announce-interval: seconds between re-announces (default 30)
    let announce_interval: u64 = arg_value(&args, "--announce-interval")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    // --verbose: noisy per-field dump of incoming messages
    let verbose = has_flag(&args, "--verbose") || has_flag(&args, "-v");

    eprintln!("[config] Config dir: {}", config_dir.display());
    eprintln!("[config] Display name: {}", display_name);
    eprintln!("[config] Announce interval: {}s", announce_interval);
    eprintln!("[config] Verbose: {}", verbose);

    // ── Reticulum init ──────────────────────────────────────────────
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

    // ── LXMF router ────────────────────────────────────────────────
    let cwd = env::current_dir().map_err(|e| format!("Failed to read cwd: {e}"))?;
    let storage_path = cwd.join("cli-tests/lxmf_storage/rust_receiver");

    eprintln!("[step] create router");
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
        Some("rust-receiver".to_string()),
    )?;

    // ── Identity & destination ──────────────────────────────────────
    eprintln!("[step] load receiver identity");
    let key_bytes = lxmf_rust::decode_key(&key_value)?;
    let identity = Identity::from_bytes(&key_bytes)?;

    eprintln!("[step] register delivery identity");
    let mut delivery_dest = {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        router_guard.register_delivery_identity(
            identity,
            Some(display_name.clone()),
            None,
        )?
    };

    // Prove all packets (so senders get delivery confirmations)
    let _ = delivery_dest.set_proof_strategy(PROVE_ALL);
    let dest_hash = delivery_dest.hash.clone();
    eprintln!("[step] delivery destination: {}", to_hex(&dest_hash));

    // ── Delivery callback ──────────────────────────────────────────
    let verbose_flag = verbose;
    let msg_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let msg_count_cb = msg_count.clone();

    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        router_guard.register_delivery_callback(Arc::new(move |message: &LXMessage| {
            let n = msg_count_cb.fetch_add(1, Ordering::SeqCst) + 1;
            let ts = {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                format!("{}.{:03}", now.as_secs(), now.subsec_millis())
            };

            eprintln!("+--- LXMF Delivery #{} [{}] ---", n, ts);
            eprintln!("| Source hash            : {}", to_hex(&message.source_hash));
            eprintln!("| Destination hash       : {}", to_hex(&message.destination_hash));
            eprintln!(
                "| Title                  : {}",
                message.title_as_string().unwrap_or_else(|| "<binary>".to_string())
            );

            let content_str = message.content_as_string();
            let content_display = match &content_str {
                Some(s) if s.len() <= 200 => s.clone(),
                Some(s) => format!("{}... ({} bytes total)", &s[..200], s.len()),
                None => format!("<binary {} bytes>", message.content.len()),
            };
            eprintln!("| Content                : {}", content_display);

            // File attachments
            let attachments = message.get_file_attachments();
            if attachments.is_empty() {
                eprintln!("| Attachments            : none");
            } else {
                eprintln!("| Attachments            : {}", attachments.len());
                for (i, (filename, data)) in attachments.iter().enumerate() {
                    eprintln!("|   - #{} {} ({} bytes)", i + 1, filename, data.len());
                }
            }

            // Signature & stamp info
            eprintln!("| Signature valid        : {}", message.signature_validated);
            if message.stamp_checked {
                eprintln!("| Stamp valid            : {}", message.stamp_valid);
            }
            eprintln!("| Transport encrypted    : {}", message.transport_encrypted);
            if let Some(enc) = &message.transport_encryption {
                eprintln!("| Transport encryption   : {}", enc);
            }

            if verbose_flag {
                eprintln!("| State                  : {}", LXMessage::state_name(message.state));
                eprintln!("| Method                 : {}", LXMessage::method_name(message.method));
                eprintln!("| Representation         : {}", LXMessage::representation_name(message.representation));
                if let Some(hash) = &message.hash {
                    eprintln!("| Message hash           : {}", to_hex(hash));
                }
                if let Some(mid) = &message.message_id {
                    eprintln!("| Message ID             : {}", to_hex(mid));
                }
            }

            eprintln!("+---------------------------------------------------------------");
        }));
    }

    // ── Initial announce ────────────────────────────────────────────
    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        eprintln!("[step] announce receiver destination");
        router_guard.announce(&dest_hash, None);
    }
    eprintln!("[step] receiver ready on: {}", to_hex(&dest_hash));
    eprintln!(
        "[timing] startup: {:.3}s",
        run_start.elapsed().as_secs_f64()
    );

    // ── Main loop: announce periodically, wait for messages ─────
    let mut last_announce = Instant::now();
    loop {
        if interrupted.load(Ordering::SeqCst) {
            eprintln!("\n[signal] SIGINT received, shutting down");
            let count = msg_count.load(Ordering::SeqCst);
            eprintln!(
                "[summary] received {} message(s) in {:.1}s",
                count,
                run_start.elapsed().as_secs_f64()
            );
            eprintln!("[time] finished: {}", unix_timestamp_string());
            return Ok(());
        }

        if last_announce.elapsed() >= Duration::from_secs(announce_interval) {
            if let Ok(mut router_guard) = router.lock() {
                router_guard.announce(&dest_hash, None);
                eprintln!("[announce] re-announced (interval={}s)", announce_interval);
            }
            last_announce = Instant::now();
        }

        thread::sleep(Duration::from_millis(250));
    }
}
