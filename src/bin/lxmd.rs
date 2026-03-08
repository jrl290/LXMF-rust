//! lxmd — LXMF Propagation Node Daemon (Rust)
//!
//! A lightweight store-and-forward propagation node for the LXMF messaging
//! protocol over Reticulum.  This is the Rust equivalent of the Python
//! `lxmd -p` utility, built on the `lxmf_rust` and `reticulum_rust` crates.
//!
//! Usage:
//!     lxmd [OPTIONS]
//!
//! Options:
//!     --config <DIR>          lxmd config/storage directory (default: ~/.lxmd)
//!     --rnsconfig <DIR>       Reticulum config directory (default: ~/.reticulum)
//!     --identity <FILE>       Path to identity file (default: <config>/identity)
//!     --name <NAME>           Propagation node display name
//!     --announce-interval <M> Node announce interval in minutes (default: 360)
//!     --announce-at-start     Announce immediately on startup
//!     --autopeer              Enable automatic peering (default)
//!     --no-autopeer           Disable automatic peering
//!     --autopeer-maxdepth <N> Maximum peering depth in hops (default: 4)
//!     --storage-limit <MB>    Message storage limit in megabytes (default: 500)
//!     --static-peer <HASH>    Add a static peer (can be repeated)
//!     --from-static-only      Only accept propagation from static peers
//!     --stamp-cost <N>        Propagation stamp cost target (default: 16)
//!     --stamp-flexibility <N> Stamp cost flexibility (default: 3)
//!     --peering-cost <N>      Peering cost (default: 18)
//!     --max-peering-cost <N>  Maximum remote peering cost (default: 26)
//!     --max-peers <N>         Maximum number of auto-peers (default: 20)
//!     -v, --verbose           Increase log verbosity
//!     -q, --quiet             Decrease log verbosity
//!     -h, --help              Show this help

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use lxmf_rust::cli_util::{arg_value, arg_value_flexible, has_flag, to_hex};
use lxmf_rust::LXMRouter;
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    eprintln!(
        r#"lxmd v{VERSION} — LXMF Propagation Node Daemon (Rust)

Usage: lxmd [OPTIONS]

Options:
  --config <DIR>            lxmd config/storage directory (default: ~/.lxmd)
  --rnsconfig <DIR>         Reticulum config directory
  --identity <FILE>         Path to identity file (default: <config>/identity)
  --name <NAME>             Node display name
  --announce-interval <MIN> Node announce interval in minutes (default: 360)
  --announce-at-start       Announce on startup (default: yes)
  --no-announce-at-start    Don't announce on startup
  --autopeer                Enable auto-peering (default)
  --no-autopeer             Disable auto-peering
  --autopeer-maxdepth <N>   Max peering depth in hops (default: 4)
  --storage-limit <MB>      Message storage limit in MB (default: 500)
  --static-peer <HASH>      Add a static peer (repeatable)
  --from-static-only        Only accept from static peers
  --stamp-cost <N>          Stamp cost target (default: 16)
  --stamp-flexibility <N>   Stamp cost flexibility (default: 3)
  --peering-cost <N>        Peering cost (default: 18)
  --max-peering-cost <N>    Max remote peering cost (default: 26)
  --max-peers <N>           Max auto-peers (default: 20)
  -v, --verbose             Increase log verbosity
  -q, --quiet               Decrease log verbosity
  -h, --help                Show this help"#
    );
}

fn decode_hex_hash(hex: &str) -> Option<Vec<u8>> {
    reticulum_rust::decode_hex(hex.trim())
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if has_flag(&args, "-h") || has_flag(&args, "--help") {
        print_help();
        return Ok(());
    }

    // ── Parse arguments ─────────────────────────────────────────────
    let home = env::var("HOME").unwrap_or_else(|_| "/root".to_string());

    let config_dir = arg_value_flexible(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{home}/.lxmd")));

    let rns_config_dir = arg_value_flexible(&args, "--rnsconfig").map(PathBuf::from);

    let identity_path = arg_value_flexible(&args, "--identity")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir.join("identity"));

    let node_name = arg_value_flexible(&args, "--name")
        .or_else(|| env::var("LXMD_NODE_NAME").ok());

    let announce_interval_minutes: u64 = arg_value(&args, "--announce-interval")
        .and_then(|s| s.parse().ok())
        .or_else(|| env::var("LXMD_ANNOUNCE_INTERVAL").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(360);

    let announce_at_start = if has_flag(&args, "--no-announce-at-start") {
        false
    } else {
        // Default true, or --announce-at-start explicit
        true
    };

    let autopeer = if has_flag(&args, "--no-autopeer") {
        false
    } else {
        true
    };

    let autopeer_maxdepth: u8 = arg_value(&args, "--autopeer-maxdepth")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);

    let storage_limit_mb: u64 = arg_value(&args, "--storage-limit")
        .and_then(|s| s.parse().ok())
        .or_else(|| env::var("LXMD_STORAGE_LIMIT_MB").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(500);

    let stamp_cost: u32 = arg_value(&args, "--stamp-cost")
        .and_then(|s| s.parse().ok())
        .unwrap_or(LXMRouter::PROPAGATION_COST);

    let stamp_flexibility: u32 = arg_value(&args, "--stamp-flexibility")
        .and_then(|s| s.parse().ok())
        .unwrap_or(LXMRouter::PROPAGATION_COST_FLEX);

    let peering_cost: u32 = arg_value(&args, "--peering-cost")
        .and_then(|s| s.parse().ok())
        .unwrap_or(LXMRouter::PEERING_COST);

    let max_peering_cost: u32 = arg_value(&args, "--max-peering-cost")
        .and_then(|s| s.parse().ok())
        .unwrap_or(LXMRouter::MAX_PEERING_COST);

    let max_peers: usize = arg_value(&args, "--max-peers")
        .and_then(|s| s.parse().ok())
        .unwrap_or(LXMRouter::MAX_PEERS);

    let from_static_only = has_flag(&args, "--from-static-only");

    // Collect all --static-peer <HASH> arguments
    let mut static_peers: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--static-peer" {
            if let Some(hex) = args.get(i + 1) {
                if let Some(hash) = decode_hex_hash(hex) {
                    static_peers.push(hash);
                } else {
                    eprintln!("[warn] Invalid static peer hash: {}", hex);
                }
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    // Also accept from env: LXMD_STATIC_PEERS=hash1,hash2,...
    if static_peers.is_empty() {
        if let Ok(peers_env) = env::var("LXMD_STATIC_PEERS") {
            for hex in peers_env.split(',') {
                let hex = hex.trim();
                if !hex.is_empty() {
                    if let Some(hash) = decode_hex_hash(hex) {
                        static_peers.push(hash);
                    }
                }
            }
        }
    }

    // ── Banner ──────────────────────────────────────────────────────
    eprintln!("┌──────────────────────────────────────────────────────┐");
    eprintln!("│  lxmd v{:<46}│", VERSION);
    eprintln!("│  LXMF Propagation Node (Rust)                       │");
    eprintln!("├──────────────────────────────────────────────────────┤");
    eprintln!(
        "│  Config dir     : {:<34}│",
        config_dir.display()
    );
    if let Some(ref rns) = rns_config_dir {
        eprintln!("│  RNS config     : {:<34}│", rns.display());
    }
    eprintln!(
        "│  Node name      : {:<34}│",
        node_name.as_deref().unwrap_or("(anonymous)")
    );
    eprintln!(
        "│  Announce int.  : {:<3} minutes{:<24}│",
        announce_interval_minutes, ""
    );
    eprintln!(
        "│  Storage limit  : {:<4} MB{:<27}│",
        storage_limit_mb, ""
    );
    eprintln!(
        "│  Auto-peer      : {:<34}│",
        if autopeer { "yes" } else { "no" }
    );
    eprintln!(
        "│  Static peers   : {:<34}│",
        static_peers.len()
    );
    eprintln!("└──────────────────────────────────────────────────────┘");

    // ── Ensure directories exist ────────────────────────────────────
    // On Synology NAS (and other Docker hosts with userns-remap), the
    // container's "root" is mapped to an unprivileged host uid that
    // cannot create directories inside bind mounts.  If create_dir_all
    // fails but the directory already exists, carry on.
    if let Err(e) = fs::create_dir_all(&config_dir) {
        if !config_dir.is_dir() {
            return Err(format!(
                "Cannot create config dir {}: {e}\n\
                 Hint: when running in Docker with bind mounts, pre-create the \
                 host directory and ensure it is writable (chmod 777).",
                config_dir.display()
            ));
        }
        eprintln!(
            "[warn] create_dir_all({}) failed ({e}), but directory exists — continuing",
            config_dir.display()
        );
    }

    let storage_dir = config_dir.join("storage");
    if let Err(e) = fs::create_dir_all(&storage_dir) {
        if !storage_dir.is_dir() {
            return Err(format!(
                "Cannot create storage dir {}: {e}\n\
                 Hint: pre-create this directory on the host and chmod 777.",
                storage_dir.display()
            ));
        }
        eprintln!(
            "[warn] create_dir_all({}) failed ({e}), but directory exists — continuing",
            storage_dir.display()
        );
    }

    // ── Ctrl-C handler ──────────────────────────────────────────────
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let flag = interrupted.clone();
        if let Err(err) = ctrlc::set_handler(move || {
            flag.store(true, Ordering::Relaxed);
        }) {
            eprintln!("[warn] Failed to install SIGINT handler: {}", err);
        }
    }

    // ── Reticulum init ──────────────────────────────────────────────
    eprintln!("[lxmd] Initialising Reticulum...");
    let rns_init = std::panic::catch_unwind(|| {
        Reticulum::init(
            rns_config_dir.clone(),
            None,
            None,
            None,
            false,
            None,
        )
    });
    match rns_init {
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
    eprintln!("[lxmd] Reticulum ready");

    // ── Identity ────────────────────────────────────────────────────
    let identity = if identity_path.exists() {
        eprintln!(
            "[lxmd] Loading identity from {}",
            identity_path.display()
        );
        Identity::from_file(&identity_path)?
    } else {
        eprintln!("[lxmd] Creating new identity...");
        let id = Identity::new(true);
        id.to_file(&identity_path)?;
        eprintln!(
            "[lxmd] Saved new identity to {}",
            identity_path.display()
        );
        id
    };

    let id_hash = identity.hash.clone().unwrap_or_default();
    eprintln!("[lxmd] Identity hash: {}", to_hex(&id_hash));

    // ── LXMF Router ─────────────────────────────────────────────────
    eprintln!("[lxmd] Creating LXMF Router...");
    let router = LXMRouter::new(
        Some(identity.clone()),
        storage_dir.to_string_lossy().to_string(),
        Some(autopeer),
        Some(autopeer_maxdepth),
        None, // propagation_limit (use default)
        None, // delivery_limit
        None, // sync_limit
        false, // enforce_ratchets
        false, // enforce_stamps
        static_peers,
        Some(max_peers),
        from_static_only,
        LXMRouter::PR_ALL_MESSAGES as u8,
        stamp_cost,
        stamp_flexibility,
        peering_cost,
        max_peering_cost,
        node_name.clone(),
    )?;

    // ── Register delivery identity (for direct messages) ────────────
    {
        let mut guard = router.lock().map_err(|_| "Router lock poisoned")?;
        let display = node_name
            .as_deref()
            .unwrap_or("LXMF Propagation Node");
        let _dest = guard.register_delivery_identity(
            identity.clone(),
            Some(display.to_string()),
            None,
        )?;
    }

    // ── Set message storage limit ───────────────────────────────────
    {
        let mut guard = router.lock().map_err(|_| "Router lock poisoned")?;
        guard.set_message_storage_limit(None, Some(storage_limit_mb), None)?;
    }

    // ── Enable propagation ──────────────────────────────────────────
    eprintln!("[lxmd] Enabling propagation node...");
    {
        let mut guard = router.lock().map_err(|_| "Router lock poisoned")?;
        guard.enable_propagation()?;
        let prop_hash = guard.propagation_destination.hash.clone();
        eprintln!(
            "[lxmd] Propagation node active: {}",
            to_hex(&prop_hash)
        );
    }

    // ── Initial announce ────────────────────────────────────────────
    if announce_at_start {
        eprintln!("[lxmd] Announcing propagation node...");
        // Small delay to let interfaces settle
        thread::sleep(Duration::from_secs(3));
        let guard = router.lock().map_err(|_| "Router lock poisoned")?;
        guard.announce_propagation_node();
    }

    let announce_interval = Duration::from_secs(announce_interval_minutes * 60);
    let mut last_announce = Instant::now();

    eprintln!("[lxmd] Node running. Press Ctrl-C to stop.");

    // ── Main loop ───────────────────────────────────────────────────
    let startup = Instant::now();
    loop {
        if interrupted.load(Ordering::Relaxed) {
            eprintln!("\n[lxmd] Shutting down...");
            eprintln!(
                "[lxmd] Uptime: {:.1} hours",
                startup.elapsed().as_secs_f64() / 3600.0
            );
            return Ok(());
        }

        // Periodic re-announce
        if last_announce.elapsed() >= announce_interval {
            if let Ok(guard) = router.lock() {
                guard.announce_propagation_node();
                eprintln!(
                    "[lxmd] Re-announced (interval={}m)",
                    announce_interval_minutes
                );
            }
            last_announce = Instant::now();
        }

        thread::sleep(Duration::from_millis(500));
    }
}
