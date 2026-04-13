//! FFI support module for LXMF.
//!
//! Builds on the handle registry in `reticulum_rust::ffi` to expose
//! LXMRouter and LXMessage operations through opaque handles.

use std::sync::{Arc, Mutex};

use reticulum_rust::ffi::{
    destroy_handle, get_handle, store_handle,
};
use reticulum_rust::identity::Identity;

use crate::lx_message::LXMessage;
use crate::lxm_router::LXMRouter;

// ---------------------------------------------------------------------------
// Snapshot of a received message (safe to send across FFI)
// ---------------------------------------------------------------------------

/// A plain-data snapshot of an inbound `LXMessage`, suitable for marshalling
/// across the FFI boundary without requiring a handle or mutex.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub hash: Vec<u8>,
    pub source_hash: Vec<u8>,
    pub destination_hash: Vec<u8>,
    pub title: String,
    pub content: String,
    pub timestamp: f64,
    pub signature_validated: bool,
    pub attachments: Vec<(String, Vec<u8>)>,
    pub rssi: Option<f64>,
    pub snr: Option<f64>,
    pub q: Option<f64>,

    /// The raw msgpack-encoded LXMF fields map.
    /// Consumers deserialize and interpret application-level fields themselves.
    pub fields_raw: Vec<u8>,
}

impl ReceivedMessage {
    /// Build a snapshot from a borrowed `LXMessage`.
    pub fn from_lxmessage(msg: &LXMessage) -> Self {
        let attachments = msg.get_file_attachments();

        // Serialize the fields map to msgpack bytes for passthrough.
        let fields_raw = {
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, msg.get_fields())
                .unwrap_or_default();
            buf
        };

        ReceivedMessage {
            hash: msg.hash.clone().unwrap_or_default(),
            source_hash: msg.source_hash.clone(),
            destination_hash: msg.destination_hash.clone(),
            title: msg.title_as_string().unwrap_or_default(),
            content: msg.content_as_string().unwrap_or_default(),
            timestamp: msg.timestamp.unwrap_or(0.0),
            signature_validated: msg.signature_validated,
            attachments,
            rssi: msg.rssi,
            snr: msg.snr,
            q: msg.q,
            fields_raw,
        }
    }
}

// ---------------------------------------------------------------------------
// LXMRouter
// ---------------------------------------------------------------------------

/// Create an `LXMRouter` with sensible defaults for a mobile chat client.
///
/// `identity_handle` – handle to a previously created `Identity`.
/// `storage_path`    – base directory for LXMF state (e.g. app internal storage).
///
/// Returns a handle to the `Arc<Mutex<LXMRouter>>`.
pub fn router_create(
    identity_handle: u64,
    storage_path: &str,
) -> Result<u64, String> {
    let id: Identity = get_handle(identity_handle)
        .ok_or_else(|| "invalid identity handle".to_string())?;

    let router = LXMRouter::new(
        Some(id),
        storage_path.to_string(),
        None,            // autopeer
        None,            // autopeer_maxdepth
        None,            // propagation_limit
        Some(1_000_000.0), // delivery_limit — no practical cap on mobile
        None,            // sync_limit
        false,           // enforce_ratchets
        false,           // enforce_stamps
        Vec::new(),      // static_peers
        None,            // max_peers
        false,           // from_static_only
        0,               // sync_strategy
        0,               // propagation_cost
        0,               // propagation_cost_flexibility
        0,               // peering_cost
        0,               // max_peering_cost
        None,            // name
    )?;

    Ok(store_handle(router))
}

/// Register an identity for receiving messages.
///
/// Returns a handle to the `Destination` that was created (the delivery
/// destination hash, useful for announcing).
pub fn router_register_delivery(
    router_handle: u64,
    identity_handle: u64,
    display_name: Option<&str>,
    stamp_cost: Option<u32>,
) -> Result<u64, String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;
    let id: Identity = get_handle(identity_handle)
        .ok_or_else(|| "invalid identity handle".to_string())?;

    let dest = router
        .lock()
        .map_err(|e| e.to_string())?
        .register_delivery_identity(id, display_name.map(|s| s.to_string()), stamp_cost)?;

    Ok(store_handle(dest))
}

/// Register a callback that fires when an inbound message is fully received.
///
/// The callback receives a `ReceivedMessage` snapshot.  The caller keeps
/// ownership of the callback `Arc` (drop it to unregister).
pub fn router_set_delivery_callback(
    router_handle: u64,
    callback: Arc<dyn Fn(ReceivedMessage) + Send + Sync>,
) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let cb = callback.clone();
    router
        .lock()
        .map_err(|e| e.to_string())?
        .register_delivery_callback(Arc::new(move |msg: &LXMessage| {
            let snapshot = ReceivedMessage::from_lxmessage(msg);
            cb(snapshot);
        }));

    Ok(())
}

/// Register a callback that fires when propagation sync completes.
///
/// The callback receives the number of messages that were synced (0 means
/// the propagation node had nothing new).
pub fn router_set_sync_complete_callback(
    router_handle: u64,
    callback: Arc<dyn Fn(u32) + Send + Sync>,
) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .register_sync_complete_callback(callback);

    Ok(())
}

/// Register a callback that fires when a delivery announce is received.
///
/// The callback receives the 16-byte destination hash and an optional
/// display name string extracted from the announce `app_data`.
pub fn router_set_announce_callback(
    router_handle: u64,
    callback: Arc<dyn Fn(&[u8], Option<String>) + Send + Sync>,
) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .register_announce_callback(callback);

    Ok(())
}

/// Announce a delivery destination on the network.
pub fn router_announce(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let ok = router
        .lock()
        .map_err(|e| e.to_string())?
        .announce(dest_hash, None);
    if ok { Ok(()) } else { Err("announce failed or destination not registered".to_string()) }
}

/// Add a destination hash to the announce watch list.
/// Only announces from watched destinations are processed.
pub fn router_watch_destination(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .watch_destination(dest_hash);
    Ok(())
}

/// Remove a destination hash from the announce watch list.
pub fn router_unwatch_destination(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .unwatch_destination(dest_hash);
    Ok(())
}

/// Trigger a processing pass on outbound messages (retries, link mgmt, etc).
pub fn router_process_outbound(router_handle: u64) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router.lock().map_err(|e| e.to_string())?.process_outbound();
    Ok(())
}

/// Destroy a router handle.
pub fn router_destroy(router_handle: u64) -> Result<(), String> {
    if destroy_handle(router_handle) {
        Ok(())
    } else {
        Err("invalid router handle".to_string())
    }
}

// ---------------------------------------------------------------------------
// LXMessage (outbound)
// ---------------------------------------------------------------------------

/// Create a new outbound message.
///
/// Returns a handle to `Arc<Mutex<LXMessage>>`.
///
/// `method` values: 0 = opportunistic, 1 = direct, 2 = propagated.
///
/// `source_identity_handle` – handle to the sender's Identity (required for signing).
pub fn message_create(
    dest_hash: &[u8],
    source_hash: &[u8],
    content: &str,
    title: &str,
    method: u8,
    source_identity_handle: u64,
) -> Result<u64, String> {
    use reticulum_rust::destination::{Destination, DestinationType};

    // Kotlin now sends the raw LXMessage constant values directly
    // (OPPORTUNISTIC=0x01, DIRECT=0x02, PROPAGATED=0x03)
    let desired = method;

    // Build source Destination with the identity (needed for signing during pack)
    reticulum_rust::log(&format!(
        "message_create: looking up identity handle={}, handle_count={}",
        source_identity_handle,
        reticulum_rust::ffi::handle_count(),
    ), reticulum_rust::LOG_NOTICE, false, false);
    let source_identity: Identity = get_handle(source_identity_handle)
        .ok_or_else(|| {
            let keys = reticulum_rust::ffi::handle_keys();
            format!(
                "invalid source identity handle {} (existing handles: {:?})",
                source_identity_handle, keys,
            )
        })?;
    let source_dest = Destination::new_inbound(
        Some(source_identity),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )?;

    let msg = LXMessage::new(
        None,                                       // destination (resolved by router)
        Some(source_dest),                          // source (with identity for signing)
        Some(content.as_bytes().to_vec()),           // content
        Some(title.as_bytes().to_vec()),             // title
        None,                                       // fields
        Some(desired),                              // desired_method
        Some(dest_hash.to_vec()),                   // destination_hash
        Some(source_hash.to_vec()),                 // source_hash
        None,                                       // stamp_cost
        false,                                      // include_ticket
    )?;

    Ok(store_handle(Arc::new(Mutex::new(msg))))
}

/// Add a file attachment to an outbound message.
pub fn message_add_attachment(
    handle: u64,
    filename: &str,
    data: &[u8],
) -> Result<(), String> {
    let msg: Arc<Mutex<LXMessage>> =
        get_handle(handle).ok_or_else(|| "invalid message handle".to_string())?;
    msg.lock()
        .map_err(|e| e.to_string())?
        .add_file_attachment(filename, data.to_vec());
    Ok(())
}

/// Add a string-valued field to an outbound message.
///
/// `key` is an LXMF field ID (e.g. 0x08 for FIELD_THREAD).
/// `value` is the UTF-8 string to store.
pub fn message_add_field_string(
    handle: u64,
    key: u8,
    value: &str,
) -> Result<(), String> {
    let msg: Arc<Mutex<LXMessage>> =
        get_handle(handle).ok_or_else(|| "invalid message handle".to_string())?;
    msg.lock()
        .map_err(|e| e.to_string())?
        .set_field(key, rmpv::Value::String(value.into()));
    Ok(())
}

/// Add a boolean-valued field to an outbound message.
pub fn message_add_field_bool(
    handle: u64,
    key: u8,
    value: bool,
) -> Result<(), String> {
    let msg: Arc<Mutex<LXMessage>> =
        get_handle(handle).ok_or_else(|| "invalid message handle".to_string())?;
    msg.lock()
        .map_err(|e| e.to_string())?
        .set_field(key, rmpv::Value::Boolean(value));
    Ok(())
}

/// Submit a message to the router for sending.
pub fn message_send(router_handle: u64, msg_handle: u64) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;
    let msg: Arc<Mutex<LXMessage>> =
        get_handle(msg_handle).ok_or_else(|| "invalid message handle".to_string())?;

    router.lock().map_err(|e| e.to_string())?.handle_outbound(msg);
    Ok(())
}

/// Query the current state of a message.
///
/// Returns the state constant (e.g. `LXMessage::DELIVERED`).
pub fn message_get_state(handle: u64) -> Result<u8, String> {
    let msg: Arc<Mutex<LXMessage>> =
        get_handle(handle).ok_or_else(|| "invalid message handle".to_string())?;
    let guard = msg.lock().map_err(|e| e.to_string())?;
    Ok(guard.state)
}

/// Query the send progress (0.0 – 1.0).
pub fn message_get_progress(handle: u64) -> Result<f32, String> {
    let msg: Arc<Mutex<LXMessage>> =
        get_handle(handle).ok_or_else(|| "invalid message handle".to_string())?;
    let guard = msg.lock().map_err(|e| e.to_string())?;
    Ok(guard.progress as f32)
}

/// Get the message hash (after packing / sending).
pub fn message_get_hash(handle: u64) -> Result<Vec<u8>, String> {
    let msg: Arc<Mutex<LXMessage>> =
        get_handle(handle).ok_or_else(|| "invalid message handle".to_string())?;
    let guard = msg.lock().map_err(|e| e.to_string())?;
    guard.hash
        .clone()
        .ok_or_else(|| "message has no hash yet".to_string())
}

/// Destroy a message handle.
pub fn message_destroy(handle: u64) -> Result<(), String> {
    if destroy_handle(handle) {
        Ok(())
    } else {
        Err("invalid message handle".to_string())
    }
}

// ---------------------------------------------------------------------------
// Propagation node management
// ---------------------------------------------------------------------------

/// Set the outbound propagation node by destination hash (16 bytes).
pub fn router_set_propagation_node(
    router_handle: u64,
    dest_hash: &[u8],
) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let mut guard = router.lock().map_err(|e| e.to_string())?;
    guard.set_outbound_propagation_node(dest_hash.to_vec())
}

/// Request messages from the configured propagation node.
///
/// `identity_handle` – identity to use for authentication with the prop node.
pub fn router_request_messages(
    router_handle: u64,
    identity_handle: u64,
) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;
    let id: Identity = get_handle(identity_handle)
        .ok_or_else(|| "invalid identity handle".to_string())?;

    let mut guard = router.lock().map_err(|e| e.to_string())?;
    guard.request_messages_from_propagation_node(id, None);
    Ok(())
}

/// Get the current propagation transfer state.
///
/// Returns one of the `PR_*` constants (e.g. PR_IDLE=0x00, PR_COMPLETE=0x07).
pub fn router_get_propagation_state(router_handle: u64) -> Result<u8, String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let guard = router.lock().map_err(|e| e.to_string())?;
    Ok(guard.propagation_transfer_state)
}

/// Get the current propagation transfer progress (0.0 – 1.0).
pub fn router_get_propagation_progress(router_handle: u64) -> Result<f64, String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let guard = router.lock().map_err(|e| e.to_string())?;
    Ok(guard.propagation_transfer_progress)
}

/// Cancel any in-progress propagation node requests.
pub fn router_cancel_propagation(router_handle: u64) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let mut guard = router.lock().map_err(|e| e.to_string())?;
    guard.cancel_propagation_node_requests();
    Ok(())
}

/// Mark a peer as "active" so the router maintains a proactive direct link.
pub fn router_set_active_peer(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .set_active_peer(dest_hash.to_vec());
    Ok(())
}

/// Stop maintaining a proactive link for a peer.
pub fn router_clear_active_peer(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .clear_active_peer(dest_hash);
    Ok(())
}

/// Return the direct-link status for a peer: 0=none, 1=pending, 2=active.
pub fn router_peer_link_status(router_handle: u64, dest_hash: &[u8]) -> Result<u8, String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let guard = router.lock().map_err(|e| e.to_string())?;
    let status = guard.peer_link_status(dest_hash);
    Ok(status)
}
