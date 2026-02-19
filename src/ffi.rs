//! FFI support module for LXMF.
//!
//! Builds on the handle registry in `reticulum_rust::ffi` to expose
//! LXMRouter and LXMessage operations through opaque handles.

use std::sync::{Arc, Mutex};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::ffi::{
    destroy_handle, get_handle, set_error, store_handle,
};
use reticulum_rust::identity::Identity;

use crate::lx_message::LXMessage;
use crate::lxm_router::LXMRouter;
use crate::lxmf::APP_NAME;

// ---------------------------------------------------------------------------
// Group-chat field IDs (application-level, carried in LXMF message fields)
// ---------------------------------------------------------------------------

pub const FIELD_GROUP_ID: u64       = 0xA0;
pub const FIELD_GROUP_MEMBERS: u64  = 0xA1;
pub const FIELD_GROUP_NAME: u64     = 0xA2;
pub const FIELD_GROUP_SECRET: u64   = 0xA3;
pub const FIELD_GROUP_SENDER: u64   = 0xA4;
pub const FIELD_GROUP_LOW_BW: u64   = 0xA5;
pub const FIELD_GROUP_RELAY_FOR: u64 = 0xA6;
pub const FIELD_GROUP_DELIVERED_TO: u64 = 0xA7;

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
}

impl ReceivedMessage {
    /// Build a snapshot from a borrowed `LXMessage`.
    pub fn from_lxmessage(msg: &LXMessage) -> Self {
        let attachments = msg.get_file_attachments();

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
        None,            // delivery_limit
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

/// Announce a delivery destination on the network.
pub fn router_announce(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .announce(dest_hash, None);
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
pub fn message_create(
    dest_hash: &[u8],
    source_hash: &[u8],
    content: &str,
    title: &str,
    method: u8,
) -> Result<u64, String> {
    let desired = match method {
        0 => LXMessage::OPPORTUNISTIC,
        1 => LXMessage::DIRECT,
        2 => LXMessage::PROPAGATED,
        _ => LXMessage::DIRECT,
    };

    let msg = LXMessage::new(
        None,                                       // destination (set via hash)
        None,                                       // source      (set via hash)
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
