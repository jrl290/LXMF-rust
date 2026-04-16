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
    // Clear all callbacks first so that Transport background threads that are
    // already in-flight (or will fire from network packets arriving after
    // shutdown) cannot call into a stale context pointer after the test
    // (or caller) has released the ctx memory.
    if let Some(router) = get_handle::<Arc<Mutex<LXMRouter>>>(router_handle) {
        if let Ok(mut r) = router.lock() {
            r.announce_callback = None;
            r.delivery_callback = None;
            r.sync_complete_callback = None;
            r.message_state_callback = None;
        }
    }
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

/// Return the direct-link status for a peer: 0=none, 1=pending, 2=active.
pub fn router_peer_link_status(router_handle: u64, dest_hash: &[u8]) -> Result<u8, String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let guard = router.lock().map_err(|e| e.to_string())?;
    let status = guard.peer_link_status(dest_hash);
    Ok(status)
}

// ---------------------------------------------------------------------------
// App links — proactive link establishment
// ---------------------------------------------------------------------------

/// Open an app link: watch + request path + establish link when available.
///
/// Returns immediately.  The link is established asynchronously via the
/// announce handler (push, no polling).
pub fn router_app_link_open(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .app_link_open(dest_hash);
    Ok(())
}

/// Close an app link: tear down the direct link and remove from app_links.
pub fn router_app_link_close(router_handle: u64, dest_hash: &[u8]) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .app_link_close(dest_hash);
    Ok(())
}

/// Query the current app-link status.
///
/// Returns: 0 = not tracked, 1 = path requested, 2 = link establishing,
///          3 = link active, 4 = disconnected (reconnects on next announce).
/// Returns `Err` on parameter error.
pub fn router_app_link_status(router_handle: u64, dest_hash: &[u8]) -> Result<u8, String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    let guard = router.lock().map_err(|e| e.to_string())?;
    Ok(guard.app_link_status(dest_hash))
}

/// Register a callback that fires when an outbound message changes delivery state.
///
/// The callback receives the 16-byte message hash and the new state byte:
///   0x02 = SENDING, 0x04 = SENT (propagated), 0x08 = DELIVERED,
///   0xFD = REJECTED, 0xFE = CANCELLED, 0xFF = FAILED.
pub fn router_set_message_state_callback(
    router_handle: u64,
    callback: Arc<dyn Fn(&[u8], u8) + Send + Sync>,
) -> Result<(), String> {
    let router: Arc<Mutex<LXMRouter>> = get_handle(router_handle)
        .ok_or_else(|| "invalid router handle".to_string())?;

    router
        .lock()
        .map_err(|e| e.to_string())?
        .register_message_state_callback(callback);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lx_message::LXMessage;
    use reticulum_rust::destination::{Destination, DestinationType};
    use reticulum_rust::ffi::store_handle;
    use reticulum_rust::identity::Identity;

    /// Build a minimal outbound LXMessage handle, no network required.
    fn make_msg_handle() -> u64 {
        let src_identity = Identity::new(true);
        let dst_identity = Identity::new(true);

        let source = Destination::new_inbound(
            Some(src_identity),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["delivery".to_string()],
        )
        .expect("source dest");

        let dest = Destination::new_outbound(
            Some(dst_identity),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["delivery".to_string()],
        )
        .expect("dest dest");

        let dest_hash = dest.hash.clone();
        let src_hash = source.hash.clone();

        let msg = LXMessage::new(
            Some(dest),
            Some(source),
            Some(b"hello world".to_vec()),
            Some(b"test".to_vec()),
            None,
            Some(LXMessage::PROPAGATED),
            Some(dest_hash),
            Some(src_hash),
            None,
            false,
        )
        .expect("LXMessage::new");

        store_handle(Arc::new(Mutex::new(msg)))
    }

    /// REGRESSION GUARD: message_get_hash returns Err before pack().
    ///
    /// The hash is only computed during pack(), which runs synchronously inside
    /// handle_outbound() (i.e. sendMessage() in the FFI).  Calling
    /// message_get_hash before sendMessage returns `Err("message has no hash yet")`.
    ///
    /// In Swift / iOS this means messageHash(msgHandle) returns nil and the guard
    /// exits, silently swallowing the send with no UI bubble.  The fix is to call
    /// sendMessage() first, then read the hash.
    ///
    /// If this test is broken (hash becomes available before pack), the ordering
    /// constraint no longer matters — update the Swift call sites accordingly.
    #[test]
    fn message_get_hash_before_pack_is_err() {
        let handle = make_msg_handle();

        let result = message_get_hash(handle);
        assert!(
            result.is_err(),
            "message_get_hash must return Err before pack() runs — \
             Swift callers must call sendMessage() first, then read the hash. \
             Got: {:?}",
            result
        );
        assert_eq!(
            result.unwrap_err(),
            "message has no hash yet",
            "error string must be 'message has no hash yet'"
        );

        destroy_handle(handle);
    }

    /// REGRESSION GUARD: message_get_hash returns Ok after pack().
    ///
    /// pack() is called synchronously from handle_outbound() / sendMessage().
    /// After sendMessage() returns the hash is guaranteed to be set.
    /// If this test fails, pack() has stopped writing the hash field.
    #[test]
    fn message_get_hash_after_pack_is_ok() {
        let handle = make_msg_handle();

        // Simulate what handle_outbound() does: call pack() directly.
        {
            let msg: Arc<Mutex<LXMessage>> = get_handle(handle).unwrap();
            msg.lock().unwrap().pack(false).expect("pack");
        }

        let result = message_get_hash(handle);
        assert!(
            result.is_ok(),
            "message_get_hash must return Ok after pack() — got: {:?}",
            result
        );
        assert!(
            !result.unwrap().is_empty(),
            "hash returned by message_get_hash must be non-empty"
        );

        destroy_handle(handle);
    }

    /// REGRESSION GUARD: message_get_hash matches the internal LXMessage.hash field.
    ///
    /// Ensures message_get_hash is reading the correct field and not truncating
    /// or otherwise corrupting the bytes.
    #[test]
    fn message_get_hash_matches_internal_hash_field() {
        let handle = make_msg_handle();

        {
            let msg: Arc<Mutex<LXMessage>> = get_handle(handle).unwrap();
            msg.lock().unwrap().pack(false).expect("pack");
        }

        let via_fn = message_get_hash(handle).expect("hash must be available after pack");

        let via_field: Vec<u8> = {
            let msg: Arc<Mutex<LXMessage>> = get_handle(handle).unwrap();
            let guard = msg.lock().unwrap();
            guard.hash.clone().expect("LXMessage.hash must be Some after pack")
        };

        assert_eq!(
            via_fn, via_field,
            "message_get_hash must return the same bytes as LXMessage.hash"
        );

        destroy_handle(handle);
    }

    /// REGRESSION GUARD: two separate messages produce distinct hashes.
    ///
    /// Each LXMF message includes a unique timestamp, so hash collisions between
    /// independently created messages are not expected.  A collision would cause
    /// the second message to overwrite the first in the pendingOutbound dict,
    /// losing its state-callback tracking.
    #[test]
    fn distinct_messages_have_distinct_hashes() {
        let h1 = make_msg_handle();
        let h2 = make_msg_handle();

        for h in [h1, h2] {
            let msg: Arc<Mutex<LXMessage>> = get_handle(h).unwrap();
            msg.lock().unwrap().pack(false).expect("pack");
        }

        let hash1 = message_get_hash(h1).unwrap();
        let hash2 = message_get_hash(h2).unwrap();

        assert_ne!(
            hash1, hash2,
            "two independently created messages must have distinct hashes"
        );

        destroy_handle(h1);
        destroy_handle(h2);
    }
}
