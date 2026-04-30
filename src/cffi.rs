//! Universal C FFI for the LXMF client.
//!
//! This is the **single, authoritative** C interface for any language bridge
//! (Swift, Kotlin, Python, C#, etc.).  Every function hides protocol internals
//! — ratchets, signing, hash truncation, proofs — so the caller only deals
//! with high-level operations: start, send, sync, shutdown.
//!
//! # Naming convention
//!
//! | Prefix             | Scope                    |
//! |--------------------|--------------------------|
//! | `lxmf_client_*`    | client-handle operations |
//! | `lxmf_message_*`   | message-handle operations|
//! | `lxmf_*`           | library-level helpers    |
//!
//! # Handle convention
//!
//! Opaque `u64` handles.  `0` = error (check [`lxmf_last_error`]).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

use reticulum_rust::ffi::{destroy_handle, get_handle, store_handle};

use crate::client::{ClientCallbacks, ClientConfig, LxmfClient};
use crate::ffi as lxmf;
use crate::ffi::ReceivedMessage;

// =========================================================================
// Internal helpers
// =========================================================================

/// Wrapper so raw `*mut c_void` can be sent across threads.
/// The C caller is responsible for thread-safety of the pointed-to object.
struct SendPtr(*mut std::ffi::c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}
impl SendPtr {
    fn ptr(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

fn string_to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn set_error(msg: impl Into<String>) {
    reticulum_rust::ffi::set_error(msg.into());
}

/// Convenience: lock a client handle or return -1.
macro_rules! with_client {
    ($handle:expr, $name:ident, $body:block) => {{
        let arc: Arc<Mutex<LxmfClient>> = match get_handle($handle) {
            Some(h) => h,
            None => {
                set_error("invalid client handle");
                return -1;
            }
        };
        let $name = arc.lock().unwrap();
        $body
    }};
}

// =========================================================================
// C callback type definitions
// =========================================================================

/// Delivery callback: fired when an inbound message is fully received.
pub type LxmfDeliveryCallback = extern "C" fn(
    context: *mut std::ffi::c_void,
    hash: *const u8,
    hash_len: u32,
    src_hash: *const u8,
    src_len: u32,
    dest_hash: *const u8,
    dest_len: u32,
    title: *const c_char,
    content: *const c_char,
    timestamp: f64,
    signature_valid: i32,
    fields_raw: *const u8,
    fields_len: u32,
);

/// Announce callback: fired when we hear a delivery announce.
pub type LxmfAnnounceCallback = extern "C" fn(
    context: *mut std::ffi::c_void,
    dest_hash: *const u8,
    dest_len: u32,
    display_name: *const c_char,
);

/// Sync-complete callback: fired when propagation sync finishes.
pub type LxmfSyncCompleteCallback = extern "C" fn(
    context: *mut std::ffi::c_void,
    message_count: u32,
);

/// Message-state callback: fired whenever an outbound message changes state.
/// `msg_hash` is a pointer to the 16-byte message hash; `hash_len` is always 16.
/// `state` is one of: 0x02=SENDING, 0x04=SENT (propagated), 0x08=DELIVERED,
///   0xFD=REJECTED, 0xFE=CANCELLED, 0xFF=FAILED.
pub type LxmfMessageStateCallback = extern "C" fn(
    context: *mut std::ffi::c_void,
    msg_hash: *const u8,
    hash_len: u32,
    state: u8,
);

/// APP_LINK status callback: fires whenever an APP_LINK transitions state.
/// `dest_hash` is a pointer to the 16-byte destination hash; `hash_len` is 16.
/// `status` is one of: 0=NONE, 1=PATH_REQUESTED, 2=ESTABLISHING,
///   3=ACTIVE, 4=DISCONNECTED.
pub type LxmfAppLinkStatusCallback = extern "C" fn(
    context: *mut std::ffi::c_void,
    dest_hash: *const u8,
    hash_len: u32,
    status: u8,
);

// =========================================================================
// Library-level
// =========================================================================

/// Get last error message.  Caller must free with [`lxmf_free_string`].
/// Returns NULL if no error is pending.
#[no_mangle]
pub extern "C" fn lxmf_last_error() -> *mut c_char {
    match reticulum_rust::ffi::take_error() {
        Some(msg) => string_to_cstr(&msg),
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn lxmf_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Free a byte buffer returned by this library.
#[no_mangle]
pub extern "C" fn lxmf_free_bytes(ptr: *mut u8, len: u32) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
        }
    }
}

// =========================================================================
// Client lifecycle
// =========================================================================

/// Start an LXMF client: init transport, load/create identity, create router,
/// register delivery endpoint, enable ratchets.
///
/// Returns a client handle (>0) or 0 on error.
///
/// # Parameters
///
/// - `config_dir`      — Reticulum config directory (contains `config` file)
/// - `storage_path`    — LXMF storage directory
/// - `identity_path`   — Path to identity file
/// - `create_identity` — If non-zero and identity file missing, create one
/// - `display_name`    — Announced display name (empty string = anonymous)
/// - `log_level`       — 0–7 or -1 for default
/// - `stamp_cost`      — Stamp cost for delivery endpoint (-1 = none)
#[no_mangle]
pub extern "C" fn lxmf_client_start(
    config_dir: *const c_char,
    storage_path: *const c_char,
    identity_path: *const c_char,
    create_identity: i32,
    display_name: *const c_char,
    log_level: i32,
    stamp_cost: i32,
) -> u64 {
    let config = ClientConfig {
        config_dir: unsafe { cstr_to_string(config_dir) },
        lxmf_storage_path: unsafe { cstr_to_string(storage_path) },
        identity_path: unsafe { cstr_to_string(identity_path) },
        create_identity: create_identity != 0,
        display_name: unsafe { cstr_to_string(display_name) },
        log_level,
        stamp_cost: if stamp_cost < 0 {
            None
        } else {
            Some(stamp_cost as u32)
        },
    };

    match LxmfClient::start(config, ClientCallbacks::default()) {
        Ok(client) => store_handle(Arc::new(Mutex::new(client))),
        Err(e) => {
            set_error(e);
            0
        }
    }
}

/// Shut down the client: destroy router, identity, and transport.
/// The handle is invalidated after this call.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_shutdown(client: u64) -> i32 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return -1;
        }
    };
    let guard = arc.lock().unwrap();
    match guard.shutdown() {
        Ok(()) => {
            drop(guard);
            destroy_handle(client);
            0
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

// =========================================================================
// Queries
// =========================================================================

/// Get the raw identity handle stored inside the client.
/// Useful for passing to transport-level functions (link_request, etc.).
/// Returns 0 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_identity_handle(client: u64) -> u64 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return 0;
        }
    };
    let c = arc.lock().unwrap();
    c.identity_handle()
}

// =========================================================================
// Callbacks
// =========================================================================

/// Set the delivery callback.  Called on a **background thread** when a
/// message is received.  Returns 0 on success.
#[no_mangle]
pub extern "C" fn lxmf_client_set_delivery_callback(
    client: u64,
    callback: LxmfDeliveryCallback,
    context: *mut std::ffi::c_void,
) -> i32 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return -1;
        }
    };
    let guard = arc.lock().unwrap();

    let ctx = SendPtr(context);
    let adapter = Arc::new(move |msg: ReceivedMessage| {
        let title_c = CString::new(msg.title.as_str()).unwrap_or_default();
        let content_c = CString::new(msg.content.as_str()).unwrap_or_default();
        callback(
            ctx.ptr(),
            msg.hash.as_ptr(),
            msg.hash.len() as u32,
            msg.source_hash.as_ptr(),
            msg.source_hash.len() as u32,
            msg.destination_hash.as_ptr(),
            msg.destination_hash.len() as u32,
            title_c.as_ptr(),
            content_c.as_ptr(),
            msg.timestamp,
            if msg.signature_validated { 1 } else { 0 },
            msg.fields_raw.as_ptr(),
            msg.fields_raw.len() as u32,
        );
    });

    match guard.set_delivery_callback(adapter) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Set the announce callback.  Called when a delivery announce is heard.
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn lxmf_client_set_announce_callback(
    client: u64,
    callback: LxmfAnnounceCallback,
    context: *mut std::ffi::c_void,
) -> i32 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return -1;
        }
    };
    let guard = arc.lock().unwrap();

    let ctx = SendPtr(context);
    let adapter = Arc::new(move |dest_hash: &[u8], display_name: Option<String>| {
        let name_c = display_name
            .as_ref()
            .map(|n| CString::new(n.as_str()).unwrap_or_default());
        let name_ptr = name_c
            .as_ref()
            .map_or(std::ptr::null(), |c| c.as_ptr());
        callback(
            ctx.ptr(),
            dest_hash.as_ptr(),
            dest_hash.len() as u32,
            name_ptr,
        );
    });

    match guard.set_announce_callback(adapter) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Set the sync-complete callback.  Fires when propagation sync finishes.
/// `message_count` is 0 when the propagation node had nothing new.
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn lxmf_client_set_sync_complete_callback(
    client: u64,
    callback: LxmfSyncCompleteCallback,
    context: *mut std::ffi::c_void,
) -> i32 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return -1;
        }
    };
    let guard = arc.lock().unwrap();

    let ctx = SendPtr(context);
    let adapter = Arc::new(move |count: u32| {
        callback(ctx.ptr(), count);
    });

    match guard.set_sync_complete_callback(adapter) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Set the message-state callback.  Fires when an outbound message changes
/// delivery state (SENDING, SENT, DELIVERED, REJECTED, CANCELLED, FAILED).
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn lxmf_client_set_message_state_callback(
    client: u64,
    callback: LxmfMessageStateCallback,
    context: *mut std::ffi::c_void,
) -> i32 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return -1;
        }
    };
    let guard = arc.lock().unwrap();

    let ctx = SendPtr(context);
    let adapter = Arc::new(move |hash: &[u8], state: u8| {
        callback(ctx.ptr(), hash.as_ptr(), hash.len() as u32, state);
    });

    match guard.set_message_state_callback(adapter) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Register an APP_LINK status callback on the global registry.
///
/// The callback fires whenever an APP_LINK transitions state.  Multiple
/// callbacks may be registered (each call appends one).  The callback is
/// invoked from the link-actor thread and MUST NOT block — copy any data
/// you need and dispatch off-thread.
///
/// Returns 0 on success, -1 on error (call `lxmf_last_error` for details).
#[no_mangle]
pub extern "C" fn lxmf_app_link_register_status_callback(
    client: u64,
    callback: LxmfAppLinkStatusCallback,
    context: *mut std::ffi::c_void,
) -> i32 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return -1;
        }
    };
    let guard = arc.lock().unwrap();

    let ctx = SendPtr(context);
    let adapter = Arc::new(move |hash: &[u8], status: u8| {
        callback(ctx.ptr(), hash.as_ptr(), hash.len() as u32, status);
    });

    match guard.register_app_link_status_callback(adapter) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

// =========================================================================
// Client queries
// =========================================================================

/// Get the client's 16-byte identity hash.
/// Writes to `out_buf`.  Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_identity_hash(
    client: u64,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = c.identity_hash();
        if buf_len < hash.len() as u32 {
            set_error("buffer too small");
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, hash.len());
        }
        hash.len() as i32
    })
}

/// Get the client's 16-byte LXMF delivery destination hash.
/// Writes to `out_buf`.  Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_dest_hash(
    client: u64,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = &c.dest_hash;
        if buf_len < hash.len() as u32 {
            set_error("buffer too small");
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, hash.len());
        }
        hash.len() as i32
    })
}

// =========================================================================
// Propagation
// =========================================================================

/// Set a propagation node and request messages.
/// `node_hash` is the 16-byte propagation node destination hash.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_sync(
    client: u64,
    node_hash: *const u8,
    node_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = if node_hash.is_null() || node_len == 0 {
            set_error("null node hash");
            return -1;
        } else {
            unsafe { std::slice::from_raw_parts(node_hash, node_len as usize) }
        };
        match c.sync_from_propagation_node(hash) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Get the current propagation transfer state byte.
/// Returns state (>=0) or -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_propagation_state(client: u64) -> i32 {
    with_client!(client, c, {
        match c.propagation_state() {
            Ok(s) => s as i32,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Get the current propagation transfer progress (0.0–1.0).
/// Returns progress or -1.0 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_propagation_progress(client: u64) -> f32 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return -1.0;
        }
    };
    let c = arc.lock().unwrap();
    match c.propagation_progress() {
        Ok(p) => p as f32,
        Err(e) => {
            set_error(e);
            -1.0
        }
    }
}

/// Cancel an in-progress propagation transfer.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_cancel_propagation(client: u64) -> i32 {
    with_client!(client, c, {
        match c.cancel_propagation() {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

// =========================================================================
// Announce
// =========================================================================

/// Announce this client's delivery destination on the network.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_announce(client: u64) -> i32 {
    with_client!(client, c, {
        match c.announce() {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Opt this client's delivery destination into Transport's auto-announce
/// daemon. After this call, Transport automatically re-announces:
///   * once on every interface false→true `online` transition, and
///   * every `refresh_secs` seconds (pass 0.0 to disable periodic
///     refresh and only re-announce on interface up-edges).
///
/// Idempotent: calling again with a different `refresh_secs` updates
/// the existing entry without re-announcing. Returns 0 on success.
#[no_mangle]
pub extern "C" fn lxmf_client_publish(client: u64, refresh_secs: f64) -> i32 {
    with_client!(client, c, {
        match c.publish(refresh_secs) {
            Ok(()) => 0,
            Err(e) => { set_error(e); -1 }
        }
    })
}

/// Remove this client's delivery destination from the announce daemon's
/// published set. Does not send a "goodbye" announce; the destination
/// simply stops being auto-announced. Returns 0 on success.
#[no_mangle]
pub extern "C" fn lxmf_client_unpublish(client: u64) -> i32 {
    with_client!(client, c, {
        match c.unpublish() {
            Ok(()) => 0,
            Err(e) => { set_error(e); -1 }
        }
    })
}

/// Watch for announces from a destination hash.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_watch(
    client: u64,
    dest_hash: *const u8,
    dest_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = if dest_hash.is_null() || dest_len == 0 {
            set_error("null dest hash");
            return -1;
        } else {
            unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
        };
        match c.watch_destination(hash) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Query the current direct-link status for a peer.
/// Returns: 0 = no link / closed, 1 = pending (establishing), 2 = active.
/// Returns -1 on parameter error.
#[no_mangle]
pub extern "C" fn lxmf_peer_link_status(
    client: u64,
    dest_hash: *const u8,
    dest_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = if dest_hash.is_null() || dest_len == 0 {
            set_error("null dest hash");
            return -1;
        } else {
            unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
        };
        match c.peer_link_status(hash) {
            Ok(s) => s as i32,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

// =========================================================================
// App links — proactive link establishment for open chat screens
// =========================================================================

/// Open an app link for a destination (e.g. when the user opens a chat screen).
///
/// Watches the destination, requests a path if needed, and establishes a
/// direct link when the path becomes available — all push-driven, no polling.
/// The link is kept alive automatically and exempt from inactivity cleanup.
///
/// `app_name` and `aspects_csv` describe the destination identity that the
/// router must resolve when (re)establishing the link. Examples:
///   `app_name="lxmf"`, `aspects_csv="delivery"` — peer chat link.
///   `app_name="rfed"`, `aspects_csv="channel"` — rfed channel link.
///   `app_name="rfed"`, `aspects_csv="notify"`  — rfed notify link.
/// `aspects_csv` is a `.`-separated list (matches Destination naming convention)
/// — pass `"foo.bar"` for app aspects `["foo","bar"]`. Empty string is allowed.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_app_link_open(
    client: u64,
    dest_hash: *const u8,
    dest_len: u32,
    app_name: *const std::os::raw::c_char,
    aspects_csv: *const std::os::raw::c_char,
) -> i32 {
    with_client!(client, c, {
        let hash = if dest_hash.is_null() || dest_len == 0 {
            set_error("null dest hash");
            return -1;
        } else {
            unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
        };
        let app = if app_name.is_null() {
            set_error("null app_name");
            return -1;
        } else {
            match unsafe { std::ffi::CStr::from_ptr(app_name) }.to_str() {
                Ok(s) => s,
                Err(_) => { set_error("app_name not utf-8"); return -1; }
            }
        };
        let aspects_str = if aspects_csv.is_null() {
            ""
        } else {
            match unsafe { std::ffi::CStr::from_ptr(aspects_csv) }.to_str() {
                Ok(s) => s,
                Err(_) => { set_error("aspects_csv not utf-8"); return -1; }
            }
        };
        let aspects: Vec<&str> = if aspects_str.is_empty() {
            Vec::new()
        } else {
            aspects_str.split('.').collect()
        };
        match c.app_link_open(hash, app, &aspects) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Close an app link (e.g. when the user leaves the chat screen).
///
/// Tears down the direct link and removes the destination from app_links.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_app_link_close(
    client: u64,
    dest_hash: *const u8,
    dest_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = if dest_hash.is_null() || dest_len == 0 {
            set_error("null dest hash");
            return -1;
        } else {
            unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
        };
        match c.app_link_close(hash) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Query the status of an app link.
///
/// Returns: 0 = not tracked, 1 = path requested, 2 = link establishing,
///          3 = link active, 4 = disconnected (reconnects on next announce).
/// Returns -1 on parameter error.
#[no_mangle]
pub extern "C" fn lxmf_app_link_status(
    client: u64,
    dest_hash: *const u8,
    dest_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = if dest_hash.is_null() || dest_len == 0 {
            set_error("null dest hash");
            return -1;
        } else {
            unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
        };
        match c.app_link_status(hash) {
            Ok(s) => s as i32,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Send a blocking request on an existing app-link.
///
/// Looks up the LinkHandle for `dest_hash` from the router's `direct_links`
/// table (or `backchannel_links`), checks that the link is `STATE_ACTIVE`,
/// then issues `path` with `payload` and waits up to `timeout_secs` for a
/// response.
///
/// This is the multiplexing equivalent of `retichat_link_request`: instead
/// of opening a new outbound link per request, it reuses the persistent
/// app-link that was opened with `lxmf_app_link_open`.
///
/// Caller MUST call `lxmf_app_link_open` first and wait for the link to be
/// `APP_LINK_ACTIVE` (status == 3) before calling this.
///
/// Returns a pointer to the response bytes (caller must free with
/// `lxmf_free_bytes`), or NULL on error / timeout / no link / link not
/// active (check `lxmf_last_error`).
///
/// This call is **blocking** — Swift must invoke it from a background thread.
#[no_mangle]
pub extern "C" fn lxmf_app_link_request(
    client: u64,
    dest_hash: *const u8,
    dest_len: u32,
    path: *const c_char,
    payload: *const u8,
    payload_len: u32,
    timeout_secs: f64,
    out_len: *mut u32,
) -> *mut u8 {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    // Validate args.
    let hash = if dest_hash.is_null() || dest_len == 0 {
        set_error("null dest hash");
        return std::ptr::null_mut();
    } else {
        unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
    };
    let path_str = if path.is_null() {
        set_error("null path");
        return std::ptr::null_mut();
    } else {
        unsafe {
            match std::ffi::CStr::from_ptr(path).to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => {
                    set_error("path is not valid UTF-8");
                    return std::ptr::null_mut();
                }
            }
        }
    };
    let payload_slice: &[u8] = if payload.is_null() || payload_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(payload, payload_len as usize) }
    };

    // Briefly lock the client to clone the LinkHandle, then drop the lock so
    // the request/wait does not block other router operations.
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return std::ptr::null_mut();
        }
    };
    let link_handle = {
        let guard = arc.lock().unwrap();
        match guard.app_link_get_handle(hash) {
            Ok(Some(h)) => h,
            Ok(None) => {
                set_error("no app-link to destination — call lxmf_app_link_open first");
                return std::ptr::null_mut();
            }
            Err(e) => {
                set_error(e);
                return std::ptr::null_mut();
            }
        }
    };

    // Verify the link is active before issuing the request.
    let status = link_handle.status();
    if status != reticulum_rust::link::STATE_ACTIVE {
        set_error(format!(
            "app-link not active (status={}) — wait for APP_LINK_ACTIVE before requesting",
            status
        ));
        return std::ptr::null_mut();
    }

    // Set up callbacks to capture the response.
    let response_data: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(None));
    let request_done = Arc::new(AtomicBool::new(false));
    let request_failed = Arc::new(AtomicBool::new(false));

    let resp_ok = Arc::clone(&response_data);
    let done_ok = Arc::clone(&request_done);
    let response_cb: Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync> =
        Arc::new(move |receipt: reticulum_rust::link::RequestReceipt| {
            if let Some(ref data) = receipt.response {
                if let Ok(mut r) = resp_ok.lock() {
                    *r = Some(data.clone());
                }
            }
            done_ok.store(true, Ordering::SeqCst);
        });

    let done_fail = Arc::clone(&request_done);
    let failed_flag = Arc::clone(&request_failed);
    let failed_cb: Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync> =
        Arc::new(move |_receipt| {
            failed_flag.store(true, Ordering::SeqCst);
            done_fail.store(true, Ordering::SeqCst);
        });

    if let Err(e) = link_handle.request(
        path_str,
        payload_slice.to_vec(),
        Some(response_cb),
        Some(failed_cb),
        None,
    ) {
        set_error(format!("link.request failed: {:?}", e));
        return std::ptr::null_mut();
    }

    // Wait for completion or timeout.
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
    while !request_done.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            set_error("app-link request timed out");
            return std::ptr::null_mut();
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Collect response.
    let result = match response_data.lock() {
        Ok(mut g) => g.take(),
        Err(_) => {
            set_error("response lock poisoned");
            return std::ptr::null_mut();
        }
    };

    match result {
        Some(bytes) => {
            let len = bytes.len() as u32;
            let boxed = bytes.into_boxed_slice();
            let raw = Box::into_raw(boxed);
            if !out_len.is_null() {
                unsafe { *out_len = len; }
            }
            raw as *mut u8
        }
        None => {
            if request_failed.load(Ordering::SeqCst) {
                set_error("app-link request failed (no response)");
            } else {
                set_error("app-link request completed without response");
            }
            std::ptr::null_mut()
        }
    }
}

/// Register an app-link reconnect handler for a non-LXMF destination aspect.
///
/// Call this once per extra aspect during startup so the LXMF router
/// re-establishes app-links to those destinations on announce.
///
/// # Arguments
/// * `client`         – handle returned by `lxmf_client_start`.
/// * `aspect_filter`  – NUL-terminated ASCII string of the full aspect name,
///   e.g. `"rfed.channel"` or `"rfed.notify"`.
///
/// Returns 0 on success, -1 on error (call `lxmf_last_error` for details).
#[no_mangle]
pub extern "C" fn lxmf_app_link_register_reconnect(
    client: u64,
    aspect_filter: *const c_char,
) -> i32 {
    with_client!(client, c, {
        let aspect = if aspect_filter.is_null() {
            set_error("null aspect_filter");
            return -1;
        } else {
            unsafe {
                match std::ffi::CStr::from_ptr(aspect_filter).to_str() {
                    Ok(s) => s.to_owned(),
                    Err(_) => {
                        set_error("aspect_filter is not valid UTF-8");
                        return -1;
                    }
                }
            }
        };
        match lxmf::router_register_app_link_reconnect_handler(c.router_handle, &aspect) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Notify the router that the host's network reachability state has
/// changed (interface up/down, Wi-Fi ↔ cellular, etc.).
///
/// Triggers ONE fresh app-link establishment attempt for every registered
/// app-link that is not currently active or establishing. The router does
/// not retry on its own — call this from a network-state observer.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_app_link_network_changed(client: u64) -> i32 {
    with_client!(client, c, {
        match lxmf::router_app_link_network_changed(c.router_handle) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Set the host lifecycle policy on the global app-link registry.
///
/// `policy`:
///   * `0` = Foreground (default; full triggers active)
///   * `1` = Background (hold links; suppress network-change retries and
///     post-ACTIVE auto-retries; announces still establish)
///   * `2` = Suspended (tear down all tracked links; suppress all triggers)
///
/// Returns 0 on success, -1 on error (invalid client handle or unknown policy).
#[no_mangle]
pub extern "C" fn lxmf_app_link_set_policy(client: u64, policy: u8) -> i32 {
    with_client!(client, c, {
        match lxmf::router_app_link_set_policy(c.router_handle, policy) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Read the current host lifecycle policy. Returns the encoding documented
/// for `lxmf_app_link_set_policy`, or `0xFF` on error.
#[no_mangle]
pub extern "C" fn lxmf_app_link_policy(client: u64) -> u8 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return 0xFF;
        }
    };
    let c = arc.lock().unwrap();
    match lxmf::router_app_link_policy(c.router_handle) {
        Ok(p) => p,
        Err(e) => {
            set_error(e);
            0xFF
        }
    }
}

/// Look up the cached display name for a destination hash.
///
/// Reads the announce app-data stored in the Reticulum Identity table when
/// the announce was received, and decodes the LXMF display-name field from
/// it.  Returns the number of bytes written to `out_buf` (including the NUL
/// terminator), or 0 if no name is known or `out_buf` is too small.
///
/// The returned string is always NUL-terminated.
#[no_mangle]
pub extern "C" fn lxmf_client_recall_display_name(
    _client: u64,
    dest_hash: *const u8,
    dest_len: u32,
    out_buf: *mut c_char,
    buf_len: u32,
) -> i32 {
    let hash = if dest_hash.is_null() || dest_len == 0 {
        return 0;
    } else {
        unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
    };

    let app_data = reticulum_rust::identity::Identity::recall_app_data(hash);
    let name = crate::lxmf::display_name_from_app_data(app_data.as_deref());

    match name {
        Some(n) if !n.is_empty() => {
            match CString::new(n.as_str()) {
                Ok(cstr) => {
                    let bytes = cstr.as_bytes_with_nul();
                    if out_buf.is_null() || (buf_len as usize) < bytes.len() {
                        return 0;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr() as *const c_char,
                            out_buf,
                            bytes.len(),
                        );
                    }
                    bytes.len() as i32
                }
                Err(_) => 0,
            }
        }
        _ => 0,
    }
}

// =========================================================================
// Outbound messages
// =========================================================================

/// Create a new outbound message.
///
/// The client's identity is used for signing and source addressing.
/// The caller only supplies the recipient, content, and delivery method.
///
/// `method`: 1 = opportunistic, 2 = direct, 3 = propagated.
///
/// Returns a message handle (>0) or 0 on error.
/// Optionally decorate with [`lxmf_message_add_field`] /
/// [`lxmf_message_add_attachment`] before sending.
#[no_mangle]
pub extern "C" fn lxmf_message_new(
    client: u64,
    dest_hash: *const u8,
    dest_len: u32,
    content: *const c_char,
    title: *const c_char,
    method: u8,
) -> u64 {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle");
            return 0;
        }
    };
    let c = arc.lock().unwrap();

    let dh = if dest_hash.is_null() || dest_len == 0 {
        set_error("null dest hash");
        return 0;
    } else {
        unsafe { std::slice::from_raw_parts(dest_hash, dest_len as usize) }
    };
    let ct = unsafe { cstr_to_string(content) };
    let ti = unsafe { cstr_to_string(title) };

    match c.create_message(dh, &ct, &ti, method) {
        Ok(h) => h,
        Err(e) => {
            set_error(e);
            0
        }
    }
}

/// Add a string-valued field to a message.
/// `key` is an LXMF field ID (e.g. 0xA0 for group ID).
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_message_add_field(
    msg: u64,
    key: u8,
    value: *const c_char,
) -> i32 {
    let v = unsafe { cstr_to_string(value) };
    match lxmf::message_add_field_string(msg, key, &v) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Add a boolean-valued field to a message.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_message_add_field_bool(msg: u64, key: u8, value: i32) -> i32 {
    match lxmf::message_add_field_bool(msg, key, value != 0) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Add a file attachment to a message.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_message_add_attachment(
    msg: u64,
    filename: *const c_char,
    data: *const u8,
    data_len: u32,
) -> i32 {
    let f = unsafe { cstr_to_string(filename) };
    let d = if data.is_null() || data_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len as usize).to_vec() }
    };
    match lxmf::message_add_attachment(msg, &f, &d) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Submit a message for delivery.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_message_send(client: u64, msg: u64) -> i32 {
    with_client!(client, c, {
        match c.send_message(msg) {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Get message delivery state.
/// Returns state byte (>=0) or -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_message_state(msg: u64) -> i32 {
    match lxmf::message_get_state(msg) {
        Ok(s) => s as i32,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Get message transfer progress (0.0–1.0).
#[no_mangle]
pub extern "C" fn lxmf_message_progress(msg: u64) -> f32 {
    match lxmf::message_get_progress(msg) {
        Ok(p) => p,
        Err(e) => {
            set_error(e);
            -1.0
        }
    }
}

/// Get message hash.  Writes to `out_buf`.
/// Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_message_hash(msg: u64, out_buf: *mut u8, buf_len: u32) -> i32 {
    match lxmf::message_get_hash(msg) {
        Ok(h) => {
            if buf_len < h.len() as u32 {
                set_error("buffer too small");
                return -1;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(h.as_ptr(), out_buf, h.len());
            }
            h.len() as i32
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Destroy a message handle.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_message_destroy(msg: u64) -> i32 {
    if destroy_handle(msg) {
        0
    } else {
        set_error("invalid message handle");
        -1
    }
}

// =========================================================================
// Utility
// =========================================================================

/// Process outbound message queue (retries, link management).
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn lxmf_client_process_outbound(client: u64) -> i32 {
    with_client!(client, c, {
        match c.process_outbound() {
            Ok(()) => 0,
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Persist path table and cached data to disk.
#[no_mangle]
pub extern "C" fn lxmf_client_persist(client: u64) {
    let arc: Arc<Mutex<LxmfClient>> = match get_handle(client) {
        Some(h) => h,
        None => return,
    };
    let c = arc.lock().unwrap();
    c.persist();
}
