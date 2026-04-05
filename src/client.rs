//! High-level Reticulum + LXMF client.
//!
//! `LxmfClient` encapsulates the common protocol sequence shared by every
//! consumer (iOS main app, NSE, Android, CLI tools, etc.):
//!
//!   1. Initialize Reticulum transport
//!   2. Load or create an identity
//!   3. Create an LXMF router + delivery endpoint
//!   4. Enable ratchets
//!   5. Wire callbacks (delivery, announce, sync-complete)
//!   6. Sync from a propagation node
//!   7. Tear down
//!
//! Consumers only need to supply a [`ClientConfig`] and optional callbacks.

use std::sync::Arc;

use reticulum_rust::ffi as rns;

use crate::ffi as lxmf;
use crate::ffi::ReceivedMessage;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything needed to stand up an LXMF client.
pub struct ClientConfig {
    /// Path to the Reticulum config directory (contains the `config` file).
    pub config_dir: String,

    /// Path to the LXMF storage directory.
    /// **Note**: `LXMRouter` internally appends `/lxmf` to this path.
    pub lxmf_storage_path: String,

    /// Path to the identity file.  If it doesn't exist and
    /// `create_identity` is `true`, a new identity will be generated.
    pub identity_path: String,

    /// Create a new identity if the file doesn't exist.
    pub create_identity: bool,

    /// Display name announced on the network (empty = anonymous).
    pub display_name: String,

    /// Log level (0–7, or -1 for default).
    pub log_level: i32,

    /// Stamp cost for the delivery endpoint (`None` = no stamps).
    pub stamp_cost: Option<u32>,
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

/// Optional callbacks a consumer wires up *before* calling `start()`.
#[derive(Default)]
pub struct ClientCallbacks {
    pub on_delivery: Option<Arc<dyn Fn(ReceivedMessage) + Send + Sync>>,
    pub on_announce: Option<Arc<dyn Fn(&[u8], Option<String>) + Send + Sync>>,
    pub on_sync_complete: Option<Arc<dyn Fn(u32) + Send + Sync>>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A running LXMF client.  All protocol state is owned here; callers only
/// interact through the public methods.
pub struct LxmfClient {
    pub identity_handle: u64,
    pub router_handle: u64,
    pub dest_handle: u64,

    /// The 16-byte identity hash.
    pub identity_hash: Vec<u8>,

    /// The 16-byte LXMF delivery destination hash.
    pub dest_hash: Vec<u8>,
}

impl LxmfClient {
    /// Stand up the full Reticulum + LXMF stack.
    ///
    /// This performs steps 1–5 of the protocol sequence.  After `start()`
    /// returns the transport interfaces are connecting and the router is
    /// ready to receive messages.
    pub fn start(
        config: ClientConfig,
        callbacks: ClientCallbacks,
    ) -> Result<Self, String> {
        // 1. Init Reticulum transport
        rns::init(&config.config_dir, config.log_level)?;

        // Re-apply stderr logging so Xcode / logcat can see it.
        rns::set_log_callback(|msg| {
            eprintln!("{}", msg);
        });

        // 2. Load or create identity
        let identity_handle =
            match rns::identity_from_file(&config.identity_path) {
                Ok(h) => h,
                Err(_) if config.create_identity => {
                    let h = rns::identity_create()?;
                    rns::identity_to_file(h, &config.identity_path)?;
                    h
                }
                Err(e) => return Err(e),
            };

        let identity_hash = rns::identity_hash(identity_handle)?;

        let dest_hash = rns::destination_hash_for(
            identity_handle,
            "lxmf",
            &["delivery"],
        )?;

        // 3. Create router + register delivery endpoint
        let router_handle =
            lxmf::router_create(identity_handle, &config.lxmf_storage_path)?;

        let display = if config.display_name.is_empty() {
            None
        } else {
            Some(config.display_name.as_str())
        };
        let dest_handle = lxmf::router_register_delivery(
            router_handle,
            identity_handle,
            display,
            config.stamp_cost,
        )?;

        // Ratchets are enabled automatically inside register_delivery_identity.

        // 4. Wire callbacks
        if let Some(cb) = callbacks.on_delivery {
            lxmf::router_set_delivery_callback(router_handle, cb)?;
        }
        if let Some(cb) = callbacks.on_announce {
            lxmf::router_set_announce_callback(router_handle, cb)?;
        }
        if let Some(cb) = callbacks.on_sync_complete {
            lxmf::router_set_sync_complete_callback(router_handle, cb)?;
        }

        Ok(LxmfClient {
            identity_handle,
            router_handle,
            dest_handle,
            identity_hash,
            dest_hash,
        })
    }

    // -------------------------------------------------------------------
    // Propagation
    // -------------------------------------------------------------------

    /// Set the outbound propagation node and request messages.
    pub fn sync_from_propagation_node(
        &self,
        node_hash: &[u8],
    ) -> Result<(), String> {
        lxmf::router_set_propagation_node(self.router_handle, node_hash)?;
        lxmf::router_request_messages(self.router_handle, self.identity_handle)
    }

    /// Current propagation transfer state byte.
    pub fn propagation_state(&self) -> Result<u8, String> {
        lxmf::router_get_propagation_state(self.router_handle)
    }

    /// Current propagation transfer progress (0.0–1.0).
    pub fn propagation_progress(&self) -> Result<f64, String> {
        lxmf::router_get_propagation_progress(self.router_handle)
    }

    /// Cancel an in-progress propagation transfer.
    pub fn cancel_propagation(&self) -> Result<(), String> {
        lxmf::router_cancel_propagation(self.router_handle)
    }

    // -------------------------------------------------------------------
    // Announce
    // -------------------------------------------------------------------

    /// Announce this client's delivery destination on the network.
    pub fn announce(&self) -> Result<(), String> {
        lxmf::router_announce(self.router_handle, &self.dest_hash)
    }

    /// Add a destination hash to the announce watch list.
    pub fn watch_destination(&self, dest_hash: &[u8]) -> Result<(), String> {
        lxmf::router_watch_destination(self.router_handle, dest_hash)
    }

    // -------------------------------------------------------------------
    // Outbound messages
    // -------------------------------------------------------------------

    /// Process outbound message queue (retries, link management).
    pub fn process_outbound(&self) -> Result<(), String> {
        lxmf::router_process_outbound(self.router_handle)
    }

    // -------------------------------------------------------------------
    // Callbacks (set after start)
    // -------------------------------------------------------------------

    /// Set or replace the delivery callback.
    pub fn set_delivery_callback(
        &self,
        cb: Arc<dyn Fn(ReceivedMessage) + Send + Sync>,
    ) -> Result<(), String> {
        lxmf::router_set_delivery_callback(self.router_handle, cb)
    }

    /// Set or replace the announce callback.
    pub fn set_announce_callback(
        &self,
        cb: Arc<dyn Fn(&[u8], Option<String>) + Send + Sync>,
    ) -> Result<(), String> {
        lxmf::router_set_announce_callback(self.router_handle, cb)
    }

    /// Set or replace the sync-complete callback.
    pub fn set_sync_complete_callback(
        &self,
        cb: Arc<dyn Fn(u32) + Send + Sync>,
    ) -> Result<(), String> {
        lxmf::router_set_sync_complete_callback(self.router_handle, cb)
    }

    // -------------------------------------------------------------------
    // Outbound messages
    // -------------------------------------------------------------------

    /// Create a new outbound message.
    ///
    /// The client's identity is used for signing and the client's delivery
    /// destination hash is used as the source.  The caller only supplies the
    /// recipient and content — no protocol knowledge needed.
    ///
    /// Returns a message handle.  Optionally decorate with
    /// [`lxmf::message_add_field_string`] / [`lxmf::message_add_attachment`]
    /// before calling [`send_message`].
    pub fn create_message(
        &self,
        dest_hash: &[u8],
        content: &str,
        title: &str,
        method: u8,
    ) -> Result<u64, String> {
        lxmf::message_create(
            dest_hash,
            &self.dest_hash,
            content,
            title,
            method,
            self.identity_handle,
        )
    }

    /// Submit a previously created message for delivery.
    pub fn send_message(&self, msg_handle: u64) -> Result<(), String> {
        lxmf::message_send(self.router_handle, msg_handle)
    }

    // -------------------------------------------------------------------
    // Lifetime
    // -------------------------------------------------------------------

    /// Persist path table and cached data to disk.
    pub fn persist(&self) {
        rns::persist_data();
    }

    /// Shut down the client: destroy router, identity, and Reticulum transport.
    pub fn shutdown(&self) -> Result<(), String> {
        // Order matters: router first (closes links), then identity, then transport.
        lxmf::router_destroy(self.router_handle)?;
        rns::identity_destroy(self.identity_handle)?;
        rns::shutdown()
    }
}
