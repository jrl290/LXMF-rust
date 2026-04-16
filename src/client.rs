//! High-level LXMF client, composed on top of [`ReticulumClient`].
//!
//! `LxmfClient` adds the LXMF protocol layer (router, delivery endpoint,
//! ratchets, propagation sync, messaging) to a running Reticulum transport
//! instance.  Consumers supply a [`ClientConfig`] and optional callbacks.

use std::sync::Arc;

use reticulum_rust::client::{ReticulumClient, ReticulumConfig};

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

/// A running LXMF client.
///
/// Owns a [`ReticulumClient`] (transport + identity) and adds LXMF-specific
/// protocol state (router, delivery destination, ratchets).
pub struct LxmfClient {
    /// The underlying Reticulum transport client.
    pub rns: ReticulumClient,

    pub router_handle: u64,
    pub dest_handle: u64,

    /// The 16-byte LXMF delivery destination hash.
    pub dest_hash: Vec<u8>,
}

impl LxmfClient {
    /// Stand up the full Reticulum + LXMF stack.
    pub fn start(
        config: ClientConfig,
        callbacks: ClientCallbacks,
    ) -> Result<Self, String> {
        // 1–2. Init transport + identity via ReticulumClient
        let rns_config = ReticulumConfig {
            config_dir: config.config_dir,
            identity_path: config.identity_path,
            create_identity: config.create_identity,
            log_level: config.log_level,
        };
        let rns_client = ReticulumClient::start(rns_config)?;

        let dest_hash = rns_client.destination_hash("lxmf", &["delivery"])?;

        // 3. Create router + register delivery endpoint
        let router_handle = lxmf::router_create(
            rns_client.identity_handle,
            &config.lxmf_storage_path,
        )?;

        let display = if config.display_name.is_empty() {
            None
        } else {
            Some(config.display_name.as_str())
        };
        let dest_handle = lxmf::router_register_delivery(
            router_handle,
            rns_client.identity_handle,
            display,
            config.stamp_cost,
        )?;

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
            rns: rns_client,
            router_handle,
            dest_handle,
            dest_hash,
        })
    }

    /// Convenience: the 16-byte identity hash (delegated to ReticulumClient).
    pub fn identity_hash(&self) -> &[u8] {
        &self.rns.identity_hash
    }

    /// Convenience: the identity handle (delegated to ReticulumClient).
    pub fn identity_handle(&self) -> u64 {
        self.rns.identity_handle
    }

    // -------------------------------------------------------------------
    // Propagation
    // -------------------------------------------------------------------

    pub fn sync_from_propagation_node(
        &self,
        node_hash: &[u8],
    ) -> Result<(), String> {
        lxmf::router_set_propagation_node(self.router_handle, node_hash)?;
        lxmf::router_request_messages(self.router_handle, self.rns.identity_handle)
    }

    pub fn propagation_state(&self) -> Result<u8, String> {
        lxmf::router_get_propagation_state(self.router_handle)
    }

    pub fn propagation_progress(&self) -> Result<f64, String> {
        lxmf::router_get_propagation_progress(self.router_handle)
    }

    pub fn cancel_propagation(&self) -> Result<(), String> {
        lxmf::router_cancel_propagation(self.router_handle)
    }

    pub fn peer_link_status(&self, dest_hash: &[u8]) -> Result<u8, String> {
        lxmf::router_peer_link_status(self.router_handle, dest_hash)
    }

    // -------------------------------------------------------------------
    // App links
    // -------------------------------------------------------------------

    pub fn app_link_open(&self, dest_hash: &[u8]) -> Result<(), String> {
        lxmf::router_app_link_open(self.router_handle, dest_hash)
    }

    pub fn app_link_close(&self, dest_hash: &[u8]) -> Result<(), String> {
        lxmf::router_app_link_close(self.router_handle, dest_hash)
    }

    pub fn app_link_status(&self, dest_hash: &[u8]) -> Result<u8, String> {
        lxmf::router_app_link_status(self.router_handle, dest_hash)
    }

    // -------------------------------------------------------------------
    // Announce
    // -------------------------------------------------------------------

    pub fn announce(&self) -> Result<(), String> {
        lxmf::router_announce(self.router_handle, &self.dest_hash)
    }

    pub fn watch_destination(&self, dest_hash: &[u8]) -> Result<(), String> {
        lxmf::router_watch_destination(self.router_handle, dest_hash)
    }

    // -------------------------------------------------------------------
    // Outbound messages
    // -------------------------------------------------------------------

    pub fn process_outbound(&self) -> Result<(), String> {
        lxmf::router_process_outbound(self.router_handle)
    }

    // -------------------------------------------------------------------
    // Callbacks (set after start)
    // -------------------------------------------------------------------

    pub fn set_delivery_callback(
        &self,
        cb: Arc<dyn Fn(ReceivedMessage) + Send + Sync>,
    ) -> Result<(), String> {
        lxmf::router_set_delivery_callback(self.router_handle, cb)
    }

    pub fn set_announce_callback(
        &self,
        cb: Arc<dyn Fn(&[u8], Option<String>) + Send + Sync>,
    ) -> Result<(), String> {
        lxmf::router_set_announce_callback(self.router_handle, cb)
    }

    pub fn set_sync_complete_callback(
        &self,
        cb: Arc<dyn Fn(u32) + Send + Sync>,
    ) -> Result<(), String> {
        lxmf::router_set_sync_complete_callback(self.router_handle, cb)
    }

    pub fn set_message_state_callback(
        &self,
        cb: Arc<dyn Fn(&[u8], u8) + Send + Sync>,
    ) -> Result<(), String> {
        lxmf::router_set_message_state_callback(self.router_handle, cb)
    }

    // -------------------------------------------------------------------
    // Messages
    // -------------------------------------------------------------------

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
            self.rns.identity_handle,
        )
    }

    pub fn send_message(&self, msg_handle: u64) -> Result<(), String> {
        lxmf::message_send(self.router_handle, msg_handle)
    }

    // -------------------------------------------------------------------
    // Lifetime
    // -------------------------------------------------------------------

    /// Persist path table and cached data to disk.
    pub fn persist(&self) {
        self.rns.persist();
    }

    /// Shut down: destroy router, then delegate identity + transport to ReticulumClient.
    pub fn shutdown(&self) -> Result<(), String> {
        lxmf::router_destroy(self.router_handle)?;
        self.rns.shutdown()
    }
}
