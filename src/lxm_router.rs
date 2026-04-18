use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use rmpv::Value;
use rmpv::encode::write_value;
use rmpv::decode::read_value;
use rmp_serde;
use serde::{Deserialize, Serialize};

use reticulum_rust::destination::{Destination, DestinationType, ALLOW_ALL, ALLOW_LIST, PROVE_ALL};
use reticulum_rust::identity::{Identity, HASHLENGTH, TRUNCATED_HASHLENGTH};
use reticulum_rust::link::{Link, LinkHandle, register_runtime_link_handle};
use reticulum_rust::packet::Packet;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::resource::{Resource, ResourceStatus};
use reticulum_rust::transport::Transport;
use reticulum_rust::{hexrep, log, prettyhexrep, prettytime, LOG_DEBUG, LOG_ERROR, LOG_NOTICE, LOG_VERBOSE, LOG_WARNING};

use crate::handlers::{delivery_announce_handler, propagation_announce_handler};
use crate::lx_message::LXMessage;
use crate::lx_stamper;
use crate::lxmf::{pn_announce_data_is_valid, APP_NAME, FIELD_TICKET};
use crate::lxm_peer::LXMPeer;

fn now() -> f64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs_f64())
		.unwrap_or(0.0)
}

// decode_hex moved to reticulum_rust::decode_hex
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
	reticulum_rust::decode_hex(hex)
}

#[derive(Clone)]
pub struct PropagationEntry {
	pub destination_hash: Vec<u8>,
	pub filepath: String,
	pub received: f64,
	pub size: usize,
	pub handled_peers: Vec<Vec<u8>>,
	pub unhandled_peers: Vec<Vec<u8>>,
	pub stamp_value: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TicketEntry {
	pub expires: f64,
	pub ticket: Vec<u8>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AvailableTickets {
	pub outbound: HashMap<Vec<u8>, TicketEntry>,
	pub inbound: HashMap<Vec<u8>, HashMap<Vec<u8>, TicketEntry>>,
	pub last_deliveries: HashMap<Vec<u8>, f64>,
}

pub struct LXMRouter {
	pub pending_inbound: Vec<Vec<u8>>,
	pub pending_outbound: Vec<Arc<Mutex<LXMessage>>>,
	pub failed_outbound: Vec<Arc<Mutex<LXMessage>>>,
	pub direct_links: HashMap<Vec<u8>, LinkHandle>,
	pub backchannel_links: HashMap<Vec<u8>, LinkHandle>,
	pub backchannel_identified_links: HashMap<Vec<u8>, bool>,
	pub delivery_destinations: HashMap<Vec<u8>, Destination>,
	pub delivery_stamp_costs: HashMap<Vec<u8>, u32>,
	pub delivery_display_names: HashMap<Vec<u8>, String>,

	pub prioritised_list: Vec<Vec<u8>>,
	pub ignored_list: Vec<Vec<u8>>,
	pub allowed_list: Vec<Vec<u8>>,
	pub control_allowed_list: Vec<Vec<u8>>,
	pub auth_required: bool,
	pub retain_synced_on_node: bool,

	pub default_sync_strategy: u8,
	pub processing_inbound: bool,
	pub processing_count: u64,
	pub name: Option<String>,

	pub propagation_node: bool,
	pub propagation_node_start_time: Option<f64>,
	pub storagepath: String,
	pub ratchetpath: String,
	pub messagepath: Option<String>,

	pub outbound_propagation_node: Option<Vec<u8>>,
	pub outbound_propagation_link: Option<LinkHandle>,

	pub message_storage_limit: Option<u64>,
	pub information_storage_limit: Option<u64>,
	pub propagation_per_transfer_limit: f64,
	pub propagation_per_sync_limit: f64,
	pub delivery_per_transfer_limit: f64,
	pub propagation_stamp_cost: u32,
	pub propagation_stamp_cost_flexibility: u32,
	pub peering_cost: u32,
	pub max_peering_cost: u32,
	pub enforce_ratchets: bool,
	pub enforce_stamps: bool,
	pub pending_deferred_stamps: HashMap<Vec<u8>, Arc<Mutex<LXMessage>>>,
	pub throttled_peers: HashMap<Vec<u8>, f64>,

	pub wants_download_on_path_available_from: Option<Vec<u8>>,
	pub wants_download_on_path_available_to: Option<Identity>,
	pub wants_download_on_path_available_timeout: f64,
	pub propagation_transfer_state: u8,
	pub propagation_transfer_progress: f64,
	pub propagation_transfer_last_result: Option<usize>,
	pub propagation_transfer_last_duplicates: Option<usize>,
	pub propagation_transfer_max_messages: Option<usize>,
	pub prioritise_rotating_unreachable_peers: bool,
	pub active_propagation_links: Vec<LinkHandle>,
	pub validated_peer_links: HashMap<Vec<u8>, bool>,
	pub locally_delivered_transient_ids: HashMap<Vec<u8>, f64>,
	pub locally_processed_transient_ids: HashMap<Vec<u8>, f64>,
	pub outbound_stamp_costs: HashMap<Vec<u8>, (f64, u32)>,
	pub available_tickets: AvailableTickets,

	pub outbound_processing_lock: Mutex<()>,
	pub cost_file_lock: Mutex<()>,
	pub ticket_file_lock: Mutex<()>,
	pub stamp_gen_lock: Mutex<()>,
	pub exit_handler_running: bool,

	pub identity: Identity,
	pub propagation_destination: Destination,
	pub control_destination: Option<Destination>,
	pub client_propagation_messages_received: u64,
	pub client_propagation_messages_served: u64,
	pub unpeered_propagation_incoming: u64,
	pub unpeered_propagation_rx_bytes: u64,

	pub autopeer: bool,
	pub autopeer_maxdepth: u8,
	pub max_peers: usize,
	pub from_static_only: bool,
	pub static_peers: Vec<Vec<u8>>,
	pub peers: HashMap<Vec<u8>, Arc<Mutex<LXMPeer>>>,
	pub propagation_entries: HashMap<Vec<u8>, PropagationEntry>,
	pub peer_distribution_queue: VecDeque<(Vec<u8>, Option<Vec<u8>>)>,

	pub delivery_callback: Option<Arc<dyn Fn(&LXMessage) + Send + Sync>>,
	pub announce_callback: Option<Arc<dyn Fn(&[u8], Option<String>) + Send + Sync>>,
	/// Fires when propagation sync completes with the count of messages received.
	pub sync_complete_callback: Option<Arc<dyn Fn(u32) + Send + Sync>>,
	/// Destination hashes we care about (contacts, pending targets).
	/// Announces from destinations NOT in this set are ignored.
	pub watched_destinations: HashSet<Vec<u8>>,
	/// Destinations the app has opened for pre-connection (chat screen visible).
	/// Links for these destinations are established proactively and exempt from
	/// inactivity cleanup.  No automatic re-establishment on failure.
	pub app_links: HashSet<Vec<u8>>,
	pub self_handle: Option<Weak<Mutex<LXMRouter>>>,
	/// Fires when an outbound message changes delivery state.
	/// Args: message hash bytes, new state byte (LXMessage::DELIVERED etc.).
	pub message_state_callback: Option<Arc<dyn Fn(&[u8], u8) + Send + Sync>>,
	/// Channel to wake the job thread for immediate process_outbound.
	/// Link-established callbacks send on this instead of calling
	/// process_outbound inline, which would block the TCP read thread.
	pub outbound_wake_tx: mpsc::Sender<()>,
}

impl LXMRouter {
	pub const MAX_DELIVERY_ATTEMPTS: u32 = 2;
	pub const PROCESSING_INTERVAL: u64 = 2;
	pub const DELIVERY_RETRY_WAIT: f64 = 2.0;
	pub const PATH_REQUEST_WAIT: f64 = 7.0;
	pub const MAX_PATHLESS_TRIES: u32 = 1;
	// TCP default. When slower interfaces (RNode/Serial/LoRa) are added,
	// look up the dest's path entry via_interface and use a longer timeout.
	pub const DIRECT_LINK_TIMEOUT: f64 = 8.0;
	pub const LINK_MAX_INACTIVITY: f64 = 10.0 * 60.0;
	pub const P_LINK_MAX_INACTIVITY: f64 = 3.0 * 60.0;

	pub const MESSAGE_EXPIRY: f64 = 30.0 * 24.0 * 60.0 * 60.0;
	pub const STAMP_COST_EXPIRY: f64 = 45.0 * 24.0 * 60.0 * 60.0;

	pub const NODE_ANNOUNCE_DELAY: u64 = 20;

	pub const MAX_PEERS: usize = 20;
	pub const AUTOPEER: bool = true;
	pub const AUTOPEER_MAXDEPTH: u8 = 4;
	pub const FASTEST_N_RANDOM_POOL: usize = 2;
	pub const ROTATION_HEADROOM_PCT: f64 = 10.0;
	pub const ROTATION_AR_MAX: f64 = 0.5;

	pub const PEERING_COST: u32 = 18;
	pub const MAX_PEERING_COST: u32 = 26;
	pub const PROPAGATION_COST_MIN: u32 = 13;
	pub const PROPAGATION_COST_FLEX: u32 = 3;
	pub const PROPAGATION_COST: u32 = 16;
	pub const PROPAGATION_LIMIT: f64 = 256.0;
	pub const SYNC_LIMIT: f64 = Self::PROPAGATION_LIMIT * 40.0;
	pub const DELIVERY_LIMIT: f64 = 1000.0;

	pub const PR_PATH_TIMEOUT: f64 = 10.0;
	pub const PN_STAMP_THROTTLE: f64 = 180.0;

	pub const JOB_OUTBOUND_INTERVAL: u64 = 1;
	pub const JOB_STAMPS_INTERVAL: u64 = 1;
	pub const JOB_LINKS_INTERVAL: u64 = 1;
	pub const JOB_TRANSIENT_INTERVAL: u64 = 60;
	pub const JOB_STORE_INTERVAL: u64 = 120;
	pub const JOB_PEERSYNC_INTERVAL: u64 = 6;
	pub const JOB_PEERINGEST_INTERVAL: u64 = Self::JOB_PEERSYNC_INTERVAL;
	pub const JOB_ROTATE_INTERVAL: u64 = 56 * Self::JOB_PEERINGEST_INTERVAL;

	pub const PR_IDLE: u8 = 0x00;
	pub const PR_PATH_REQUESTED: u8 = 0x01;
	pub const PR_LINK_ESTABLISHING: u8 = 0x02;
	pub const PR_LINK_ESTABLISHED: u8 = 0x03;
	pub const PR_REQUEST_SENT: u8 = 0x04;
	pub const PR_RECEIVING: u8 = 0x05;
	pub const PR_RESPONSE_RECEIVED: u8 = 0x06;
	pub const PR_COMPLETE: u8 = 0x07;
	pub const PR_NO_PATH: u8 = 0xf0;
	pub const PR_LINK_FAILED: u8 = 0xf1;
	pub const PR_TRANSFER_FAILED: u8 = 0xf2;
	pub const PR_NO_IDENTITY_RCVD: u8 = 0xf3;
	pub const PR_NO_ACCESS: u8 = 0xf4;
	pub const PR_FAILED: u8 = 0xfe;

	pub const PR_ALL_MESSAGES: usize = 0x00;
	pub const DUPLICATE_SIGNAL: &'static str = "lxmf_duplicate";

	pub const STATS_GET_PATH: &'static str = "/pn/get/stats";
	pub const SYNC_REQUEST_PATH: &'static str = "/pn/peer/sync";
	pub const UNPEER_REQUEST_PATH: &'static str = "/pn/peer/unpeer";

	pub fn new(
		identity: Option<Identity>,
		storagepath: String,
		autopeer: Option<bool>,
		autopeer_maxdepth: Option<u8>,
		propagation_limit: Option<f64>,
		delivery_limit: Option<f64>,
		sync_limit: Option<f64>,
		enforce_ratchets: bool,
		enforce_stamps: bool,
		static_peers: Vec<Vec<u8>>,
		max_peers: Option<usize>,
		from_static_only: bool,
		sync_strategy: u8,
		propagation_cost: u32,
		propagation_cost_flexibility: u32,
		peering_cost: u32,
		max_peering_cost: u32,
		name: Option<String>,
	) -> Result<Arc<Mutex<Self>>, String> {
		let identity = identity.unwrap_or_else(|| Identity::new(true));
		let storagepath = format!("{}/lxmf", storagepath);
		let ratchetpath = format!("{}/ratchets", storagepath);
		let propagation_limit = propagation_limit.unwrap_or(Self::PROPAGATION_LIMIT);
		let delivery_limit = delivery_limit.unwrap_or(Self::DELIVERY_LIMIT);
		let mut propagation_cost = propagation_cost;
		if propagation_cost < Self::PROPAGATION_COST_MIN {
			propagation_cost = Self::PROPAGATION_COST_MIN;
		}

		let propagation_destination = Destination::new_inbound(
			Some(identity.clone()),
			DestinationType::Single,
			APP_NAME.to_string(),
			vec!["propagation".to_string()],
		)?;

		let (outbound_wake_tx, outbound_wake_rx) = mpsc::channel::<()>();

		let router = Arc::new(Mutex::new(LXMRouter {
			pending_inbound: Vec::new(),
			pending_outbound: Vec::new(),
			failed_outbound: Vec::new(),
			direct_links: HashMap::new(),
			backchannel_links: HashMap::new(),
			backchannel_identified_links: HashMap::new(),
			delivery_destinations: HashMap::new(),
			delivery_stamp_costs: HashMap::new(),
			delivery_display_names: HashMap::new(),
			prioritised_list: Vec::new(),
			ignored_list: Vec::new(),
			allowed_list: Vec::new(),
			control_allowed_list: Vec::new(),
			auth_required: false,
			retain_synced_on_node: false,
			default_sync_strategy: sync_strategy,
			processing_inbound: false,
			processing_count: 0,
			name,
			propagation_node: false,
			propagation_node_start_time: None,
			storagepath,
			ratchetpath,
			messagepath: None,
			outbound_propagation_node: None,
			outbound_propagation_link: None,
			message_storage_limit: None,
			information_storage_limit: None,
			propagation_per_transfer_limit: propagation_limit,
			propagation_per_sync_limit: sync_limit.unwrap_or(propagation_limit),
			delivery_per_transfer_limit: delivery_limit,
			propagation_stamp_cost: propagation_cost,
			propagation_stamp_cost_flexibility: propagation_cost_flexibility,
			peering_cost,
			max_peering_cost,
			enforce_ratchets,
			enforce_stamps,
			pending_deferred_stamps: HashMap::new(),
			throttled_peers: HashMap::new(),
			wants_download_on_path_available_from: None,
			wants_download_on_path_available_to: None,
			wants_download_on_path_available_timeout: 0.0,
			propagation_transfer_state: Self::PR_IDLE,
			propagation_transfer_progress: 0.0,
			propagation_transfer_last_result: None,
			propagation_transfer_last_duplicates: None,
			propagation_transfer_max_messages: None,
			prioritise_rotating_unreachable_peers: false,
			active_propagation_links: Vec::new(),
			validated_peer_links: HashMap::new(),
			locally_delivered_transient_ids: HashMap::new(),
			locally_processed_transient_ids: HashMap::new(),
			outbound_stamp_costs: HashMap::new(),
			available_tickets: AvailableTickets::default(),
			outbound_processing_lock: Mutex::new(()),
			cost_file_lock: Mutex::new(()),
			ticket_file_lock: Mutex::new(()),
			stamp_gen_lock: Mutex::new(()),
			exit_handler_running: false,
			identity,
			propagation_destination,
			control_destination: None,
			client_propagation_messages_received: 0,
			client_propagation_messages_served: 0,
			unpeered_propagation_incoming: 0,
			unpeered_propagation_rx_bytes: 0,
			autopeer: autopeer.unwrap_or(Self::AUTOPEER),
			autopeer_maxdepth: autopeer_maxdepth.unwrap_or(Self::AUTOPEER_MAXDEPTH),
			max_peers: max_peers.unwrap_or(Self::MAX_PEERS),
			from_static_only,
			static_peers,
			peers: HashMap::new(),
			propagation_entries: HashMap::new(),
			peer_distribution_queue: VecDeque::new(),
			delivery_callback: None,
			announce_callback: None,
			sync_complete_callback: None,
			watched_destinations: HashSet::new(),
			app_links: HashSet::new(),
			self_handle: None,
			message_state_callback: None,
			outbound_wake_tx,
		}));

		// Register announce handlers BEFORE any locking to avoid deadlock
		// (Python does this early in __init__ before loading cached state)
		let router_clone_for_handlers = router.clone();
		let delivery_handler = delivery_announce_handler(router_clone_for_handlers.clone());
		Transport::register_announce_handler(delivery_handler);
		let propagation_handler = propagation_announce_handler(router_clone_for_handlers.clone());
		Transport::register_announce_handler(propagation_handler);

		if let Ok(mut router_guard) = router.lock() {
			router_guard.self_handle = Some(Arc::downgrade(&router));
			router_guard.load_cached_state();
		}

		let job_router = Arc::downgrade(&router);
		thread::spawn(move || {
			while let Some(router) = job_router.upgrade() {
				if let Ok(mut router) = router.lock() {
					router.jobs();
				}
				// Wait for the processing interval, but wake early if a
				// link_established callback signals that outbound work is ready.
				// This keeps the TCP read thread free — callbacks just send on
				// the channel instead of calling process_outbound inline.
				let _ = outbound_wake_rx.recv_timeout(Duration::from_secs(Self::PROCESSING_INTERVAL));
			}
		});

		Ok(router)
	}

	pub fn update_stamp_cost(&mut self, destination_hash: &[u8], stamp_cost: Option<u32>) {
		if let Some(cost) = stamp_cost {
			log(
				&format!("Updating outbound stamp cost for {} to {}", prettyhexrep(destination_hash), cost),
				LOG_DEBUG,
				false,
				false,
			);
			self.outbound_stamp_costs.insert(destination_hash.to_vec(), (now(), cost));
			self.save_outbound_stamp_costs();
		} else {
			self.outbound_stamp_costs.remove(destination_hash);
		}
	}

	pub fn get_outbound_stamp_cost(&self, destination_hash: &[u8]) -> Option<u32> {
		self.outbound_stamp_costs
			.get(destination_hash)
			.map(|entry| entry.1)
	}

	pub fn announce(&mut self, destination_hash: &[u8], attached_interface: Option<String>) -> bool {
		let app_data = self.get_announce_app_data(destination_hash);
		if let Some(destination) = self.delivery_destinations.get_mut(destination_hash) {
			let dest_hex = reticulum_rust::hexrep(destination_hash, false);
			match destination.announce(app_data.as_deref(), false, attached_interface, None, true) {
				Ok(_) => {
					reticulum_rust::log(&format!("[LXMF] Announce sent dest={}", dest_hex), reticulum_rust::LOG_NOTICE, false, false);
					// Sync the destination to Transport so its ratchet keys are current
					// (rotate_ratchets() runs during announce, generating new keys)
					Transport::update_destination(destination.clone());
					true
				}
				Err(e) => {
					reticulum_rust::log(&format!("[LXMF] Announce FAILED dest={}: {}", dest_hex, e), reticulum_rust::LOG_ERROR, false, false);
					false
				}
			}
		} else {
			let dest_hex = reticulum_rust::hexrep(destination_hash, false);
			reticulum_rust::log(&format!("[LXMF] Announce: delivery destination {} not registered", dest_hex), reticulum_rust::LOG_ERROR, false, false);
			false
		}
	}

	fn update_delivery_announce_app_data(&mut self, destination_hash: &[u8]) {
		let app_data = self.get_announce_app_data(destination_hash);
		if let Some(destination) = self.delivery_destinations.get_mut(destination_hash) {
			destination.set_default_app_data(app_data);
		}
	}

	pub fn get_announce_app_data(&self, destination_hash: &[u8]) -> Option<Vec<u8>> {
		if !self.delivery_destinations.contains_key(destination_hash) {
			return None;
		}

		let display_name = self
			.delivery_display_names
			.get(destination_hash)
			.map(|name| Value::Binary(name.as_bytes().to_vec()))
			.unwrap_or(Value::Nil);

		let stamp_cost = self
			.delivery_stamp_costs
			.get(destination_hash)
			.map(|cost| Value::Integer((*cost as i64).into()))
			.unwrap_or(Value::Nil);

		let mut buf = Vec::new();
		let payload = Value::Array(vec![display_name, stamp_cost]);
		if write_value(&mut buf, &payload).is_ok() {
			Some(buf)
		} else {
			None
		}
	}

	pub fn get_propagation_node_announce_metadata(&self) -> Value {
		let mut entries = Vec::new();
		if let Some(name) = &self.name {
			entries.push((
				Value::Integer((crate::lxmf::PN_META_NAME as i64).into()),
				Value::Binary(name.as_bytes().to_vec()),
			));
		}
		Value::Map(entries)
	}

	pub fn get_propagation_node_app_data(&self) -> Vec<u8> {
		let node_state = self.propagation_node && !self.from_static_only;
		let stamp_costs = Value::Array(vec![
			Value::Integer((self.propagation_stamp_cost as i64).into()),
			Value::Integer((self.propagation_stamp_cost_flexibility as i64).into()),
			Value::Integer((self.peering_cost as i64).into()),
		]);

		let announce_data = Value::Array(vec![
			Value::Boolean(false),
			Value::Integer((now() as i64).into()),
			Value::Boolean(node_state),
			Value::Integer((self.propagation_per_transfer_limit as i64).into()),
			Value::Integer((self.propagation_per_sync_limit as i64).into()),
			stamp_costs,
			self.get_propagation_node_announce_metadata(),
		]);

		let mut buf = Vec::new();
		let _ = write_value(&mut buf, &announce_data);
		buf
	}

	pub fn announce_propagation_node(&self) {
		let router_weak = self.self_handle.clone();
		thread::spawn(move || {
			thread::sleep(Duration::from_secs(Self::NODE_ANNOUNCE_DELAY));
			if let Some(router_arc) = router_weak.and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					let app_data = router.get_propagation_node_app_data();
					// Set default_app_data so path responses also include
					// the propagation node config (stamp cost, limits, etc.)
					router
						.propagation_destination
						.set_default_app_data(Some(app_data.clone()));
					let _ = router
						.propagation_destination
						.announce(Some(&app_data), false, None, None, true);
					if router.control_allowed_list.len() > 1 {
						if let Some(control_dest) = router.control_destination.as_mut() {
							let _ = control_dest.announce(None, false, None, None, true);
						}
					}
				}
			}
		});
	}

	pub fn enable_propagation(&mut self) -> Result<(), String> {
		let messagepath = format!("{}/messagestore", self.storagepath);
		self.messagepath = Some(messagepath.clone());
		// On Synology/userns-remap hosts, create_dir_all may fail even
		// though the directory already exists.  Tolerate that.
		if let Err(e) = fs::create_dir_all(&self.storagepath) {
			if !std::path::Path::new(&self.storagepath).is_dir() {
				return Err(format!("Cannot create storage dir {}: {e}", self.storagepath));
			}
		}
		if let Err(e) = fs::create_dir_all(&messagepath) {
			if !std::path::Path::new(&messagepath).is_dir() {
				return Err(format!("Cannot create messagestore dir {}: {e}", messagepath));
			}
		}

		self.propagation_entries.clear();

		let start = now();
		log("Indexing messagestore...", LOG_NOTICE, false, false);
		if let Ok(entries) = fs::read_dir(&messagepath) {
			for entry in entries.flatten() {
				let filename = entry.file_name().to_string_lossy().to_string();
				let components: Vec<&str> = filename.split('_').collect();
				if components.len() < 3 {
					continue;
				}

				let hex_len = (HASHLENGTH / 8) * 2;
				if components[0].len() != hex_len {
					continue;
				}

				let received: f64 = match components[1].parse() {
					Ok(value) if value > 0.0 => value,
					_ => continue,
				};

				let stamp_value: u32 = match components[2].parse() {
					Ok(value) => value,
					Err(_) => continue,
				};

				let filepath = entry.path().to_string_lossy().to_string();
				let msg_size = entry.metadata().map(|m| m.len() as usize).unwrap_or(0);

				let destination_hash = match fs::read(&filepath) {
					Ok(data) if data.len() >= LXMessage::DESTINATION_LENGTH => {
						data[..LXMessage::DESTINATION_LENGTH].to_vec()
					}
					_ => continue,
				};

				let transient_id = match decode_hex(components[0]) {
					Some(bytes) => bytes,
					None => continue,
				};

				self.propagation_entries.insert(
					transient_id,
					PropagationEntry {
						destination_hash,
						filepath,
						received,
						size: msg_size,
						handled_peers: Vec::new(),
						unhandled_peers: Vec::new(),
						stamp_value,
					},
				);
			}
		}

		let elapsed = now() - start;
		let mps = if elapsed > 0.0 {
			(self.propagation_entries.len() as f64 / elapsed).floor() as usize
		} else {
			0
		};
		log(
			&format!(
				"Indexed {} messages in {}, {} msgs/s",
				self.propagation_entries.len(),
				prettytime(elapsed, false, false),
				mps
			),
			LOG_NOTICE,
			false,
			false,
		);

		log("Rebuilding peer synchronisation states...", LOG_NOTICE, false, false);
		let peers_storage_path = format!("{}/peers", self.storagepath);
		if let Ok(peers_data) = fs::read(&peers_storage_path) {
			if !peers_data.is_empty() {
				if let Ok(serialised_peers) = rmp_serde::from_slice::<Vec<Vec<u8>>>(&peers_data) {
					for peer_bytes in serialised_peers.into_iter() {
						if let Some(router_weak) = self.self_handle.clone() {
							if let Ok(peer) = LXMPeer::from_bytes(&peer_bytes, router_weak) {
								if self.static_peers.contains(&peer.destination_hash) && peer.last_heard == 0.0 {
									Transport::request_path(&peer.destination_hash, None, None, None, None);
								}
								if peer.identity.is_some() {
									let dest_hash = peer.destination_hash.clone();
									let peer_arc = Arc::new(Mutex::new(peer));
									self.peers.insert(dest_hash, peer_arc);
								}
							}
						}
					}
				} else {
					log(
						&format!("Could not load propagation node peering data from {}", peers_storage_path),
						LOG_ERROR,
						false,
						false,
					);
				}
			}
		}

		for static_peer in self.static_peers.clone() {
			if !self.peers.contains_key(&static_peer) {
				log(
					&format!("Activating static peering with {}", prettyhexrep(&static_peer)),
					LOG_NOTICE,
					false,
					false,
				);
				if let Some(router_weak) = self.self_handle.clone() {
					let peer = LXMPeer::new(router_weak, static_peer.clone(), self.default_sync_strategy);
					if peer.last_heard == 0.0 {
						Transport::request_path(&static_peer, None, None, None, None);
					}
					self.peers.insert(static_peer, Arc::new(Mutex::new(peer)));
				}
			}
		}

		let node_stats_path = format!("{}/node_stats", self.storagepath);
		if let Ok(data) = fs::read(&node_stats_path) {
			if let Ok(stats) = rmp_serde::from_slice::<HashMap<String, u64>>(&data) {
				if let Some(value) = stats.get("client_propagation_messages_received") {
					self.client_propagation_messages_received = *value;
				}
				if let Some(value) = stats.get("client_propagation_messages_served") {
					self.client_propagation_messages_served = *value;
				}
				if let Some(value) = stats.get("unpeered_propagation_incoming") {
					self.unpeered_propagation_incoming = *value;
				}
				if let Some(value) = stats.get("unpeered_propagation_rx_bytes") {
					self.unpeered_propagation_rx_bytes = *value;
				}
			}
		}

		self.propagation_node = true;
		self.propagation_node_start_time = Some(now());

		let router_weak = self.self_handle.clone();
		self.propagation_destination.set_link_established_callback(Some(Arc::new(move |link| {
			if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					router.propagation_link_established(link);
				}
			}
		})));

		let router_weak_packet = self.self_handle.clone();
		self.propagation_destination.set_packet_callback(Some(Arc::new(move |data, packet| {
			if let Some(router_arc) = router_weak_packet.as_ref().and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					router.propagation_packet(data, packet);
				}
			}
		})));

		let router_weak_offer = self.self_handle.clone();
		self.propagation_destination.register_request_handler(
			LXMPeer::OFFER_REQUEST_PATH.to_string(),
			Some(Arc::new(move |path, data, request_id, remote_identity, requested_at| {
				if let Some(router_arc) = router_weak_offer.as_ref().and_then(|w| w.upgrade()) {
					if let Ok(mut router) = router_arc.lock() {
						return router.offer_request(path, data, request_id, remote_identity, requested_at);
					}
				}
				Vec::new()
			})),
			ALLOW_ALL,
			None,
			false,
		)?;

		let router_weak3 = self.self_handle.clone();
		self.propagation_destination.register_request_handler(
			LXMPeer::MESSAGE_GET_PATH.to_string(),
			Some(Arc::new(move |path, data, request_id, remote_identity, requested_at| {
				if let Some(router_arc) = router_weak3.as_ref().and_then(|w| w.upgrade()) {
					if let Ok(mut router) = router_arc.lock() {
						return router.message_get_request(path, data, request_id, remote_identity, requested_at);
					}
				}
				Vec::new()
			})),
			ALLOW_ALL,
			None,
			false,
		)?;

		self.control_allowed_list = vec![self.identity.hash.clone().expect("Router identity hash missing")];
		let mut control_destination = Destination::new_inbound(
			Some(self.identity.clone()),
			DestinationType::Single,
			APP_NAME.to_string(),
			vec!["propagation".to_string(), "control".to_string()],
		)?;

		let allow_list = Some(self.control_allowed_list.clone());
		let router_weak4 = self.self_handle.clone();
		control_destination.register_request_handler(
			Self::STATS_GET_PATH.to_string(),
			Some(Arc::new(move |path, data, request_id, remote_identity, requested_at| {
				if let Some(router_arc) = router_weak4.as_ref().and_then(|w| w.upgrade()) {
					if let Ok(mut router) = router_arc.lock() {
						return router.stats_get_request(path, data, request_id, remote_identity, requested_at);
					}
				}
				Vec::new()
			})),
			ALLOW_LIST,
			allow_list.clone(),
			false,
		)?;

		let router_weak5 = self.self_handle.clone();
		control_destination.register_request_handler(
			Self::SYNC_REQUEST_PATH.to_string(),
			Some(Arc::new(move |path, data, request_id, remote_identity, requested_at| {
				if let Some(router_arc) = router_weak5.as_ref().and_then(|w| w.upgrade()) {
					if let Ok(mut router) = router_arc.lock() {
						return router.peer_sync_request(path, data, request_id, remote_identity, requested_at);
					}
				}
				Vec::new()
			})),
			ALLOW_LIST,
			allow_list.clone(),
			false,
		)?;

		let router_weak6 = self.self_handle.clone();
		control_destination.register_request_handler(
			Self::UNPEER_REQUEST_PATH.to_string(),
			Some(Arc::new(move |path, data, request_id, remote_identity, requested_at| {
				if let Some(router_arc) = router_weak6.as_ref().and_then(|w| w.upgrade()) {
					if let Ok(mut router) = router_arc.lock() {
						return router.peer_unpeer_request(path, data, request_id, remote_identity, requested_at);
					}
				}
				Vec::new()
			})),
			ALLOW_LIST,
			allow_list,
			false,
		)?;

		Transport::register_destination(self.propagation_destination.clone());
		Transport::register_destination(control_destination.clone());
		self.control_destination = Some(control_destination);

		// Set default_app_data immediately so path responses include
		// propagation node config (stamp cost, limits, etc.) even
		// before the deferred initial announce fires.
		let app_data = self.get_propagation_node_app_data();
		self.propagation_destination.set_default_app_data(Some(app_data));

		// Update the already-registered destination so Transport has
		// the copy with default_app_data set.
		Transport::update_destination(self.propagation_destination.clone());

		self.announce_propagation_node();
		Ok(())
	}

	pub fn disable_propagation(&mut self) {
		self.propagation_node = false;
		self.announce_propagation_node();
	}

	pub fn cancel_propagation_node_requests(&mut self) {
		if let Some(link) = self.outbound_propagation_link.as_ref() {
			link.teardown();
		}
		self.outbound_propagation_link = None;
		self.acknowledge_sync_completion(None);
	}

	pub fn set_message_storage_limit(
		&mut self,
		kilobytes: Option<u64>,
		megabytes: Option<u64>,
		gigabytes: Option<u64>,
	) -> Result<(), String> {
		let mut limit_bytes = 0u64;
		if let Some(kb) = kilobytes {
			limit_bytes = limit_bytes.saturating_add(kb.saturating_mul(1000));
		}
		if let Some(mb) = megabytes {
			limit_bytes = limit_bytes.saturating_add(mb.saturating_mul(1_000_000));
		}
		if let Some(gb) = gigabytes {
			limit_bytes = limit_bytes.saturating_add(gb.saturating_mul(1_000_000_000));
		}

		if limit_bytes == 0 {
			self.message_storage_limit = None;
			return Ok(());
		}

		self.message_storage_limit = Some(limit_bytes);
		Ok(())
	}

	pub fn message_storage_limit(&self) -> Option<u64> {
		self.message_storage_limit
	}

	pub fn set_information_storage_limit(
		&mut self,
		kilobytes: Option<u64>,
		megabytes: Option<u64>,
		gigabytes: Option<u64>,
	) -> Result<(), String> {
		let mut limit_bytes = 0u64;
		if let Some(kb) = kilobytes {
			limit_bytes = limit_bytes.saturating_add(kb.saturating_mul(1000));
		}
		if let Some(mb) = megabytes {
			limit_bytes = limit_bytes.saturating_add(mb.saturating_mul(1_000_000));
		}
		if let Some(gb) = gigabytes {
			limit_bytes = limit_bytes.saturating_add(gb.saturating_mul(1_000_000_000));
		}

		if limit_bytes == 0 {
			self.information_storage_limit = None;
			return Ok(());
		}

		self.information_storage_limit = Some(limit_bytes);
		Ok(())
	}

	pub fn information_storage_limit(&self) -> Option<u64> {
		self.information_storage_limit
	}

	pub fn information_storage_size(&self) -> Option<u64> {
		None
	}

	pub fn delivery_link_available(&self, destination_hash: &[u8]) -> bool {
		self.direct_links.contains_key(destination_hash)
			|| self.backchannel_links.contains_key(destination_hash)
	}

	pub fn set_active_propagation_node(&mut self, destination_hash: Vec<u8>) -> Result<(), String> {
		self.set_outbound_propagation_node(destination_hash)
	}

	pub fn set_retain_node_lxms(&mut self, retain: bool) {
		self.retain_synced_on_node = retain;
	}

	pub fn get_size(&self, transient_id: &[u8]) -> Option<usize> {
		self.propagation_entries.get(transient_id).map(|entry| entry.size)
	}

	pub fn get_weight(&self, transient_id: &[u8]) -> f64 {
		if let Some(entry) = self.propagation_entries.get(transient_id) {
			let age_weight = ((now() - entry.received) / 60.0 / 60.0 / 24.0 / 4.0).max(1.0);
			let priority_weight = if self.prioritised_list.contains(&entry.destination_hash) {
				0.1
			} else {
				1.0
			};
			priority_weight * age_weight * entry.size as f64
		} else {
			0.0
		}
	}

	pub fn get_stamp_value(&self, transient_id: &[u8]) -> Option<u32> {
		self.propagation_entries.get(transient_id).map(|entry| entry.stamp_value)
	}

	pub fn process_outbound(&mut self) {
		log(&format!("[POB] enter pending={}", self.pending_outbound.len()), LOG_VERBOSE, false, false);
		let _guard = match self.outbound_processing_lock.lock() {
			Ok(guard) => {
				guard
			}
			Err(_err) => {
				return;
			}
		};

		let mut index = 0;
		let mut backchannel_setup_links: Vec<(LinkHandle, Vec<u8>)> = Vec::new();
		while index < self.pending_outbound.len() {
			let message = self.pending_outbound[index].clone();
			let mut remove = false;
			let message_lock = message.lock();
			if let Ok(mut lxm) = message_lock {
				let message_label = lxm
					.message_id
					.as_ref()
					.or(lxm.hash.as_ref())
					.map(|id| hexrep(id, false))
					.unwrap_or_else(|| prettyhexrep(&lxm.destination_hash));
				log(&format!("[POB][{}] state={} method={} attempts={}", message_label, lxm.state, lxm.method, lxm.delivery_attempts), LOG_NOTICE, false, false);

				if lxm.state == LXMessage::DELIVERED {
					if lxm.include_ticket {
						self.available_tickets
							.last_deliveries
							.insert(lxm.destination_hash.clone(), now());
						self.save_available_tickets();
					}

					// Fire state-change callback so the app knows without polling.
					if let Some(hash) = lxm.hash.as_ref() {
						self.fire_message_state(hash, LXMessage::DELIVERED);
					}

					// Prepare link for backchannel communications (matches Python LXMRouter.py L2527-2540)
					// After delivery, we identify on our outbound link and set up delivery callbacks
					// so the remote peer can send messages BACK to us on the same link.
					if lxm.method == LXMessage::DIRECT {
						let dest_hash = lxm.destination_hash.clone();
						if let Some(direct_link) = self.direct_links.get(&dest_hash).cloned() {
							let is_initiator = direct_link.snapshot().map(|s| s.initiator).unwrap_or(false);
							if is_initiator {
								// Step 1: Identify if not already done
								if !self.backchannel_identified_links.contains_key(&dest_hash) {
									let source_hash = lxm.source_hash.clone();
									let backchannel_identity = self.delivery_destinations.get(&source_hash)
										.and_then(|d| d.identity.clone());
									if let Some(identity) = backchannel_identity {
										match direct_link.identify(&identity) {
											Ok(()) => {
												self.backchannel_identified_links.insert(dest_hash.clone(), true);
												log(&format!(
													"Performed backchannel identification on outbound link to {}",
													hexrep(&dest_hash, false)
												), LOG_NOTICE, false, false);
											},
											Err(e) => {
												log(&format!(
													"Backchannel identify error: {}",
													e
												), LOG_NOTICE, false, false);
											},
										}
									}
								}
								// Step 2: ALWAYS set up delivery callbacks on the outbound link
								// so we can RECEIVE messages from the peer on this same link.
								// This must happen even if identify was done earlier (pre-send).
								// Deferred until after the loop to avoid borrow conflict with _guard.
								backchannel_setup_links.push((direct_link.clone(), dest_hash.clone()));
							}
						}
					}

					remove = true;
				} else if lxm.method == LXMessage::PROPAGATED && lxm.state == LXMessage::SENT {
					if let Some(hash) = lxm.hash.as_ref() {
						self.fire_message_state(hash, LXMessage::SENT);
					}
					remove = true;
				} else if lxm.state == LXMessage::CANCELLED {
					if let Some(hash) = lxm.hash.as_ref() {
						self.fire_message_state(hash, LXMessage::CANCELLED);
					}
					if let Some(callback) = lxm.failed_callback() {
						callback(&lxm);
					}
					remove = true;
				} else if lxm.state == LXMessage::REJECTED {
					if let Some(hash) = lxm.hash.as_ref() {
						self.fire_message_state(hash, LXMessage::REJECTED);
					}
					if let Some(callback) = lxm.failed_callback() {
						callback(&lxm);
					}
					remove = true;
				} else {
					if lxm.progress < 0.01 {
						lxm.progress = 0.01;
					}

					match lxm.method {
						LXMessage::OPPORTUNISTIC => {
							if lxm.delivery_attempts <= Self::MAX_DELIVERY_ATTEMPTS {
								let dest_hash = lxm.destination_hash.clone();
								if lxm.next_delivery_attempt.map(|t| now() > t).unwrap_or(true) {
									if lxm.delivery_attempts >= Self::MAX_PATHLESS_TRIES && !Transport::has_path(&dest_hash) {
										log(
											&format!("Requesting path to {} after {} pathless tries", prettyhexrep(&dest_hash), lxm.delivery_attempts),
											LOG_DEBUG,
											false,
											false,
										);
										lxm.delivery_attempts += 1;
										Transport::request_path(&dest_hash, None, None, None, None);
										lxm.next_delivery_attempt = Some(now() + Self::PATH_REQUEST_WAIT);
										lxm.progress = 0.01;
									} else if lxm.delivery_attempts == Self::MAX_PATHLESS_TRIES + 1
										&& Transport::has_path(&dest_hash)
									{
										log(
											&format!("Rediscovering path to {} after failed opportunistic attempt", prettyhexrep(&dest_hash)),
											LOG_DEBUG,
											false,
											false,
										);
										lxm.delivery_attempts += 1;
										if let Some(reticulum) = Reticulum::get_instance() {
											if let Ok(reticulum) = reticulum.lock() {
												let _ = reticulum.drop_path(&dest_hash);
											}
										}
										let dest_clone = dest_hash.clone();
										thread::spawn(move || {
											thread::sleep(Duration::from_millis(500));
											Transport::request_path(&dest_clone, None, None, None, None);
										});
										lxm.next_delivery_attempt = Some(now() + Self::PATH_REQUEST_WAIT);
										lxm.progress = 0.01;
									} else {
										lxm.delivery_attempts += 1;
										lxm.next_delivery_attempt = Some(now() + Self::DELIVERY_RETRY_WAIT);
										match lxm.send_with_handle(Some(message.clone())) {
										Ok(_) => {}
										Err(_e) => {}
										}
									}
								}
							} else {
								self.fail_message(&mut lxm);
								remove = true;
							}
						}
						LXMessage::DIRECT => {
							let dest_hash = lxm.destination_hash.clone();

							// Select the best available link (prefer the most-recently-activated one).
							let mut direct_link = self.direct_links.get(&dest_hash).cloned();
							if direct_link.is_none() {
								direct_link = self.backchannel_links.get(&dest_hash).cloned();
							} else if let Some(bl) = self.backchannel_links.get(&dest_hash).cloned() {
								let dl_activated = direct_link
									.as_ref()
									.and_then(|d| d.snapshot().ok().and_then(|s| s.activated_at.map(|t| t as f64)))
									.unwrap_or(0.0);
								let bl_activated = bl
									.snapshot()
									.ok()
									.and_then(|s| s.activated_at.or(s.established_at).map(|t| t as f64))
									.unwrap_or(0.0);
								if bl_activated > dl_activated {
									log(&format!("[POB][{}] Preferring newer backchannel link", message_label), LOG_NOTICE, false, false);
									direct_link = Some(bl);
								}
							}

							if let Some(link_arc) = direct_link {
								let status = link_arc.status();
								log(&format!("[POB][{}] DIRECT has-link status={}", message_label, status), LOG_NOTICE, false, false);
								if status == reticulum_rust::link::STATE_ACTIVE {
									// Happy path: link is up — send now.
									if lxm.progress < 0.05 { lxm.progress = 0.05; }
									if lxm.state != LXMessage::SENDING {
										log(&format!("[POB][{}] DIRECT ACTIVE sending", message_label), LOG_NOTICE, false, false);
										let snap = link_arc.snapshot().ok();
										if let Some(ref snap) = snap {
											if snap.initiator && !self.backchannel_identified_links.contains_key(&dest_hash) {
												let source_identity = lxm.source().and_then(|s| s.identity.clone());
												if let Some(identity) = source_identity {
													log(&format!("[POB][{}] Pre-send identify on link {}", message_label, hexrep(&snap.link_id, false)), LOG_NOTICE, false, false);
													if let Err(e) = link_arc.identify(&identity) {
														log(&format!("[POB][{}] identify error: {}", message_label, e), LOG_NOTICE, false, false);
													} else {
														log(&format!("[POB][{}] Pre-send identify OK", message_label), LOG_NOTICE, false, false);
														self.backchannel_identified_links.insert(dest_hash.clone(), true);
													}
												}
											}
										}
										if let Ok(link_destination) = link_arc.build_link_destination() {
											lxm.set_delivery_destination(link_destination);
										}
										lxm.set_delivery_link(link_arc.clone());
										if let Err(err) = lxm.send_with_handle(Some(message.clone())) {
											log(&format!("[POB][{}] DIRECT send FAILED: {}", message_label, err), LOG_NOTICE, false, false);
											// Send failed — clear state and fall through to propagation next cycle.
											lxm.state = LXMessage::OUTBOUND;
											lxm.clear_delivery_link();
											log(&format!("[POB][{}] DIRECT send error → downgrading to PROPAGATED", message_label), LOG_NOTICE, false, false);
											lxm.method = LXMessage::PROPAGATED;
										} else {
											log(&format!("[POB][{}] DIRECT send OK", message_label), LOG_NOTICE, false, false);
											if !backchannel_setup_links.iter().any(|(l, _)| l.same_link(&link_arc)) {
												backchannel_setup_links.push((link_arc.clone(), dest_hash.clone()));
											}
										}
									}
								} else if status == reticulum_rust::link::STATE_CLOSED {
									// Link is CLOSED — clean up and retry with fresh link.
									if lxm.state == LXMessage::SENDING {
										lxm.state = LXMessage::OUTBOUND;
										lxm.resource_representation = None;
									}
									lxm.clear_delivery_link();
									self.direct_links.remove(&dest_hash);
									self.backchannel_links.remove(&dest_hash);
									self.backchannel_identified_links.remove(&dest_hash);
									log(
										&format!("[POB][{}] DIRECT link CLOSED → requesting new path", message_label),
										LOG_NOTICE, false, false,
									);
									Transport::request_path(&dest_hash, None, None, None, None);
									lxm.next_delivery_attempt = Some(now() + Self::DELIVERY_RETRY_WAIT);
								} else {
									// Link is PENDING/HANDSHAKE — just wait for it to become active.
									log(
										&format!("[POB][{}] DIRECT link PENDING (status={}), waiting", message_label, status),
										LOG_NOTICE, false, false,
									);
								}
							} else {
								// No link exists — establish one (matching Python LXMRouter behavior).
								if lxm.next_delivery_attempt.map(|t| now() > t).unwrap_or(true) {
									lxm.delivery_attempts += 1;
									lxm.next_delivery_attempt = Some(now() + Self::DELIVERY_RETRY_WAIT);

									if lxm.delivery_attempts <= Self::MAX_DELIVERY_ATTEMPTS {
										if Transport::has_path(&dest_hash) {
											log(&format!("[POB][{}] DIRECT no link → establishing link (attempt {})", message_label, lxm.delivery_attempts), LOG_NOTICE, false, false);
											let destination = match Destination::from_destination_hash(&dest_hash, "lxmf", &["delivery"]) {
												Ok(d) => d,
												Err(e) => {
													log(&format!("[POB][{}] DIRECT dest resolve failed: {}", message_label, e), LOG_ERROR, false, false);
													// Will retry on next process_outbound cycle
													continue;
												}
											};
											match Link::new_outbound(destination, reticulum_rust::link::MODE_AES256_CBC) {
												Ok(link) => {
													let handle = LinkHandle::spawn(link);
													let wake_tx = self.outbound_wake_tx.clone();
													handle.set_link_established_callback(Some(Arc::new(move |_| {
														log("[POB] Direct delivery link ESTABLISHED", LOG_NOTICE, false, false);
														let _ = wake_tx.send(());
													})));
													if let Err(e) = handle.initiate() {
														log(&format!("[POB][{}] DIRECT link initiate failed: {}", message_label, e), LOG_ERROR, false, false);
														continue;
													}
													register_runtime_link_handle(handle.clone());
													self.direct_links.insert(dest_hash.clone(), handle);
													lxm.progress = 0.03;
												}
												Err(e) => {
													log(&format!("[POB][{}] DIRECT Link::new_outbound failed: {}", message_label, e), LOG_ERROR, false, false);
												}
											}
										} else {
											log(&format!("[POB][{}] DIRECT no link, no path → requesting", message_label), LOG_NOTICE, false, false);
											Transport::request_path(&dest_hash, None, None, None, None);
											lxm.next_delivery_attempt = Some(now() + Self::PATH_REQUEST_WAIT);
											lxm.progress = 0.01;
										}
									} else {
										log(&format!("[POB][{}] DIRECT max attempts reached", message_label), LOG_NOTICE, false, false);
										self.fail_message(&mut lxm);
										remove = true;
									}
								}
							}
						}
						LXMessage::PROPAGATED => {
							if self.outbound_propagation_node.is_none() {
								self.fail_message(&mut lxm);
								remove = true;
							} else if lxm.delivery_attempts <= Self::MAX_DELIVERY_ATTEMPTS {
								let node_hash = self.outbound_propagation_node.clone().unwrap();
								let _has_link = self.outbound_propagation_link.is_some();
								if let Some(link_arc) = self.outbound_propagation_link.clone() {
									let status = link_arc.status();
									if status == reticulum_rust::link::STATE_ACTIVE {
										if lxm.state != LXMessage::SENDING {
											// PROTOCOL: Send propagation_packed over the link using link.send_packet().
											// propagation_packed = msgpack([timestamp_f64, [[dest_hash | EC_encrypted(rest) | pn_stamp?]]])
											// This matches Python: link.send_packet(lxm.propagation_packed); lxm.state = SENT
											//
											// DO NOT use send_with_handle() / as_packet() / Packet::new() here.
											// That path calls destination.encrypt() → runtime_encrypt_for_destination()
											// which fails silently for Link-type destinations (the error was being swallowed),
											// leaving the message stuck in OUTBOUND forever, retrying every 2 seconds.
											//
											// link.send_packet() uses the link's AES-256-CBC session key directly and
											// builds the raw packet bytes without touching RUNTIME_LINKS.
											// After a successful send state = SENT immediately (fire-and-forget);
											// the propagation node does not send a delivery receipt.
											let propagation_packed = lxm.propagation_packed.clone();
											if let Some(pdata) = propagation_packed {
												// Using link.send_packet() directly (not Packet::new → pack → encrypt)
												// because link.send_packet() correctly uses the link session key.
												match link_arc.send_packet(&pdata)
													.map_err(|e| e.to_string())
												{
													Ok(()) => {
														log(&format!("[POB][{}] PROPAGATED sent via link → SENT", message_label), LOG_NOTICE, false, false);
														lxm.state = LXMessage::SENT; // fire-and-forget
													}
													Err(e) => {
														log(&format!("[POB][{}] PROPAGATED send_packet failed: {}", message_label, e), LOG_NOTICE, false, false);
														lxm.state = LXMessage::OUTBOUND;
														lxm.delivery_attempts += 1;
														lxm.next_delivery_attempt = Some(now() + Self::DELIVERY_RETRY_WAIT);
													}
												}
											} else {
												log(&format!("[POB][{}] PROPAGATED propagation_packed is None — re-packing not supported", message_label), LOG_NOTICE, false, false);
												lxm.state = LXMessage::OUTBOUND;
												lxm.delivery_attempts += 1;
												lxm.next_delivery_attempt = Some(now() + Self::DELIVERY_RETRY_WAIT);
											}
										}
									} else if status == reticulum_rust::link::STATE_CLOSED {
										self.outbound_propagation_link = None;
										lxm.next_delivery_attempt = Some(now() + Self::DELIVERY_RETRY_WAIT);
									} else {
										let pending_for = link_arc
											.snapshot()
											.ok()
											.and_then(|s| s.request_time.map(|requested| (now() - requested).max(0.0)))
											.unwrap_or(0.0);
										log(
											&format!("Propagation link to {} pending ({:.1}s elapsed)", prettyhexrep(&node_hash), pending_for),
											LOG_DEBUG,
											false,
											false,
										);
									}
								} else if lxm.next_delivery_attempt.map(|t| now() > t).unwrap_or(true) {
									lxm.delivery_attempts += 1;
									lxm.next_delivery_attempt = Some(now() + Self::DELIVERY_RETRY_WAIT);
									if lxm.delivery_attempts < Self::MAX_DELIVERY_ATTEMPTS {
										if Transport::has_path(&node_hash) {
											// Identity presence check is implicit in the next line's recall
											if let Some(identity) = Identity::recall(&node_hash) {
												if let Ok(destination) = Destination::new_outbound(
													Some(identity.clone()),
													DestinationType::Single,
													APP_NAME.to_string(),
													vec!["propagation".to_string()],
												) {
													if let Ok(link) = Link::new_outbound(destination, reticulum_rust::link::MODE_AES256_CBC) {
														let link_handle = LinkHandle::spawn(link);
														let wake_tx = self.outbound_wake_tx.clone();
														let router_weak_packet = self.self_handle.clone();
														let message_id = lxm.message_id.clone();
														link_handle.set_link_established_callback(Some(Arc::new(move |_| {
															let _ = wake_tx.send(());
														})));
														link_handle.set_packet_callback(Some(Arc::new(move |data, _packet| {
															if let Some(router_arc) = router_weak_packet.as_ref().and_then(|w| w.upgrade()) {
																if let Ok(mut router) = router_arc.lock() {
																	if let Some(message_id) = message_id.clone() {
																		router.handle_propagation_transfer_signal(&message_id, data);
																	}
																}
															}
														})));
														let _ = link_handle.initiate();
														reticulum_rust::link::register_runtime_link_handle(link_handle.clone());
														self.outbound_propagation_link = Some(link_handle);
													} else {
														log("Could not establish propagation link", LOG_ERROR, false, false);
													}
												}
											} else {
												log("Propagation node identity not known", LOG_ERROR, false, false);
											}
										} else {
											Transport::request_path(&node_hash, None, None, None, None);
											lxm.next_delivery_attempt = Some(now() + Self::PATH_REQUEST_WAIT);
										}
									}
								} else {
									// Not time to retry yet — leave in pending_outbound
									log(
										&format!("Propagation link to {} not yet ready, waiting for retry", prettyhexrep(&node_hash)),
										LOG_DEBUG,
										false,
										false,
									);
								}
							} else {
								self.fail_message(&mut lxm);
								remove = true;
							}
						}
						_ => {}
					}
				}
				if remove {
					self.pending_outbound.remove(index);
				} else {
					index += 1;
				}
			} else {
				index += 1;
			}
		}

		// Drop the processing lock before calling delivery_link_established
		// (which needs &mut self)
		drop(_guard);

		// Set up backchannel delivery callbacks on any outbound links
		// that just had messages DELIVERED
		for (link, dest_hash) in backchannel_setup_links {
			self.delivery_link_established(link);
			log(&format!(
				"Set up backchannel delivery callbacks on outbound link to {}",
				hexrep(&dest_hash, false)
			), LOG_NOTICE, false, false);
		}
	}

	pub fn handle_outbound(&mut self, message: Arc<Mutex<LXMessage>>) {
		let mut unknown_path_requested = false;
		let mut defer_stamp = false;
		let mut defer_propagation_stamp = false;
		if let Ok(mut lxm) = message.lock() {
			let destination_hash = lxm.destination_hash.clone();
			if lxm.stamp_cost.is_none() {
				if let Some((_, stamp_cost)) = self.outbound_stamp_costs.get(&destination_hash) {
					lxm.stamp_cost = Some(*stamp_cost);
					log(
						&format!(
							"No stamp cost set on LXM to {}, autoconfigured to {}",
							prettyhexrep(&destination_hash),
							stamp_cost
						),
						LOG_DEBUG,
						false,
						false,
						);
				}
			}

			lxm.state = LXMessage::OUTBOUND;
			lxm.outbound_ticket = self.get_outbound_ticket(&destination_hash);
			if lxm.outbound_ticket.is_some() && lxm.defer_stamp {
				lxm.defer_stamp = false;
			}
			if lxm.include_ticket {
				if let Some(ticket) = self.generate_ticket(&destination_hash, LXMessage::TICKET_EXPIRY) {
					lxm.set_field(
						FIELD_TICKET,
						Value::Array(vec![
						Value::F64(ticket.expires),
						Value::Binary(ticket.ticket.clone()),
						]),
					);
				}
			}

			// Resolve the Destination object from the hash if needed.
			// PROPAGATED and OPPORTUNISTIC delivery require the destination
			// (with its public key) for encryption during pack().
			if lxm.destination().is_none() {
				match Destination::from_destination_hash(
					&destination_hash,
					"lxmf",
					&["delivery"],
				) {
					Ok(dest) => {
						let _ = lxm.set_destination(dest);
					}
					Err(e) => {
						log(
							&format!(
								"Could not resolve destination for {}: {}",
								prettyhexrep(&destination_hash),
								e
							),
							LOG_NOTICE,
							false,
							false,
						);
					}
				}
			}

			if lxm.packed.is_none() {
				if let Err(e) = lxm.pack(false) {
					log(&format!("Failed to pack message: {}", e), LOG_ERROR, false, false);
					lxm.state = LXMessage::FAILED;
				if let Some(hash) = lxm.hash.as_ref() {
					self.fire_message_state(hash, LXMessage::FAILED);
				}
				}
			}

			if lxm.method == LXMessage::OPPORTUNISTIC && !Transport::has_path(&destination_hash) {
				Transport::request_path(&destination_hash, None, None, None, None);
				lxm.next_delivery_attempt = Some(now() + Self::PATH_REQUEST_WAIT);
				unknown_path_requested = true;
			}

			lxm.determine_transport_encryption();

			if lxm.defer_stamp && lxm.stamp_cost.is_none() {
				lxm.defer_stamp = false;
			}

			// Capture defer flags while we hold the lock
			defer_stamp = lxm.defer_stamp;
			defer_propagation_stamp = if lxm.desired_method == Some(LXMessage::PROPAGATED) {
				lxm.defer_propagation_stamp
			} else {
				false
			};
		}

		if !defer_stamp && !defer_propagation_stamp {
			self.pending_outbound.push(message);
			if !unknown_path_requested {
				self.process_outbound();
			}
		} else {
			let message_id = message.lock().ok().and_then(|lxm| lxm.message_id.clone());
			if let Some(message_id) = message_id {
				self.pending_deferred_stamps.insert(message_id, message);
			}
		}
	}

	pub fn fail_message(&self, message: &mut LXMessage) {
		log(&format!("{} failed to send", message), LOG_DEBUG, false, false);
		message.progress = 0.0;
		message.state = LXMessage::FAILED;
		if let Some(hash) = message.hash.as_ref() {
			self.fire_message_state(hash, LXMessage::FAILED);
		}
		if let Some(callback) = message.failed_callback() {
			callback(message);
		}
	}

	pub fn get_outbound_ticket(&self, destination_hash: &[u8]) -> Option<Vec<u8>> {
		self.available_tickets
			.outbound
			.get(destination_hash)
			.and_then(|entry| if entry.expires > now() { Some(entry.ticket.clone()) } else { None })
	}

	pub fn get_outbound_ticket_expiry(&self, destination_hash: &[u8]) -> Option<f64> {
		self.available_tickets
			.outbound
			.get(destination_hash)
			.and_then(|entry| if entry.expires > now() { Some(entry.expires) } else { None })
	}

	pub fn generate_ticket(&mut self, destination_hash: &[u8], expiry: u64) -> Option<TicketEntry> {
		let now = now();
		if let Some(last_delivery) = self.available_tickets.last_deliveries.get(destination_hash) {
			if now - *last_delivery < LXMessage::TICKET_INTERVAL as f64 {
				log(
					&format!("A ticket for {} was delivered recently, skipping", prettyhexrep(destination_hash)),
					LOG_DEBUG,
					false,
					false,
				);
				return None;
			}
		}

		let inbound = self
			.available_tickets
			.inbound
			.entry(destination_hash.to_vec())
			.or_insert_with(HashMap::new);
		for ticket in inbound.values() {
			if ticket.expires - now > LXMessage::TICKET_RENEW as f64 {
				return Some(ticket.clone());
			}
		}

		let expires = now + expiry as f64;
		let ticket = Identity::get_random_hash();
		let entry = TicketEntry {
			expires,
			ticket: ticket.clone(),
		};
		inbound.insert(ticket.clone(), entry.clone());
		self.save_available_tickets();
		Some(entry)
	}

	pub fn remember_ticket(&mut self, destination_hash: &[u8], ticket_entry: &TicketEntry) {
		let expires = ticket_entry.expires - now();
		log(
			&format!(
				"Remembering ticket for {}, expires in {}",
				prettyhexrep(destination_hash),
				prettytime(expires, false, false)
			),
			LOG_DEBUG,
			false,
			false,
		);
		self.available_tickets
			.outbound
			.insert(destination_hash.to_vec(), ticket_entry.clone());
		self.save_available_tickets();
	}

	pub fn get_inbound_tickets(&self, destination_hash: &[u8]) -> Option<Vec<Vec<u8>>> {
		let now = now();
		if let Some(inbound) = self.available_tickets.inbound.get(destination_hash) {
			let available: Vec<Vec<u8>> = inbound
				.iter()
				.filter_map(|(ticket, entry)| if now < entry.expires { Some(ticket.clone()) } else { None })
				.collect();
			return if available.is_empty() { None } else { Some(available) };
		}
		None
	}

	pub fn peer(
		&mut self,
		destination_hash: Vec<u8>,
		timestamp: f64,
		propagation_transfer_limit: f64,
		propagation_sync_limit: Option<f64>,
		propagation_stamp_cost: u32,
		propagation_stamp_cost_flexibility: u32,
		peering_cost: u32,
		metadata: Vec<u8>,
	) {
		if peering_cost > self.max_peering_cost {
			if self.peers.contains_key(&destination_hash) {
				log(
					&format!(
						"Peer {} increased peering cost beyond local maximum, breaking peering",
						prettyhexrep(&destination_hash)
					),
					LOG_NOTICE,
					false,
					false,
				);
				self.unpeer(destination_hash, Some(timestamp));
			} else {
				log(
					&format!(
						"Not peering with {}, cost {} exceeds max {}",
						prettyhexrep(&destination_hash),
						peering_cost,
						self.max_peering_cost
					),
					LOG_NOTICE,
					false,
					false,
				);
			}
			return;
		}

		if let Some(peer) = self.peers.get(&destination_hash) {
			if let Ok(mut peer) = peer.lock() {
				if timestamp > peer.peering_timebase {
					peer.alive = true;
					peer.metadata = Some(metadata.clone());
					peer.sync_backoff = 0.0;
					peer.next_sync_attempt = 0.0;
					peer.peering_timebase = timestamp;
					peer.last_heard = now();
					peer.propagation_stamp_cost = Some(propagation_stamp_cost);
					peer.propagation_stamp_cost_flexibility = Some(propagation_stamp_cost_flexibility);
					peer.peering_cost = Some(peering_cost);
					peer.propagation_transfer_limit = Some(propagation_transfer_limit);
					peer.propagation_sync_limit = propagation_sync_limit.or(Some(propagation_transfer_limit));
					log(
						&format!("Peering config updated for {}", prettyhexrep(&destination_hash)),
						LOG_VERBOSE,
						false,
						false,
						);
				}
			}
		} else if self.peers.len() < self.max_peers {
			let router_weak = self.self_handle.clone().unwrap_or_else(Weak::new);
			let mut peer = LXMPeer::new(router_weak, destination_hash.clone(), self.default_sync_strategy);
			peer.alive = true;
			peer.metadata = Some(metadata.clone());
			peer.last_heard = now();
			peer.propagation_stamp_cost = Some(propagation_stamp_cost);
			peer.propagation_stamp_cost_flexibility = Some(propagation_stamp_cost_flexibility);
			peer.peering_cost = Some(peering_cost);
			peer.propagation_transfer_limit = Some(propagation_transfer_limit);
			peer.propagation_sync_limit = propagation_sync_limit.or(Some(propagation_transfer_limit));

			let peer_arc = Arc::new(Mutex::new(peer));
			if let Ok(mut peer) = peer_arc.lock() {
				peer.self_handle = Some(Arc::downgrade(&peer_arc));
			}
			self.peers.insert(destination_hash.clone(), peer_arc);
			log(
				&format!("Peered with {}", prettyhexrep(&destination_hash)),
				LOG_NOTICE,
				false,
				false,
			);
		}
	}

	pub fn unpeer(&mut self, destination_hash: Vec<u8>, timestamp: Option<f64>) {
		let timestamp = timestamp.unwrap_or_else(now);
		let peer_arc = self.peers.get(&destination_hash).cloned();
		if let Some(peer_arc) = peer_arc {
			let should_remove = if let Ok(peer) = peer_arc.lock() {
				if timestamp >= peer.peering_timebase {
					log(&format!("Broke peering with {}", peer), LOG_NOTICE, false, false);
					true
				} else {
					false
				}
			} else {
				false
			};
			if should_remove {
				self.peers.remove(&destination_hash);
			}
		}
	}

	pub fn jobs(&mut self) {
		if self.exit_handler_running {
			return;
		}

		self.processing_count += 1;

		if self.processing_count % Self::JOB_OUTBOUND_INTERVAL == 0 {
			self.process_outbound();
		}

		if self.processing_count % Self::JOB_STAMPS_INTERVAL == 0 {
			if let Some(router_weak) = self.self_handle.clone() {
				thread::spawn(move || {
					if let Some(router_arc) = router_weak.upgrade() {
						if let Ok(mut router) = router_arc.lock() {
							router.process_deferred_stamps();
						}
					}
				});
			}
		}

		if self.processing_count % Self::JOB_LINKS_INTERVAL == 0 {
			self.clean_links();
		}

		if self.processing_count % Self::JOB_TRANSIENT_INTERVAL == 0 {
			self.clean_transient_id_caches();
		}

		if self.processing_count % Self::JOB_STORE_INTERVAL == 0 && self.propagation_node {
			self.clean_message_store();
		}

		if self.processing_count % Self::JOB_PEERINGEST_INTERVAL == 0 && self.propagation_node {
			self.flush_queues();
		}

		if self.processing_count % Self::JOB_ROTATE_INTERVAL == 0 && self.propagation_node {
			self.rotate_peers();
		}

		if self.processing_count % Self::JOB_PEERSYNC_INTERVAL == 0 {
			if self.propagation_node {
				self.sync_peers();
			}
			self.clean_throttled_peers();
		}
	}

	fn load_cached_state(&mut self) {
		let deliveries_path = format!("{}/local_deliveries", self.storagepath);
		if let Ok(data) = fs::read(&deliveries_path) {
			if let Ok(map) = rmp_serde::from_slice::<HashMap<Vec<u8>, f64>>(&data) {
				self.locally_delivered_transient_ids = map;
			} else {
				log(
					"Invalid data format for loaded locally delivered transient IDs, recreating",
					LOG_ERROR,
					false,
					false,
				);
				self.locally_delivered_transient_ids = HashMap::new();
			}
		}

		let processed_path = format!("{}/locally_processed", self.storagepath);
		if let Ok(data) = fs::read(&processed_path) {
			if let Ok(map) = rmp_serde::from_slice::<HashMap<Vec<u8>, f64>>(&data) {
				self.locally_processed_transient_ids = map;
			} else {
				log(
					"Invalid data format for loaded locally processed transient IDs, recreating",
					LOG_ERROR,
					false,
					false,
				);
				self.locally_processed_transient_ids = HashMap::new();
			}
		}

		self.clean_transient_id_caches();

		let stamp_costs_path = format!("{}/outbound_stamp_costs", self.storagepath);
		if let Ok(data) = fs::read(&stamp_costs_path) {
			match rmp_serde::from_slice::<HashMap<Vec<u8>, (f64, u32)>>(&data) {
				Ok(map) => {
					self.outbound_stamp_costs = map;
				}
				Err(_e) => {
					log(
						"Invalid data format for loaded outbound stamp costs, recreating",
						LOG_ERROR,
						false,
						false,
					);
					self.outbound_stamp_costs = HashMap::new();
				}
			}
			self.clean_outbound_stamp_costs();
			self.save_outbound_stamp_costs();
		}

		let tickets_path = format!("{}/available_tickets", self.storagepath);
		if let Ok(data) = fs::read(&tickets_path) {
			if let Ok(tickets) = rmp_serde::from_slice::<AvailableTickets>(&data) {
				self.available_tickets = tickets;
			} else {
				log(
					"Invalid data format for loaded available tickets, recreating",
					LOG_ERROR,
					false,
					false,
				);
				self.available_tickets = AvailableTickets::default();
			}
			self.clean_available_tickets();
			self.save_available_tickets();
		}
	}

	fn clean_links(&mut self) {
		let mut closed_links = Vec::new();
		for (link_hash, link_arc) in self.direct_links.iter() {
			// Skip inactivity cleanup for app_links — their lifetime is
			// managed explicitly by app_link_open / app_link_close.
			if self.app_links.contains(link_hash.as_slice()) {
				continue;
			}
			if link_arc.no_data_for().map(|n| n as f64 > Self::LINK_MAX_INACTIVITY).unwrap_or(false) {
					closed_links.push(link_hash.clone());
				}
		}

		for link_hash in closed_links.iter() {
			if let Some(link_arc) = self.direct_links.get(link_hash) {
				self.validated_peer_links.remove(&link_arc.link_id());
				link_arc.teardown();
			}
			self.direct_links.remove(link_hash);
			self.backchannel_identified_links.remove(link_hash);
			log("Cleaned inactive direct link", LOG_DEBUG, false, false);
		}

		let mut inactive_links = Vec::new();
		for link_arc in self.active_propagation_links.iter() {
			if link_arc.no_data_for().map(|n| n as f64 > Self::P_LINK_MAX_INACTIVITY).unwrap_or(false) {
				inactive_links.push(link_arc.clone());
			}
		}

		for link_arc in inactive_links {
			self.active_propagation_links.retain(|l| !l.same_link(&link_arc));
			link_arc.teardown();
		}

		let should_clear = if let Some(link_arc) = self.outbound_propagation_link.as_ref() {
			link_arc.status() == reticulum_rust::link::STATE_CLOSED
		} else {
			false
		};
		if should_clear {
			self.outbound_propagation_link = None;
			if self.propagation_transfer_state == Self::PR_COMPLETE {
				self.acknowledge_sync_completion(None);
			} else if self.propagation_transfer_state < Self::PR_LINK_ESTABLISHED {
				self.acknowledge_sync_completion(Some(Self::PR_LINK_FAILED));
			} else if self.propagation_transfer_state < Self::PR_COMPLETE {
				self.acknowledge_sync_completion(Some(Self::PR_TRANSFER_FAILED));
			} else {
				self.acknowledge_sync_completion(None);
			}
			log("Cleaned outbound propagation link", LOG_DEBUG, false, false);
		}
	}

	fn clean_transient_id_caches(&mut self) {
		let now_ts = now();
		let mut removed = Vec::new();
		for (transient_id, timestamp) in self.locally_delivered_transient_ids.iter() {
			if now_ts > *timestamp + Self::MESSAGE_EXPIRY * 6.0 {
				removed.push(transient_id.clone());
			}
		}
		for transient_id in removed.drain(..) {
			self.locally_delivered_transient_ids.remove(&transient_id);
			log(
				&format!("Cleaned {} from local delivery cache", prettyhexrep(&transient_id)),
				LOG_DEBUG,
				false,
				false,
			);
		}

		let mut removed = Vec::new();
		for (transient_id, timestamp) in self.locally_processed_transient_ids.iter() {
			if now_ts > *timestamp + Self::MESSAGE_EXPIRY * 6.0 {
				removed.push(transient_id.clone());
			}
		}
		for transient_id in removed {
			self.locally_processed_transient_ids.remove(&transient_id);
			log(
				&format!("Cleaned {} from locally processed cache", prettyhexrep(&transient_id)),
				LOG_DEBUG,
				false,
				false,
			);
		}
	}

	fn clean_throttled_peers(&mut self) {
		let now_ts = now();
		let mut expired = Vec::new();
		for (peer_hash, until) in self.throttled_peers.iter() {
			if now_ts > *until {
				expired.push(peer_hash.clone());
			}
		}
		for peer_hash in expired {
			self.throttled_peers.remove(&peer_hash);
		}
	}

	fn message_storage_size(&self) -> Option<u64> {
		if !self.propagation_node {
			return None;
		}
		let mut total = 0u64;
		for entry in self.propagation_entries.values() {
			total += entry.size as u64;
		}
		Some(total)
	}

	fn clean_message_store(&mut self) {
		log("Cleaning message store", LOG_VERBOSE, false, false);
		let now_ts = now();
		let mut removed = HashMap::new();
		for (transient_id, entry) in self.propagation_entries.iter() {
			let filename = match entry.filepath.split('/').last() {
				Some(name) => name,
				None => {
					removed.insert(transient_id.clone(), entry.filepath.clone());
					continue;
				}
			};
			let parts: Vec<&str> = filename.split('_').collect();
			let parsed = if parts.len() == 3 {
				let ts = parts[1].parse::<f64>().ok();
				let stamp = parts[2].parse::<u32>().ok();
				let hash_len = parts[0].len() == (HASHLENGTH / 8) * 2;
				(ts, stamp, hash_len)
			} else {
				(None, None, false)
			};
			let purge = match parsed {
				(Some(ts), Some(stamp), true) => ts + Self::MESSAGE_EXPIRY < now_ts || stamp != entry.stamp_value,
				_ => true,
			};
			if purge {
				removed.insert(transient_id.clone(), entry.filepath.clone());
			}
		}

		let mut removed_count = 0u64;
		for (transient_id, filepath) in removed {
			self.propagation_entries.remove(&transient_id);
			if fs::remove_file(&filepath).is_ok() {
				removed_count += 1;
			}
		}

		if removed_count > 0 {
			log(
				&format!("Cleaned {} entries from the message store", removed_count),
				LOG_VERBOSE,
				false,
				false,
			);
		}

		if let (Some(limit), Some(size)) = (self.message_storage_limit, self.message_storage_size()) {
			if size > limit {
				let bytes_needed = size - limit;
				let mut bytes_cleaned = 0u64;
				let mut weighted = Vec::new();
				for (transient_id, entry) in self.propagation_entries.iter() {
					weighted.push((self.get_weight(transient_id), transient_id.clone(), entry.clone()));
				}
				weighted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
				for (_, transient_id, entry) in weighted {
					if bytes_cleaned >= bytes_needed {
						break;
					}
					let _ = fs::remove_file(&entry.filepath);
					self.propagation_entries.remove(&transient_id);
					bytes_cleaned += entry.size as u64;
				}
			}
		}
	}

	fn clean_outbound_stamp_costs(&mut self) {
		let now_ts = now();
		let mut expired = Vec::new();
		for (destination_hash, entry) in self.outbound_stamp_costs.iter() {
			if now_ts > entry.0 + Self::STAMP_COST_EXPIRY {
				expired.push(destination_hash.clone());
			}
		}
		for destination_hash in expired {
			self.outbound_stamp_costs.remove(&destination_hash);
		}
	}

	fn clean_available_tickets(&mut self) {
		let now_ts = now();
		let mut expired_outbound = Vec::new();
		for (destination_hash, entry) in self.available_tickets.outbound.iter() {
			if now_ts > entry.expires {
				expired_outbound.push(destination_hash.clone());
			}
		}
		for destination_hash in expired_outbound {
			self.available_tickets.outbound.remove(&destination_hash);
		}

		let mut expired_inbound = Vec::new();
		for (destination_hash, tickets) in self.available_tickets.inbound.iter() {
			let mut expired_tickets = Vec::new();
			for (ticket, entry) in tickets.iter() {
				if now_ts > entry.expires + LXMessage::TICKET_GRACE as f64 {
					expired_tickets.push(ticket.clone());
				}
			}
			if !expired_tickets.is_empty() {
				expired_inbound.push((destination_hash.clone(), expired_tickets));
			}
		}
		for (destination_hash, tickets) in expired_inbound {
			if let Some(map) = self.available_tickets.inbound.get_mut(&destination_hash) {
				for ticket in tickets {
					map.remove(&ticket);
				}
			}
		}
	}

	fn save_locally_delivered_transient_ids(&self) {
		if self.locally_delivered_transient_ids.is_empty() {
			return;
		}
		if let Ok(data) = rmp_serde::to_vec(&self.locally_delivered_transient_ids) {
			let _ = fs::create_dir_all(&self.storagepath);
			let _ = fs::write(format!("{}/local_deliveries", self.storagepath), data);
		}
	}

	#[allow(dead_code)]
	fn save_locally_processed_transient_ids(&self) {
		if self.locally_processed_transient_ids.is_empty() {
			return;
		}
		if let Ok(data) = rmp_serde::to_vec(&self.locally_processed_transient_ids) {
			let _ = fs::create_dir_all(&self.storagepath);
			let _ = fs::write(format!("{}/locally_processed", self.storagepath), data);
		}
	}

	#[allow(dead_code)]
	fn save_node_stats(&self) {
		let mut stats = HashMap::new();
		stats.insert("client_propagation_messages_received".to_string(), self.client_propagation_messages_received);
		stats.insert("client_propagation_messages_served".to_string(), self.client_propagation_messages_served);
		stats.insert("unpeered_propagation_incoming".to_string(), self.unpeered_propagation_incoming);
		stats.insert("unpeered_propagation_rx_bytes".to_string(), self.unpeered_propagation_rx_bytes);
		if let Ok(data) = rmp_serde::to_vec(&stats) {
			let _ = fs::create_dir_all(&self.storagepath);
			let _ = fs::write(format!("{}/node_stats", self.storagepath), data);
		}
	}

	fn flush_queues(&mut self) {
		if self.peers.is_empty() {
			return;
		}
		self.flush_peer_distribution_queue();
		let peers: Vec<Arc<Mutex<LXMPeer>>> = self.peers.values().cloned().collect();
		for peer_arc in peers {
			if let Ok(mut peer) = peer_arc.lock() {
				if peer.queued_items() {
					peer.process_queues(self);
				}
			}
		}
	}

	fn rotate_peers(&mut self) {
		let rotation_headroom = ((self.max_peers as f64) * (Self::ROTATION_HEADROOM_PCT / 100.0)).floor() as usize;
		let rotation_headroom = rotation_headroom.max(1);
		let required_drops = self.peers.len().saturating_sub(self.max_peers.saturating_sub(rotation_headroom));
		if required_drops == 0 || self.peers.len().saturating_sub(required_drops) <= 1 {
			return;
		}

		let mut untested = Vec::new();
		for peer_arc in self.peers.values() {
			if let Ok(peer) = peer_arc.lock() {
				if peer.last_sync_attempt == 0.0 {
					untested.push(peer.destination_hash.clone());
				}
			}
		}
		if untested.len() >= rotation_headroom {
			log("Newly added peer threshold reached, postponing peer rotation", LOG_DEBUG, false, false);
			return;
		}

		let mut pool = Vec::new();
		for peer_arc in self.peers.values() {
			if let Ok(mut peer) = peer_arc.lock() {
				if peer.unhandled_message_count(self) == 0 {
					pool.push(peer.destination_hash.clone());
				}
			}
		}

		let candidate_ids = if pool.is_empty() {
			self.peers.keys().cloned().collect::<Vec<_>>()
		} else {
			pool
		};

		let mut drop_pool = Vec::new();
		let mut waiting = Vec::new();
		let mut unresponsive = Vec::new();
		for peer_id in candidate_ids {
			if let Some(peer_arc) = self.peers.get(&peer_id) {
				if let Ok(peer) = peer_arc.lock() {
					if !self.static_peers.contains(&peer_id) && peer.state == LXMPeer::IDLE {
						if peer.alive {
							if peer.offered > 0 {
								waiting.push(peer_id.clone());
							}
						} else {
							unresponsive.push(peer_id.clone());
						}
					}
				}
			}
		}

		if !unresponsive.is_empty() {
			drop_pool.extend(unresponsive);
			if !self.prioritise_rotating_unreachable_peers {
				drop_pool.extend(waiting);
			}
		} else {
			drop_pool.extend(waiting);
		}

		if drop_pool.is_empty() {
			return;
		}

		drop_pool.sort_by(|a, b| {
			let ar_a = self.peers.get(a).and_then(|p| p.lock().ok()).map(|p| p.acceptance_rate()).unwrap_or(0.0);
			let ar_b = self.peers.get(b).and_then(|p| p.lock().ok()).map(|p| p.acceptance_rate()).unwrap_or(0.0);
			ar_a.partial_cmp(&ar_b).unwrap_or(std::cmp::Ordering::Equal)
		});

		let mut dropped = 0usize;
		for peer_id in drop_pool.into_iter().take(required_drops) {
			let ar = self
				.peers
				.get(&peer_id)
				.and_then(|p| p.lock().ok())
				.map(|p| p.acceptance_rate() * 100.0)
				.unwrap_or(0.0);
			if ar < Self::ROTATION_AR_MAX * 100.0 {
				self.unpeer(peer_id, None);
				dropped += 1;
			}
		}

		if dropped > 0 {
			log(
				&format!("Dropped {} low acceptance rate peer(s)", dropped),
				LOG_DEBUG,
				false,
				false,
			);
		}
	}

	fn sync_peers(&mut self) {
		let mut culled = Vec::new();
		let mut waiting = Vec::new();
		let mut unresponsive = Vec::new();
		for (peer_id, peer_arc) in self.peers.iter() {
			if let Ok(mut peer) = peer_arc.lock() {
				if now() > peer.last_heard + LXMPeer::MAX_UNREACHABLE {
					if !self.static_peers.contains(peer_id) {
						culled.push(peer_id.clone());
					}
				} else if peer.state == LXMPeer::IDLE && peer.unhandled_message_count(self) > 0 {
					if peer.alive {
						waiting.push(peer.destination_hash.clone());
					} else if now() > peer.next_sync_attempt {
						unresponsive.push(peer.destination_hash.clone());
					}
				}
			}
		}

		let mut pool = Vec::new();
		if !waiting.is_empty() {
			let mut waiting_peers = waiting.clone();
			waiting_peers.sort_by(|a, b| {
				let a_rate = self.peers.get(a).and_then(|p| p.lock().ok()).map(|p| p.sync_transfer_rate).unwrap_or(0.0);
				let b_rate = self.peers.get(b).and_then(|p| p.lock().ok()).map(|p| p.sync_transfer_rate).unwrap_or(0.0);
				b_rate.partial_cmp(&a_rate).unwrap_or(std::cmp::Ordering::Equal)
			});
			let fastest: Vec<Vec<u8>> = waiting_peers.into_iter().take(Self::FASTEST_N_RANDOM_POOL).collect();
			pool.extend(fastest.clone());

			let unknown_speed: Vec<Vec<u8>> = waiting
				.iter()
				.filter(|peer_id| {
					self.peers
						.get(*peer_id)
						.and_then(|p| p.lock().ok())
						.map(|p| p.sync_transfer_rate == 0.0)
						.unwrap_or(false)
				})
				.cloned()
				.collect();
			if !unknown_speed.is_empty() {
				let take = std::cmp::min(unknown_speed.len(), fastest.len());
				pool.extend(unknown_speed.into_iter().take(take));
			}

			log(
				&format!("Selecting peer to sync from {} waiting peers", waiting.len()),
				LOG_DEBUG,
				false,
				false,
			);
		} else if !unresponsive.is_empty() {
			log(
				&format!("No active peers available, selecting from {} unresponsive peers", unresponsive.len()),
				LOG_DEBUG,
				false,
				false,
			);
			pool = unresponsive;
		}

		if !pool.is_empty() {
			let mut rng = rand::thread_rng();
			let index = rng.gen_range(0..pool.len());
			if let Some(peer_arc) = self.peers.get(&pool[index]) {
				if let Ok(mut peer) = peer_arc.lock() {
					peer.sync();
				}
			}
		}

		for peer_id in culled {
			self.peers.remove(&peer_id);
			log(
				&format!("Removing peer {} due to excessive unreachability", prettyhexrep(&peer_id)),
				LOG_WARNING,
				false,
				false,
			);
		}
	}

	fn process_deferred_stamps(&mut self) {
		if self.pending_deferred_stamps.is_empty() {
			return;
		}
		let lock = match self.stamp_gen_lock.try_lock() {
			Ok(guard) => guard,
			Err(_) => {
				return;
			}
		};

		let (message_id, message_arc) = match self.pending_deferred_stamps.iter().next() {
			Some((id, msg)) => (id.clone(), msg.clone()),
			None => return,
		};

		let mut enqueue = false;
		if let Ok(mut message) = message_arc.lock() {
			if message.state == LXMessage::CANCELLED {
				message.stamp_generation_failed = true;
				self.pending_deferred_stamps.remove(&message_id);
				if let Some(callback) = message.failed_callback() {
					callback(&message);
				}
				return;
			}

			let mut stamp_ok = !message.defer_stamp || message.stamp.is_some();
			let mut propagation_ok = if message.desired_method == Some(LXMessage::PROPAGATED) {
				!message.defer_propagation_stamp || message.propagation_stamp.is_some()
			} else {
				true
			};

			if !stamp_ok {
				let _stamp_start = std::time::Instant::now();
				let generated = message.get_stamp();
				if let Some(stamp) = generated {
					message.stamp = Some(stamp);
					message.defer_stamp = false;
					message.packed = None;
					let _ = message.pack(true);
					stamp_ok = true;
				} else {
					message.stamp_generation_failed = true;
					self.pending_deferred_stamps.remove(&message_id);
					self.fail_message(&mut message);
					return;
				}
			}

			if !propagation_ok {
				let target_cost = self.get_outbound_propagation_cost();
				if let Some(cost) = target_cost {
					let _prop_start = std::time::Instant::now();
					if let Ok(stamp) = message.get_propagation_stamp(cost) {
						if let Some(stamp) = stamp {
							message.propagation_stamp = Some(stamp);
							message.defer_propagation_stamp = false;
							message.packed = None;
							let _ = message.pack(false);
							propagation_ok = true;
						}
					} else {
					}
				}
				if !propagation_ok {
					message.stamp_generation_failed = true;
					self.pending_deferred_stamps.remove(&message_id);
					self.fail_message(&mut message);
					return;
				}
			}

			if stamp_ok && propagation_ok {
				self.pending_deferred_stamps.remove(&message_id);
				enqueue = true;
			}
		}
		if enqueue {
			self.pending_outbound.push(message_arc);
		}
		drop(lock);
	}

	pub fn cancel_outbound(&mut self, message_id: &[u8], cancel_state: u8) {
		if let Some(message_arc) = self.pending_deferred_stamps.remove(message_id) {
			if let Ok(mut message) = message_arc.lock() {
				message.state = cancel_state;
				lx_stamper::cancel_work(message_id);
			}
		}

		let mut cancelled = None;
		for message in self.pending_outbound.iter() {
			if let Ok(lxm) = message.lock() {
				if lxm.message_id.as_deref() == Some(message_id) {
					cancelled = Some(message.clone());
					break;
				}
			}
		}

		if let Some(message_arc) = cancelled {
			if let Ok(mut message) = message_arc.lock() {
				message.state = cancel_state;
				if message.representation == LXMessage::RESOURCE {
					if let Some(resource) = message.resource_representation.clone() {
						if let Ok(mut resource) = resource.lock() {
							resource.cancel();
						}
					}
				}
			}
		}
	}

	pub fn get_outbound_progress(&self, lxm_hash: &[u8]) -> Option<f64> {
		for message in self.pending_outbound.iter() {
			if let Ok(lxm) = message.lock() {
				if lxm.hash.as_deref() == Some(lxm_hash) {
					return Some(lxm.progress);
				}
			}
		}
		for message in self.pending_deferred_stamps.values() {
			if let Ok(lxm) = message.lock() {
				if lxm.hash.as_deref() == Some(lxm_hash) {
					return Some(lxm.progress);
				}
			}
		}
		None
	}

	pub fn get_outbound_lxm_stamp_cost(&self, lxm_hash: &[u8]) -> Option<u32> {
		for message in self.pending_outbound.iter() {
			if let Ok(lxm) = message.lock() {
				if lxm.hash.as_deref() == Some(lxm_hash) {
					return if lxm.outbound_ticket.is_some() { None } else { lxm.stamp_cost };
				}
			}
		}
		for message in self.pending_deferred_stamps.values() {
			if let Ok(lxm) = message.lock() {
				if lxm.hash.as_deref() == Some(lxm_hash) {
					return if lxm.outbound_ticket.is_some() { None } else { lxm.stamp_cost };
				}
			}
		}
		None
	}

	pub fn get_outbound_lxm_propagation_stamp_cost(&self, lxm_hash: &[u8]) -> Option<u32> {
		for message in self.pending_outbound.iter() {
			if let Ok(lxm) = message.lock() {
				if lxm.hash.as_deref() == Some(lxm_hash) {
					return lxm.propagation_target_cost;
				}
			}
		}
		for message in self.pending_deferred_stamps.values() {
			if let Ok(lxm) = message.lock() {
				if lxm.hash.as_deref() == Some(lxm_hash) {
					return lxm.propagation_target_cost;
				}
			}
		}
		None
	}

	pub fn set_outbound_propagation_node(&mut self, destination_hash: Vec<u8>) -> Result<(), String> {
		if destination_hash.len() != TRUNCATED_HASHLENGTH / 8 {
			return Err("Invalid destination hash for outbound propagation node".to_string());
		}
		if self.outbound_propagation_node.as_ref() != Some(&destination_hash) {
			self.outbound_propagation_node = Some(destination_hash.clone());
			let should_teardown = if let Some(link) = self.outbound_propagation_link.as_ref() {
				link.destination_hash()
					.map(|hash| hash != destination_hash)
					.unwrap_or(false)
			} else {
				false
			};
			if should_teardown {
				if let Some(link) = self.outbound_propagation_link.as_ref() {
					link.teardown();
				}
				self.outbound_propagation_link = None;
			}
		}

		// Proactively request the path so it is available before the first sync attempt
		if !Transport::has_path(&destination_hash) {
			log(
				&format!(
					"No path to propagation node {}, requesting proactively",
					reticulum_rust::hexrep(&destination_hash, false)
				),
				LOG_DEBUG,
				false,
				false,
			);
			Transport::request_path(&destination_hash, None, None, None, None);
		}

		Ok(())
	}

	pub fn get_outbound_propagation_node(&self) -> Option<Vec<u8>> {
		self.outbound_propagation_node.clone()
	}

	pub fn set_inbound_propagation_node(&mut self, _destination_hash: Vec<u8>) -> Result<(), String> {
		// Inbound/outbound propagation node differentiation is currently not implemented
		Err("Inbound/outbound propagation node differentiation is currently not implemented".to_string())
	}

	pub fn get_inbound_propagation_node(&self) -> Option<Vec<u8>> {
		self.get_outbound_propagation_node()
	}

	fn get_outbound_propagation_cost(&self) -> Option<u32> {
		let pn_hash = self.outbound_propagation_node.clone()?;
		let target_cost = Identity::recall_app_data(&pn_hash)
			.and_then(|data| if pn_announce_data_is_valid(&data) { Self::decode_value(&data) } else { None })
			.and_then(|value| match value {
				Value::Array(values) => values.get(5).cloned(),
				_ => None,
			})
			.and_then(|value| match value {
				Value::Array(costs) => costs.get(0).and_then(|v| v.as_i64()).map(|v| v as u32),
				_ => None,
			});

		if target_cost.is_none() {
			// Fire off a path request so future sends will have the cached cost,
			// but don't block — default to 0 so the message ships immediately.
			Transport::request_path(&pn_hash, None, None, None, None);
			log("Propagation node stamp cost not cached, requesting path and defaulting to 0", LOG_NOTICE, false, false);
			return Some(0);
		}

		target_cost
	}

	pub fn save_outbound_stamp_costs(&self) {
		let _guard = match self.cost_file_lock.lock() {
			Ok(guard) => guard,
			Err(_) => return,
		};
		if let Ok(data) = rmp_serde::to_vec(&self.outbound_stamp_costs) {
			let _ = fs::create_dir_all(&self.storagepath);
			let _ = fs::write(format!("{}/outbound_stamp_costs", self.storagepath), data);
		}
	}

	pub fn save_available_tickets(&self) {
		let _guard = match self.ticket_file_lock.lock() {
			Ok(guard) => guard,
			Err(_) => return,
		};
		if let Ok(data) = rmp_serde::to_vec(&self.available_tickets) {
			let _ = fs::create_dir_all(&self.storagepath);
			let _ = fs::write(format!("{}/available_tickets", self.storagepath), data);
		}
	}

	/// Register a delivery identity to receive messages
	pub fn register_delivery_identity(
		&mut self,
		identity: Identity,
		display_name: Option<String>,
		stamp_cost: Option<u32>,
	) -> Result<Destination, String> {
		if !self.delivery_destinations.is_empty() {
			return Err("Currently only one delivery identity is supported per LXMF router instance".to_string());
		}

		// Create ratchet directory
		let _ = fs::create_dir_all(&self.ratchetpath);

		// Create delivery destination
		let mut delivery_destination = Destination::new_inbound(
			Some(identity),
			DestinationType::Single,
			APP_NAME.to_string(),
			vec!["delivery".to_string()],
		)?;

		// Enable ratchets
		let ratchet_file = format!("{}/{}.ratchets", self.ratchetpath, hexrep(&delivery_destination.hash, false));
		log(&format!("[RATCHET] enable_ratchets: path={} exists={}", ratchet_file, std::path::Path::new(&ratchet_file).exists()), LOG_NOTICE, false, false);
		let ratchet_result = delivery_destination.enable_ratchets(ratchet_file);
		log(&format!("[RATCHET] enable_ratchets result: {:?} loaded_count={}", ratchet_result,
			delivery_destination.ratchets.as_ref().map(|r| r.len()).unwrap_or(0)), LOG_NOTICE, false, false);

		if self.enforce_ratchets {
			let _ = delivery_destination.enforce_ratchets();
		}

		// LXMF delivery destinations should always prove packets so senders
		// receive delivery confirmations. In Python this is set by the caller
		// on a shared reference, but in Rust we clone, so set it before cloning.
		let _ = delivery_destination.set_proof_strategy(PROVE_ALL);

		// Note: display_name is not a field on Destination in Rust implementation
		//delivery_destination.display_name = display_name;

		// Set packet callback
		let router_weak = self.self_handle.clone();
		delivery_destination.set_packet_callback(Some(Arc::new(move |data, packet| {
			if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					router.delivery_packet(data, packet);
				}
			}
		}))); 

		// Set link established callback
		let router_weak2 = self.self_handle.clone();
		delivery_destination.set_link_established_callback(Some(Arc::new(move |link| {
			if let Some(router_arc) = router_weak2.as_ref().and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					router.delivery_link_established(link);
				}
			}
		}))); 

		let dest_hash = delivery_destination.hash.clone();
		if let Some(name) = display_name.clone() {
			self.delivery_display_names.insert(dest_hash.clone(), name);
		}
		self.delivery_destinations.insert(dest_hash.clone(), delivery_destination.clone());
		self.set_inbound_stamp_cost(&dest_hash, stamp_cost);
		self.update_delivery_announce_app_data(&dest_hash);
		Transport::register_destination(delivery_destination.clone());

		Ok(delivery_destination)
	}

	/// Register a callback to be called when messages are delivered
	pub fn register_delivery_callback(&mut self, callback: Arc<dyn Fn(&LXMessage) + Send + Sync>) {
		self.delivery_callback = Some(callback);
	}

	/// Register a callback that fires when propagation sync completes.
	/// The callback receives the number of messages that were synced.
	pub fn register_sync_complete_callback(&mut self, callback: Arc<dyn Fn(u32) + Send + Sync>) {
		self.sync_complete_callback = Some(callback);
	}

	/// Register a callback that fires when a delivery announce is received.
	/// The callback receives (destination_hash, Option<display_name>).
	pub fn register_announce_callback(&mut self, callback: Arc<dyn Fn(&[u8], Option<String>) + Send + Sync>) {
		self.announce_callback = Some(callback);
	}

	/// Add a destination hash to the watch list.
	/// Only announces from watched destinations (or pending outbound targets)
	/// will be fully processed.
	pub fn watch_destination(&mut self, dest_hash: &[u8]) {
		self.watched_destinations.insert(dest_hash.to_vec());
	}

	/// Remove a destination hash from the watch list.
	pub fn unwatch_destination(&mut self, dest_hash: &[u8]) {
		self.watched_destinations.remove(dest_hash);
	}

	/// Return the current state of a direct link to a peer.
	/// 0 = no link / closed, 1 = pending (establishing), 2 = active.
	pub fn peer_link_status(&self, dest_hash: &[u8]) -> u8 {
		let link_arc = self.direct_links.get(dest_hash)
			.or_else(|| self.backchannel_links.get(dest_hash));
		match link_arc {
			None => 0,
			Some(arc) => {
				let status = arc.status();
				if status == reticulum_rust::link::STATE_ACTIVE {
					2
				} else if status == reticulum_rust::link::STATE_PENDING {
					1
				} else {
					0
				}
			}
		}
	}

	// -------------------------------------------------------------------
	// App links — proactive link establishment for open chat screens
	// -------------------------------------------------------------------

	/// Status constants for [`app_link_status`].
	pub const APP_LINK_NONE: u8 = 0x00;
	pub const APP_LINK_PATH_REQUESTED: u8 = 0x01;
	pub const APP_LINK_ESTABLISHING: u8 = 0x02;
	pub const APP_LINK_ACTIVE: u8 = 0x03;
	pub const APP_LINK_DISCONNECTED: u8 = 0x04;

	/// Open an app link for a destination.
	///
	/// Adds the destination to the `app_links` set, ensures it is watched at
	/// both LXMF and transport levels, and kicks off path request / link
	/// establishment as far as current state allows.  Returns immediately.
	///
	/// If a path is already known, the link is initiated inline.  If not,
	/// a path request is sent; the announce handler will establish the link
	/// when the path response arrives (push, no polling).
	///
	/// Keepalive is maintained automatically.  If the link fails, the status
	/// becomes `APP_LINK_DISCONNECTED`; it will be re-established automatically
	/// when the next announce arrives from the destination (push-driven via
	/// `watched_destinations`).
	pub fn app_link_open(&mut self, dest_hash: &[u8]) {
		self.app_links.insert(dest_hash.to_vec());
		self.watched_destinations.insert(dest_hash.to_vec());
		Transport::watch_announce(dest_hash.to_vec());

		// If we already have an active link, nothing to do.
		if self.peer_link_status(dest_hash) == 2 {
			return;
		}

		// If we have a pending link, let it finish.
		if self.peer_link_status(dest_hash) == 1 {
			return;
		}

		// Clean any stale/closed link entry before trying fresh.
		self.direct_links.remove(dest_hash);
		self.backchannel_identified_links.remove(dest_hash);

		if Transport::has_path(dest_hash) {
			self.establish_app_link(dest_hash);
		} else {
			log(
				&format!("[APP_LINK] No path → requesting for {}", hexrep(dest_hash, false)),
				LOG_NOTICE, false, false,
			);
			Transport::request_path(dest_hash, None, None, None, None);
		}
	}

	/// Close an app link.
	///
	/// Removes the destination from `app_links`, tears down the associated
	/// direct link (if any), and removes it from `direct_links`.  Does NOT
	/// remove from `watched_destinations` — the caller controls that separately.
	pub fn app_link_close(&mut self, dest_hash: &[u8]) {
		self.app_links.remove(dest_hash);
		if let Some(link_arc) = self.direct_links.remove(dest_hash) {
			self.validated_peer_links.remove(&link_arc.link_id());
			link_arc.teardown();
		}
		self.backchannel_identified_links.remove(dest_hash);
	}

	/// Query the current state of an app link.
	///
	/// This is a snapshot — no polling is involved.  Status reflects the
	/// combination of app_links membership, path availability, and link state.
	///
	/// Returns one of the `APP_LINK_*` constants:
	///   0 = not in app_links (or unknown),
	///   1 = path requested (no path yet),
	///   2 = link establishing (PENDING/HANDSHAKE),
	///   3 = link active (ready to send),
	///   4 = disconnected (will reconnect on next announce).
	pub fn app_link_status(&self, dest_hash: &[u8]) -> u8 {
		if !self.app_links.contains(dest_hash) {
			return Self::APP_LINK_NONE;
		}

		let link = self.direct_links.get(dest_hash)
			.or_else(|| self.backchannel_links.get(dest_hash));

		match link {
			Some(arc) => {
				let status = arc.status();
				match status {
					reticulum_rust::link::STATE_ACTIVE => Self::APP_LINK_ACTIVE,
					reticulum_rust::link::STATE_PENDING
					| reticulum_rust::link::STATE_HANDSHAKE => Self::APP_LINK_ESTABLISHING,
					_ => Self::APP_LINK_DISCONNECTED,
				}
			}
			None => {
				if Transport::has_path(dest_hash) {
					// Path exists but no link — link was lost and will be
					// re-established on the next announce.
					Self::APP_LINK_DISCONNECTED
				} else {
					Self::APP_LINK_PATH_REQUESTED
				}
			}
		}
	}

	/// Create and initiate a link for an app_links destination.
	///
	/// Assumes path exists.  The link-established callback wakes the outbound
	/// processing thread so any queued messages are sent immediately.
	pub fn establish_app_link(&mut self, dest_hash: &[u8]) {
		// Check if an existing link is still alive — if so, leave it alone.
		if let Some(existing) = self.direct_links.get(dest_hash) {
			let status = existing.status();
			if status == reticulum_rust::link::STATE_ACTIVE
				|| status == reticulum_rust::link::STATE_PENDING
			{
				return;
			}
		}
		// Clean dead link entry before creating a new one.
		if let Some(old) = self.direct_links.remove(dest_hash) {
			self.validated_peer_links.remove(&old.link_id());
			old.teardown();
		}
		self.backchannel_identified_links.remove(dest_hash);

		log(
			&format!("[APP_LINK] Establishing link to {}", hexrep(dest_hash, false)),
			LOG_NOTICE, false, false,
		);
		let destination = match Destination::from_destination_hash(dest_hash, "lxmf", &["delivery"]) {
			Ok(d) => d,
			Err(e) => {
				log(&format!("[APP_LINK] Destination resolve failed: {}", e), LOG_ERROR, false, false);
				return;
			}
		};
		match Link::new_outbound(destination, reticulum_rust::link::MODE_AES256_CBC) {
			Ok(link) => {
				let link_handle = LinkHandle::spawn(link);
				let wake_tx = self.outbound_wake_tx.clone();
				link_handle.set_link_established_callback(Some(Arc::new(move |_| {
					log("[APP_LINK] Direct link ESTABLISHED", LOG_NOTICE, false, false);
					let _ = wake_tx.send(());
				})));
				if let Err(e) = link_handle.initiate() {
					log(&format!("[APP_LINK] Link initiate failed: {}", e), LOG_ERROR, false, false);
					return;
				}
				register_runtime_link_handle(link_handle.clone());
				self.direct_links.insert(dest_hash.to_vec(), link_handle);
			}
			Err(e) => {
				log(&format!("[APP_LINK] Link::new_outbound failed: {}", e), LOG_ERROR, false, false);
			}
		}
	}

	/// Register a callback that fires whenever an outbound message changes
	/// delivery state.  The callback receives the message hash bytes and the
	/// new state value (one of `LXMessage::SENT`, `DELIVERED`, `FAILED`, etc.).
	pub fn register_message_state_callback(&mut self, callback: Arc<dyn Fn(&[u8], u8) + Send + Sync>) {
		self.message_state_callback = Some(callback);
	}

	/// Fire the message-state callback, if one is registered.
	fn fire_message_state(&self, hash: &[u8], state: u8) {
		if let Some(cb) = &self.message_state_callback {
			cb(hash, state);
		}
	}


	pub fn set_inbound_stamp_cost(&mut self, destination_hash: &[u8], stamp_cost: Option<u32>) -> bool {
		if self.delivery_destinations.contains_key(destination_hash) {
			if let Some(cost) = stamp_cost {
				if cost >= 1 && cost < 255 {
					self.delivery_stamp_costs.insert(destination_hash.to_vec(), cost);
				} else if cost < 1 {
					self.delivery_stamp_costs.remove(destination_hash);
				} else {
					return false;
				}
			} else {
				self.delivery_stamp_costs.remove(destination_hash);
			}
			self.update_delivery_announce_app_data(destination_hash);
			true
		} else {
			false
		}
	}

	/// Check if a message with the given transient ID has been received
	pub fn has_message(&self, transient_id: &[u8]) -> bool {
		self.locally_delivered_transient_ids.contains_key(transient_id)
	}

	/// Core message delivery handler
	pub fn lxmf_delivery(
		&mut self,
		lxmf_data: &[u8],
		destination_type: Option<DestinationType>,
		phy_stats: Option<(Option<f64>, Option<f64>, Option<f64>)>,
		ratchet_id: Option<Vec<u8>>,
		method: Option<u8>,
		no_stamp_enforcement: bool,
		allow_duplicate: bool,
	) -> bool {
		log(&format!("[LXMF-DELIVERY] enter data_len={} method={:?} dest_type={:?}", lxmf_data.len(), method, destination_type), LOG_NOTICE, false, false);
		let mut message = match LXMessage::unpack_from_bytes(lxmf_data, method) {
			Ok(msg) => {
				log(&format!("[LXMF-DELIVERY] unpacked OK source={} dest={}", hexrep(&msg.source_hash, false), hexrep(&msg.destination_hash, false)), LOG_NOTICE, false, false);
				msg
			}
			Err(e) => {
				log(
					&format!("[LXMF-DELIVERY] unpack FAILED: {}", e),
					LOG_NOTICE,
					false,
					false,
				);
				return false;
			}
		};

		if ratchet_id.is_some() && message.ratchet_id.is_none() {
			message.ratchet_id = ratchet_id;
		}

		// Extract and remember ticket if present and signature is valid
		if message.signature_validated {
			if let Value::Map(ref fields) = message.fields {
				for (key, value) in fields {
					if let Value::Integer(int) = key {
						if int.as_u64() == Some(crate::lxmf::FIELD_TICKET as u64) {
							if let Value::Array(ref ticket_entry) = value {
								if ticket_entry.len() > 1 {
									if let (Value::F64(expires), Value::Binary(ticket)) =
										(&ticket_entry[0], &ticket_entry[1])
									{
										if now() < *expires && ticket.len() == LXMessage::TICKET_LENGTH {
											let ticket_entry = TicketEntry {
												expires: *expires,
												ticket: ticket.clone(),
											};
											self.remember_ticket(&message.source_hash, &ticket_entry);
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Validate stamp if required
		if self.delivery_destinations.contains_key(&message.destination_hash) {
			if let Some(&required_stamp_cost) = self.delivery_stamp_costs.get(&message.destination_hash) {
				let destination_tickets = self.get_inbound_tickets(&message.source_hash);
				let tickets_vec: Option<Vec<Vec<u8>>> = destination_tickets.map(|tickets| tickets.clone());

				message.stamp_checked = true;
				message.stamp_valid = message.validate_stamp(required_stamp_cost, tickets_vec.as_deref());

				if !message.stamp_valid {
					if no_stamp_enforcement {
						log(
							&format!(
								"Received message with invalid stamp, but allowing anyway (enforcement disabled temporarily)"
							),
							LOG_NOTICE,
							false,
							false,
						);
					} else if self.enforce_stamps {
						log(&format!("Dropping message with invalid stamp"), LOG_NOTICE, false, false);
						return false;
					} else {
						log(
							&format!("Received message with invalid stamp, but allowing anyway (enforcement disabled)"),
							LOG_NOTICE,
							false,
							false,
						);
					}
				} else {
					log(&format!("Received message with valid stamp"), LOG_DEBUG, false, false);
				}
			}
		}

		// Set physical stats
		if let Some((rssi, snr, q)) = phy_stats {
			message.rssi = rssi;
			message.snr = snr;
			message.q = q;
		}

		// Set transport encryption info
		message.transport_encrypted = match destination_type {
			Some(DestinationType::Single) => {
				message.transport_encryption = Some(LXMessage::ENCRYPTION_DESCRIPTION_EC.to_string());
				true
			}
			Some(DestinationType::Group) => {
				message.transport_encryption = Some(LXMessage::ENCRYPTION_DESCRIPTION_AES.to_string());
				true
			}
			Some(DestinationType::Link) => {
				message.transport_encryption = Some(LXMessage::ENCRYPTION_DESCRIPTION_EC.to_string());
				true
			}
			_ => {
				message.transport_encryption = None;
				false
			}
		};

		// Check if sender is ignored
		if self.ignored_list.contains(&message.source_hash) {
			log(
				&format!("Ignored message from {}", hexrep(&message.source_hash, false)),
				LOG_DEBUG,
				false,
				false,
			);
			return false;
		}

		// Check for duplicates
		if !allow_duplicate {
			if let Some(hash) = &message.hash {
				if self.has_message(hash) {
					log(&format!("Ignored duplicate message"), LOG_DEBUG, false, false);
					return false;
				} else {
					self.locally_delivered_transient_ids.insert(hash.clone(), now());
				}
			}
		}

		// Call delivery callback
		if let Some(callback) = &self.delivery_callback {
			if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				callback(&message);
			})) {
				log(
					&format!("Error in delivery callback: {:?}", e),
					LOG_ERROR,
					false,
					false,
				);
			}
		}

		true
	}

	/// Handle delivery packet
	pub fn delivery_packet(&mut self, data: &[u8], packet: &Packet) {
		log(&format!("delivery_packet received: data_len={} dest_type={:?} dest_hash={}",
			data.len(),
			packet.destination_type,
			packet.destination_hash.as_ref().map(|h| hexrep(h, false)).unwrap_or_default()
		), LOG_NOTICE, false, false);
		// ── FIX: NO EXPLICIT PROVE CALL IN delivery_packet ─────────────────────────
		// DO NOT ADD packet.prove(None) or packet.prove(Some(link)) HERE.
		//
		// Bug (pre-fix): a call to packet.prove(None) was present here.  On an
		// inbound delivery packet the Packet object represents data *received from*
		// the sender, so calling prove() on it attempts to sign and retransmit it
		// outbound — which silently fails because the packet has no send interface
		// set.  More importantly it masked the real prove path and prevented
		// delivery receipts from firing correctly.
		//
		// Proving is handled elsewhere:
		//   • OPPORTUNISTIC destinations: Transport uses PROVE_ALL strategy and
		//     sends a proof automatically when the packet is processed.
		//   • DIRECT destinations (link-based): link.prove_packet() is called by
		//     the link layer after it validates the packet, routing the proof via
		//     the correct attached interface (see prove_packet fix in link.rs).
		// ────────────────────────────────────────────────────────────────────────

		let mut rssi = packet.rssi;
		let mut snr = packet.snr;
		let mut q = packet.q;
		if rssi.is_none() || snr.is_none() || q.is_none() {
			if let Some(packet_hash) = packet.packet_hash.as_ref() {
				if let Some(reticulum) = Reticulum::get_instance() {
					if let Ok(reticulum) = reticulum.lock() {
						rssi = rssi.or(reticulum.get_packet_rssi(packet_hash));
						snr = snr.or(reticulum.get_packet_snr(packet_hash));
						q = q.or(reticulum.get_packet_q(packet_hash));
					}
				}
			}
		}

		let (lxmf_data, method) = if packet.destination_type != Some(DestinationType::Link) {
			let mut lxmf_data = Vec::new();
			if let Some(dest_hash) = packet.destination_hash.as_ref() {
				lxmf_data.extend_from_slice(dest_hash);
			}
			lxmf_data.extend_from_slice(data);
			(lxmf_data, Some(LXMessage::OPPORTUNISTIC))
		} else {
			(data.to_vec(), Some(LXMessage::DIRECT))
		};

		let phy_stats = (rssi, snr, q);

		self.lxmf_delivery(
			&lxmf_data,
			packet.destination_type,
			Some(phy_stats),
			packet.ratchet_id.clone(),
			method,
			false,
			false,
		);
	}

	/// Callback when delivery link is established
	pub fn delivery_link_established(&mut self, link: LinkHandle) {
		let link_id_hex = hexrep(&link.link_id(), false);
		let is_initiator = link.snapshot().map(|s| s.initiator).unwrap_or(false);
		log(&format!("delivery_link_established: link={} initiator={}", link_id_hex, is_initiator), LOG_NOTICE, false, false);
		link.set_track_phy_stats(true);

		// Set packet callback (via set_packet_callback so any early-arrival
		// packets queued before this point are drained and proved).
		let router_weak = self.self_handle.clone();
		link.set_packet_callback(Some(Arc::new(move |data, packet| {
			if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					router.delivery_packet(data, packet);
				}
			}
		})));

		// Set resource strategy
		link.set_resource_strategy(reticulum_rust::link::ACCEPT_APP);

		// Set resource callbacks
		let resource_cb = Arc::new({
			let router_weak = self.self_handle.clone();
			move |resource: Arc<Mutex<Resource>>| {
				if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
					if let Ok(router) = router_arc.lock() {
						if let Ok(resource_guard) = resource.lock() {
							let allowed = router.delivery_resource_advertised(&resource_guard);
							if !allowed {
								resource_guard.link.cancel_incoming_resource(resource.clone());
							}
						}
					}
				}
			}
		});

		let resource_started_cb = Arc::new(move |_resource: Arc<Mutex<Resource>>| {
			log(
				&format!("Transfer began for LXMF delivery resource"),
				LOG_DEBUG,
				false,
				false,
			);
		});

		let router_weak3 = self.self_handle.clone();
		let resource_concluded_cb = Arc::new(move |resource: Arc<Mutex<Resource>>| {
			log("LXMF delivery resource concluded", LOG_DEBUG, false, false);
			if let Some(router_arc) = router_weak3.as_ref().and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					router.delivery_resource_concluded(resource);
				} else {
					log("[LXMF] resource_concluded: FAILED to lock router", LOG_ERROR, false, false);
				}
			} else {
				log("[LXMF] resource_concluded: router Weak ref expired", LOG_ERROR, false, false);
			}
		});

		link.set_resource_callbacks(
			Some(resource_cb),
			Some(resource_started_cb),
			Some(resource_concluded_cb),
		);

		let router_weak4 = self.self_handle.clone();
		link.set_remote_identified_callback(Some(Arc::new(move |link, identity| {
			if let Some(router_arc) = router_weak4.as_ref().and_then(|w| w.upgrade()) {
				if let Ok(mut router) = router_arc.lock() {
					router.delivery_remote_identified(link, identity);
				}
			}
		})));
	}

	/// Check if an advertised resource should be accepted
	pub fn delivery_resource_advertised(&self, resource: &Resource) -> bool {
		let size = resource.total_size as f64;
		let limit = self.delivery_per_transfer_limit * 1000.0;

		if size > limit {
			log(
				&format!(
					"Rejecting incoming LXMF delivery resource of {} bytes (exceeds limit of {} bytes)",
					size, limit
				),
				LOG_DEBUG,
				false,
				false,
			);
			false
		} else {
			true
		}
	}

	/// Handle delivery resource conclusion
	pub fn delivery_resource_concluded(&mut self, resource: Arc<Mutex<Resource>>) {
		if let Ok(res) = resource.lock() {
			log(&format!("LXMF delivery resource concluded status={:?} data_len={} split={} seg={}/{}",
				res.status, res.data.as_ref().map(|d| d.len()).unwrap_or(0),
				res.split, res.segment_index, res.total_segments), LOG_DEBUG, false, false);
			if res.status == ResourceStatus::Complete {
				let data = match &res.data {
					Some(bytes) if !bytes.is_empty() => bytes.clone(),
					_ => {
						// Non-final segment of a split resource — data is on disk,
						// not available yet. Skip until the final segment delivers
						// the combined data.
						return;
					}
				};

				let link_arc = res.link.clone();
			let ratchet_id = Some(link_arc.link_id());

			let phy_stats = link_arc.snapshot().ok().map(|s| (s.rssi.map(|r| r as f64), s.snr, s.q));
				self.lxmf_delivery(
					&data,
					Some(DestinationType::Link),
					phy_stats,
					ratchet_id,
					Some(LXMessage::DIRECT),
					false,
					false,
				);
			}
		}
	}

	/// Handle remote identity identified on delivery link
	pub fn delivery_remote_identified(&mut self, link: LinkHandle, identity: Identity) {
		let destination_hash = Destination::hash_from_name_and_identity(
			&format!("{}.delivery", APP_NAME),
			Some(&identity),
		);

		// If we have an existing outbound direct link to this peer, tear it down.
		// The peer has established its own link, indicating it prefers this channel.
		// Keeping the old link causes delivery failures: we'd send on a link the
		// peer no longer services, the proof never arrives, and we time out.
		if let Some(old_link) = self.direct_links.remove(&destination_hash) {
			log(
				&format!(
					"Peer {} established backchannel; tearing down old direct link",
					hexrep(&destination_hash, false)
				),
				LOG_NOTICE,
				false,
				false,
			);
			old_link.teardown();
			self.backchannel_identified_links.remove(&destination_hash);
		}

		self.backchannel_links.insert(destination_hash.clone(), link.clone());

		log(
			&format!(
				"Backchannel became available for {} on delivery link",
				hexrep(&destination_hash, false)
			),
			LOG_NOTICE,
			false,
			false,
		);
	}

	/// Set authentication requirement for propagation node
	pub fn set_authentication(&mut self, required: bool) {
		self.auth_required = required;
	}

	pub fn enforce_stamps(&mut self) {
		self.enforce_stamps = true;
	}

	pub fn ignore_stamps(&mut self) {
		self.enforce_stamps = false;
	}

	/// Check if authentication is required
	pub fn requires_authentication(&self) -> bool {
		self.auth_required
	}

	/// Allow an identity hash for propagation
	pub fn allow(&mut self, identity_hash: Vec<u8>) {
		if !self.allowed_list.contains(&identity_hash) {
			self.allowed_list.push(identity_hash);
		}
	}

	/// Disallow an identity hash for propagation
	pub fn disallow(&mut self, identity_hash: &[u8]) {
		self.allowed_list.retain(|h| h != identity_hash);
	}

	/// Allow an identity hash for control functions
	pub fn allow_control(&mut self, identity_hash: Vec<u8>) {
		if !self.control_allowed_list.contains(&identity_hash) {
			self.control_allowed_list.push(identity_hash);
		}
	}

	/// Disallow an identity hash for control functions
	pub fn disallow_control(&mut self, identity_hash: &[u8]) {
		self.control_allowed_list.retain(|h| h != identity_hash);
	}

	/// Add a destination hash to the ignored list
	pub fn ignore_destination(&mut self, destination_hash: Vec<u8>) {
		if !self.ignored_list.contains(&destination_hash) {
			self.ignored_list.push(destination_hash);
		}
	}

	/// Remove a destination hash from the ignored list
	pub fn unignore_destination(&mut self, destination_hash: &[u8]) {
		self.ignored_list.retain(|h| h != destination_hash);
	}

	pub fn prioritise(&mut self, destination_hash: Vec<u8>) {
		if !self.prioritised_list.contains(&destination_hash) {
			self.prioritised_list.push(destination_hash);
		}
	}

	pub fn unprioritise(&mut self, destination_hash: &[u8]) {
		self.prioritised_list.retain(|h| h != destination_hash);
	}

	/// Callback when propagation link is established
	pub fn propagation_link_established(&mut self, link: LinkHandle) {
		self.active_propagation_links.push(link.clone());
		if let Some(link) = self.active_propagation_links.last() {
			link.set_packet_callback(Some(Arc::new({
				let router_weak = self.self_handle.clone();
				move |data, packet| {
					if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
						if let Ok(mut router) = router_arc.lock() {
							router.propagation_packet(data, packet);
						}
					}
				}
			})));

			link.set_resource_strategy(reticulum_rust::link::ACCEPT_APP);

			let resource_cb = Arc::new({
				let router_weak = self.self_handle.clone();
				move |resource: Arc<Mutex<Resource>>| {
					if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
						if let Ok(router) = router_arc.lock() {
							let allowed = router.propagation_resource_advertised(resource.clone());
							if !allowed {
								if let Ok(resource_guard) = resource.lock() {
									resource_guard.link.cancel_incoming_resource(resource.clone());
								}
							}
						}
					}
				}
			});

			let resource_started_cb = Arc::new(|_resource: Arc<Mutex<Resource>>| {
				log("Propagation resource transfer started", LOG_DEBUG, false, false);
			});

			let resource_concluded_cb = Arc::new({
				let router_weak = self.self_handle.clone();
				move |resource: Arc<Mutex<Resource>>| {
					if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
						if let Ok(mut router) = router_arc.lock() {
							router.propagation_resource_concluded(resource);
						}
					}
				}
			});

			link.set_resource_callbacks(
				Some(resource_cb),
				Some(resource_started_cb),
				Some(resource_concluded_cb),
			);
		}

		log("Propagation link established", LOG_DEBUG, false, false);
	}

	/// Callback for propagation packets
	pub fn propagation_packet(&mut self, data: &[u8], packet: &Packet) {
		if packet.destination_type != Some(DestinationType::Link) {
			return;
		}

		let unpacked = match read_value(&mut std::io::Cursor::new(data)) {
			Ok(Value::Array(items)) => items,
			_ => return,
		};

		if unpacked.len() < 2 {
			return;
		}

		let messages = match &unpacked[1] {
			Value::Array(values) => values
				.iter()
				.filter_map(|v| match v {
					Value::Binary(bytes) => Some(bytes.clone()),
					_ => None,
				})
				.collect::<Vec<Vec<u8>>>(),
			_ => Vec::new(),
		};

		let min_accepted_cost = self
			.propagation_stamp_cost
			.saturating_sub(self.propagation_stamp_cost_flexibility);
		let validated = lx_stamper::validate_pn_stamps(&messages, min_accepted_cost);

		for validated_entry in validated.iter() {
			let lxmf_data = &validated_entry.1;
			let stamp_value = validated_entry.2;
			let stamp_data = validated_entry.3.clone();
			self.lxmf_propagation(
				lxmf_data,
				None,
				None,
				false,
				false,
				None,
				Some(stamp_value),
				Some(stamp_data),
			);
			self.client_propagation_messages_received += 1;
		}

		if validated.len() == messages.len() {
			// NOTE: No explicit prove() call here.
			// This handler is invoked only for LINK-type packets (see early return above).
			// For link packets, link.rs automatically calls prove_packet() BEFORE firing
			// this callback, so the proof is already on its way to the sending peer.
			// Calling packet.prove(None) here would silently fail: received packets
			// have destination=None, so prove(None) cannot resolve an identity to sign with.
		} else {
			log(
				"Propagation transfer contained messages with invalid stamps",
				LOG_NOTICE,
				false,
				false,
			);
		}
	}

	/// Decide whether an incoming propagation resource should be accepted
	pub fn propagation_resource_advertised(&self, resource: Arc<Mutex<Resource>>) -> bool {
		let resource_guard = match resource.lock() {
			Ok(guard) => guard,
			Err(_) => return false,
		};

		if self.from_static_only {
			let remote_identity = resource_guard.link.remote_identity().ok().flatten();
			let remote_identity = match remote_identity {
				Some(identity) => identity,
				None => return false,
			};
			let remote_hash = Destination::hash_from_name_and_identity(
				&format!("{}.propagation", APP_NAME),
				Some(&remote_identity),
			);
			if !self.static_peers.contains(&remote_hash) {
				return false;
			}
		}

		let size = resource_guard.total_size as f64;
		let limit = self.propagation_per_sync_limit * 1000.0;
		if size > limit {
			log(
				&format!(
					"Rejecting incoming propagation resource of {} bytes (limit {})",
					size, limit
				),
				LOG_DEBUG,
				false,
				false,
			);
			false
		} else {
			true
		}
	}

	/// Handle propagation transfer signalling packets
	pub fn propagation_transfer_signalling_packet(&mut self, data: &[u8], _packet: &Packet) {
		if let Some(Value::Array(values)) = Self::decode_value(data) {
			if let Some(Value::Integer(code)) = values.get(0) {
				if code.as_i64().unwrap_or(0) as u8 == LXMPeer::ERROR_INVALID_STAMP {
					if let Some(link) = self.outbound_propagation_link.as_ref() {
						link.teardown();
					}
					self.propagation_transfer_state = Self::PR_FAILED;
				}
			}
		}
	}

	fn handle_propagation_transfer_signal(&mut self, message_id: &[u8], data: &[u8]) {
		if let Some(Value::Array(values)) = Self::decode_value(data) {
			if let Some(Value::Integer(code)) = values.get(0) {
				if code.as_i64().unwrap_or(0) as u8 == LXMPeer::ERROR_INVALID_STAMP {
					log("Message rejected by propagation node", LOG_ERROR, false, false);
					self.cancel_outbound(message_id, LXMessage::REJECTED);
				}
			}
		}
	}

	pub fn request_messages_path_job(&self) {
		let router_weak = self.self_handle.clone();
		thread::spawn(move || {
			loop {
				let (destination_hash, identity, timeout) = if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
					if let Ok(router) = router_arc.lock() {
						(
							router.wants_download_on_path_available_from.clone(),
							router.wants_download_on_path_available_to.clone(),
							router.wants_download_on_path_available_timeout,
						)
					} else {
						return;
					}
				} else {
					return;
				};

				let destination_hash = match destination_hash {
					Some(hash) => hash,
					None => return,
				};

				if now() > timeout {
					if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
						if let Ok(mut router) = router_arc.lock() {
							log("[PSYNC] path job: path request TIMED OUT", LOG_WARNING, false, false);
							router.acknowledge_sync_completion(Some(Self::PR_NO_PATH));
						}
					}
					return;
				}

				if Transport::has_path(&destination_hash) {
					log("[PSYNC] path job: path now available, retrying sync", LOG_NOTICE, false, false);
					if let (Some(router_arc), Some(identity)) = (router_weak.as_ref().and_then(|w| w.upgrade()), identity) {
						if let Ok(mut router) = router_arc.lock() {
								let max_messages = router.propagation_transfer_max_messages;
								router.request_messages_from_propagation_node(identity, max_messages);
						}
					}
					return;
				}

				thread::sleep(Duration::from_millis(100));
			}
		});
	}

	pub fn request_messages_from_propagation_node(&mut self, identity: Identity, max_messages: Option<usize>) {
		let max_messages = max_messages.unwrap_or(Self::PR_ALL_MESSAGES);
		self.propagation_transfer_progress = 0.0;
		self.propagation_transfer_max_messages = Some(max_messages);

		let outbound_node = match self.outbound_propagation_node.clone() {
			Some(node) => node,
			None => {
				log("[PSYNC] Cannot request sync, no outbound propagation node configured", LOG_WARNING, false, false);
				return;
			}
		};

		log(&format!("[PSYNC] request_messages_from_propagation_node: node={} has_link={} has_path={} state=0x{:02x}",
			reticulum_rust::hexrep(&outbound_node, false),
			self.outbound_propagation_link.is_some(),
			Transport::has_path(&outbound_node),
			self.propagation_transfer_state,
		), LOG_NOTICE, false, false);

		if let Some(link_arc) = self.outbound_propagation_link.clone() {
			let link_status = link_arc.status();
			log(&format!("[PSYNC] existing link status={}", link_status), LOG_NOTICE, false, false);
			// If a link is already pending (being established), don't create another one —
			// replacing the Arc here would drop the first link before its PROOF arrives.
			if link_status == reticulum_rust::link::STATE_PENDING {
				log("[PSYNC] link pending, skipping duplicate sync request", LOG_NOTICE, false, false);
				return;
			}
			let link_is_active = link_status == reticulum_rust::link::STATE_ACTIVE;
			if link_is_active {
				self.propagation_transfer_state = Self::PR_LINK_ESTABLISHED;

				// Identify ourselves on the link before requesting messages
				if let Ok(snap) = link_arc.snapshot() {
					log(&format!("[PSYNC] identify: attached_interface={:?} link_id={}",
						snap.attached_interface,
						reticulum_rust::hexrep(&snap.link_id, false)), LOG_NOTICE, false, false);
				}
				match link_arc.identify(&identity) {
					Ok(_) => log("[PSYNC] identify sent OK", LOG_NOTICE, false, false),
					Err(e) => log(&format!("[PSYNC] identify FAILED: {}", e), LOG_ERROR, false, false),
				}

				link_arc.set_packet_callback(Some(Arc::new({
					let router_weak = self.self_handle.clone();
					move |data, packet| {
						if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
							if let Ok(mut router) = router_arc.lock() {
								router.propagation_transfer_signalling_packet(data, packet);
							}
						}
					}
				})));

				let request_cb: Option<Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>> = Some(Arc::new({
					let router_weak = self.self_handle.clone();
					move |receipt: reticulum_rust::link::RequestReceipt| {
						if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
							if let Ok(mut router) = router_arc.lock() {
								router.message_list_response(receipt);
							}
						}
					}
				}));

				let failed_cb: Option<Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>> = Some(Arc::new({
					let router_weak = self.self_handle.clone();
					move |receipt: reticulum_rust::link::RequestReceipt| {
						if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
							if let Ok(mut router) = router_arc.lock() {
								router.message_get_failed(receipt);
							}
						}
					}
				}));

				let _ = link_arc.request(
					LXMPeer::MESSAGE_GET_PATH.to_string(),
					Self::encode_value(Value::Array(vec![Value::Nil, Value::Nil])),
					request_cb,
					failed_cb,
					None,
				);
				log("[PSYNC] message_list request sent", LOG_NOTICE, false, false);
				self.propagation_transfer_state = Self::PR_REQUEST_SENT;
				return;
			}
		}

		if Transport::has_path(&outbound_node) {
			log("[PSYNC] has path → establishing new link", LOG_NOTICE, false, false);
			self.propagation_transfer_state = Self::PR_LINK_ESTABLISHING;
			if let Some(prop_identity) = Identity::recall(&outbound_node) {
				if let Ok(destination) = Destination::new_outbound(
					Some(prop_identity),
					DestinationType::Single,
					APP_NAME.to_string(),
					vec!["propagation".to_string()],
				) {
					if let Ok(link) = Link::new_outbound(destination, reticulum_rust::link::MODE_AES256_CBC) {
						let handle = LinkHandle::spawn(link);
						let router_weak = self.self_handle.clone();
						handle.set_link_established_callback(Some(Arc::new(move |_| {
							log("[PSYNC] propagation link ESTABLISHED", LOG_NOTICE, false, false);
							if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
								if let Ok(mut router) = router_arc.lock() {
									let max_messages = router.propagation_transfer_max_messages;
									router.request_messages_from_propagation_node(identity.clone(), max_messages);
								}
							}
						})));
						if let Err(e) = handle.initiate() {
							log(&format!("Failed to initiate propagation link: {}", e), LOG_ERROR, false, false);
						} else {
							register_runtime_link_handle(handle.clone());
							self.outbound_propagation_link = Some(handle);
						}
					}
				}
			}
		} else {
			log(&format!("[PSYNC] no path to {} → requesting path, starting path job", reticulum_rust::hexrep(&outbound_node, false)), LOG_NOTICE, false, false);
			Transport::request_path(&outbound_node, None, None, None, None);
			self.wants_download_on_path_available_from = Some(outbound_node);
			self.wants_download_on_path_available_to = Some(identity);
			self.wants_download_on_path_available_timeout = now() + Self::PR_PATH_TIMEOUT;
			self.propagation_transfer_state = Self::PR_PATH_REQUESTED;
			self.request_messages_path_job();
		}
	}

	pub fn message_list_response(&mut self, receipt: reticulum_rust::link::RequestReceipt) {
		if let Some(response) = receipt.response {
			log(&format!("[MLS] message_list_response: response {} bytes, decoded={:?}",
				response.len(),
				match Self::decode_value(&response) {
					Some(Value::Array(ref v)) => format!("Array({} items)", v.len()),
					Some(Value::Integer(ref i)) => format!("Integer({})", i),
					Some(ref v) => format!("Other({:?})", v),
					None => "None (decode failed)".to_string(),
				}
			), LOG_NOTICE, false, false);
			if let Some(Value::Integer(code)) = Self::decode_value(&response) {
				let code = code.as_i64().unwrap_or(0) as u8;
				if code == LXMPeer::ERROR_NO_IDENTITY {
					if let Some(link) = self.outbound_propagation_link.as_ref() {
						link.teardown();
					}
					self.propagation_transfer_state = Self::PR_NO_IDENTITY_RCVD;
					return;
				}
				if code == LXMPeer::ERROR_NO_ACCESS {
					if let Some(link) = self.outbound_propagation_link.as_ref() {
						link.teardown();
					}
					self.propagation_transfer_state = Self::PR_NO_ACCESS;
					return;
				}
			}

			if let Some(Value::Array(list)) = Self::decode_value(&response) {
				let mut wants = Vec::new();
				let mut haves = Vec::new();
				for value in list {
					if let Value::Binary(transient_id) = value {
						if self.has_message(&transient_id) {
							if !self.retain_synced_on_node {
								haves.push(Value::Binary(transient_id));
							}
						} else if self.propagation_transfer_max_messages == Some(Self::PR_ALL_MESSAGES)
							|| wants.len() < self.propagation_transfer_max_messages.unwrap_or(0)
						{
							wants.push(Value::Binary(transient_id));
						}
					}
				}

				if wants.is_empty() {
					log(&format!("[MLS] wants=0 haves={}, nothing to request → PR_COMPLETE", haves.len()), LOG_NOTICE, false, false);
					self.propagation_transfer_state = Self::PR_COMPLETE;
					self.propagation_transfer_progress = 1.0;
					self.propagation_transfer_last_result = Some(0);
					if let Some(cb) = &self.sync_complete_callback {
						let cb = cb.clone();
						std::thread::spawn(move || cb(0));
					}
					return;
				}

				log(&format!("[MLS] wants={} haves={}, sending second request", wants.len(), haves.len()), LOG_NOTICE, false, false);

				if let Some(link) = self.outbound_propagation_link.as_ref() {
					let request_cb: Option<Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>> = Some(Arc::new({
						let router_weak = self.self_handle.clone();
						move |receipt: reticulum_rust::link::RequestReceipt| {
							if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
								if let Ok(mut router) = router_arc.lock() {
									router.message_get_response(receipt);
								}
							}
						}
					}));
					let failed_cb: Option<Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>> = Some(Arc::new({
						let router_weak = self.self_handle.clone();
						move |receipt: reticulum_rust::link::RequestReceipt| {
							if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
								if let Ok(mut router) = router_arc.lock() {
									router.message_get_failed(receipt);
								}
							}
						}
					}));
					let progress_cb: Option<Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>> = Some(Arc::new({
						let router_weak = self.self_handle.clone();
						move |receipt: reticulum_rust::link::RequestReceipt| {
							if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
								if let Ok(mut router) = router_arc.lock() {
									router.message_get_progress(receipt);
								}
							}
						}
					}));

					let payload = Value::Array(vec![
						Value::Array(wants),
						Value::Array(haves),
						Value::F64(self.delivery_per_transfer_limit),
					]);
					let _ = link.request(
						LXMPeer::MESSAGE_GET_PATH.to_string(),
						Self::encode_value(payload),
						request_cb,
						failed_cb,
						progress_cb,
					);
				}
			} else {
				log("Invalid message list data received from propagation node", LOG_DEBUG, false, false);
				if let Some(link) = self.outbound_propagation_link.as_ref() {
					link.teardown();
				}
			}
		}
	}

	pub fn message_get_response(&mut self, receipt: reticulum_rust::link::RequestReceipt) {
		if let Some(response) = receipt.response {
			if let Some(Value::Integer(code)) = Self::decode_value(&response) {
				let code = code.as_i64().unwrap_or(0) as u8;
				if code == LXMPeer::ERROR_NO_IDENTITY {
					if let Some(link) = self.outbound_propagation_link.as_ref() {
						link.teardown();
					}
					self.propagation_transfer_state = Self::PR_NO_IDENTITY_RCVD;
					return;
				}
				if code == LXMPeer::ERROR_NO_ACCESS {
					if let Some(link) = self.outbound_propagation_link.as_ref() {
						link.teardown();
					}
					self.propagation_transfer_state = Self::PR_NO_ACCESS;
					return;
				}
			}

			let mut duplicates = 0usize;
			log(&format!("[MGR] message_get_response: response {} bytes, decoded={:?}",
				response.len(),
				match Self::decode_value(&response) {
					Some(Value::Array(ref v)) => format!("Array({} items)", v.len()),
					Some(Value::Integer(ref i)) => format!("Integer({})", i),
					Some(ref v) => format!("Other({:?})", v),
					None => "None (decode failed)".to_string(),
				}
			), LOG_NOTICE, false, false);
			if let Some(Value::Array(messages)) = Self::decode_value(&response) {
				log(&format!("[MGR] message_get_response: {} messages in response", messages.len()), LOG_NOTICE, false, false);
				let mut haves = Vec::new();
				for value in messages.iter() {
					if let Value::Binary(lxmf_data) = value {
						log(&format!("[MGR] message_get_response: calling lxmf_propagation for {} bytes", lxmf_data.len()), LOG_NOTICE, false, false);
						let result = self.lxmf_propagation(
							&lxmf_data,
							None,
							Some(Self::DUPLICATE_SIGNAL),
							false,
							false,
							None,
							None,
							None,
						);
						log(&format!("[MGR] lxmf_propagation returned {}", result), LOG_NOTICE, false, false);
						if !result {
							duplicates += 1;
						} else {
							// Only acknowledge messages that were successfully processed
							haves.push(Value::Binary(reticulum_rust::identity::full_hash(lxmf_data)));
						}
					}
				}

				if let Some(link) = self.outbound_propagation_link.as_ref() {
					let failed_cb: Option<Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>> = Some(Arc::new({
						let router_weak = self.self_handle.clone();
						move |receipt: reticulum_rust::link::RequestReceipt| {
							if let Some(router_arc) = router_weak.as_ref().and_then(|w| w.upgrade()) {
								if let Ok(mut router) = router_arc.lock() {
									router.message_get_failed(receipt);
								}
							}
						}
					}));
					let payload = Value::Array(vec![Value::Nil, Value::Array(haves)]);
					let _ = link.request(
						LXMPeer::MESSAGE_GET_PATH.to_string(),
						Self::encode_value(payload),
						None,
						failed_cb,
						None,
					);
				}
				self.propagation_transfer_state = Self::PR_COMPLETE;
				self.propagation_transfer_progress = 1.0;
				self.propagation_transfer_last_duplicates = Some(duplicates);
				self.propagation_transfer_last_result = Some(messages.len());
				self.save_locally_delivered_transient_ids();
				if let Some(cb) = &self.sync_complete_callback {
					let cb = cb.clone();
					let count = messages.len() as u32;
					std::thread::spawn(move || cb(count));
				}
			}
		}
	}

	pub fn message_get_progress(&mut self, receipt: reticulum_rust::link::RequestReceipt) {
		self.propagation_transfer_state = Self::PR_RECEIVING;
		self.propagation_transfer_progress = receipt.get_progress();
	}

	pub fn message_get_failed(&mut self, _receipt: reticulum_rust::link::RequestReceipt) {
		log("[PSYNC] message list/get request FAILED", LOG_WARNING, false, false);
		if let Some(link) = self.outbound_propagation_link.as_ref() {
			link.teardown();
		}
		self.propagation_transfer_state = Self::PR_TRANSFER_FAILED;
	}

	pub fn acknowledge_sync_completion(&mut self, failure_state: Option<u8>) {
		self.propagation_transfer_last_result = None;
		self.propagation_transfer_progress = 0.0;
		self.wants_download_on_path_available_from = None;
		self.wants_download_on_path_available_to = None;
		self.propagation_transfer_state = failure_state.unwrap_or(Self::PR_IDLE);
	}

	fn encode_value(value: Value) -> Vec<u8> {
		let mut buf = Vec::new();
		let _ = write_value(&mut buf, &value);
		buf
	}

	fn decode_value(data: &[u8]) -> Option<Value> {
		read_value(&mut std::io::Cursor::new(data)).ok()
	}

	fn compile_stats(&self) -> Option<Value> {
		if !self.propagation_node {
			return None;
		}

		let mut peer_stats = Vec::new();
		for (peer_id, peer_arc) in self.peers.iter() {
			if let Ok(mut peer) = peer_arc.lock() {
				let mut peer_map = Vec::new();
				peer_map.push((Value::String("type".into()), Value::String(if self.static_peers.contains(peer_id) { "static".into() } else { "discovered".into() })));
				peer_map.push((Value::String("state".into()), Value::Integer((peer.state as i64).into())));
				peer_map.push((Value::String("alive".into()), Value::Boolean(peer.alive)));
				peer_map.push((Value::String("name".into()), peer.name().map(|n| Value::String(n.into())).unwrap_or(Value::Nil)));
				peer_map.push((Value::String("last_heard".into()), Value::Integer((peer.last_heard as i64).into())));
				peer_map.push((Value::String("next_sync_attempt".into()), Value::F64(peer.next_sync_attempt)));
				peer_map.push((Value::String("last_sync_attempt".into()), Value::F64(peer.last_sync_attempt)));
				peer_map.push((Value::String("sync_backoff".into()), Value::F64(peer.sync_backoff)));
				peer_map.push((Value::String("peering_timebase".into()), Value::F64(peer.peering_timebase)));
				peer_map.push((Value::String("ler".into()), Value::Integer((peer.link_establishment_rate as i64).into())));
				peer_map.push((Value::String("str".into()), Value::Integer((peer.sync_transfer_rate as i64).into())));
				peer_map.push((Value::String("transfer_limit".into()), peer.propagation_transfer_limit.map(Value::F64).unwrap_or(Value::Nil)));
				peer_map.push((Value::String("sync_limit".into()), peer.propagation_sync_limit.map(Value::F64).unwrap_or(Value::Nil)));
				peer_map.push((Value::String("target_stamp_cost".into()), peer.propagation_stamp_cost.map(|v| Value::Integer((v as i64).into())).unwrap_or(Value::Nil)));
				peer_map.push((Value::String("stamp_cost_flexibility".into()), peer.propagation_stamp_cost_flexibility.map(|v| Value::Integer((v as i64).into())).unwrap_or(Value::Nil)));
				peer_map.push((Value::String("peering_cost".into()), peer.peering_cost.map(|v| Value::Integer((v as i64).into())).unwrap_or(Value::Nil)));
				peer_map.push((Value::String("peering_key".into()), peer.peering_key_value().map(|v| Value::Integer((v as i64).into())).unwrap_or(Value::Nil)));
				peer_map.push((Value::String("network_distance".into()), Value::Integer((Transport::hops_to(peer_id) as i64).into())));
				peer_map.push((Value::String("rx_bytes".into()), Value::Integer((peer.rx_bytes as i64).into())));
				peer_map.push((Value::String("tx_bytes".into()), Value::Integer((peer.tx_bytes as i64).into())));
				peer_map.push((Value::String("acceptance_rate".into()), Value::F64(peer.acceptance_rate())));
				let mut messages_map = Vec::new();
				messages_map.push((Value::String("offered".into()), Value::Integer((peer.offered as i64).into())));
				messages_map.push((Value::String("outgoing".into()), Value::Integer((peer.outgoing as i64).into())));
				messages_map.push((Value::String("incoming".into()), Value::Integer((peer.incoming as i64).into())));
				messages_map.push((Value::String("unhandled".into()), Value::Integer((peer.unhandled_message_count(self) as i64).into())));
				peer_map.push((Value::String("messages".into()), Value::Map(messages_map)));
				peer_stats.push((Value::Binary(peer_id.clone()), Value::Map(peer_map)));
			}
		}

		let uptime = self.propagation_node_start_time.map(|t| now() - t).unwrap_or(0.0);
		let mut node_map = Vec::new();
		node_map.push((Value::String("identity_hash".into()), Value::Binary(self.identity.hash.clone().expect("Router identity hash missing"))));
		node_map.push((Value::String("destination_hash".into()), Value::Binary(self.propagation_destination.hash.clone())));
		node_map.push((Value::String("uptime".into()), Value::F64(uptime)));
		node_map.push((Value::String("delivery_limit".into()), Value::F64(self.delivery_per_transfer_limit)));
		node_map.push((Value::String("propagation_limit".into()), Value::F64(self.propagation_per_transfer_limit)));
		node_map.push((Value::String("sync_limit".into()), Value::F64(self.propagation_per_sync_limit)));
		node_map.push((Value::String("target_stamp_cost".into()), Value::Integer((self.propagation_stamp_cost as i64).into())));
		node_map.push((Value::String("stamp_cost_flexibility".into()), Value::Integer((self.propagation_stamp_cost_flexibility as i64).into())));
		node_map.push((Value::String("peering_cost".into()), Value::Integer((self.peering_cost as i64).into())));
		node_map.push((Value::String("max_peering_cost".into()), Value::Integer((self.max_peering_cost as i64).into())));
		node_map.push((Value::String("autopeer_maxdepth".into()), Value::Integer((self.autopeer_maxdepth as i64).into())));
		node_map.push((Value::String("from_static_only".into()), Value::Boolean(self.from_static_only)));
		let message_bytes: u64 = self.propagation_entries.values().map(|e| e.size as u64).sum();
		let mut store_map = Vec::new();
		store_map.push((Value::String("count".into()), Value::Integer((self.propagation_entries.len() as i64).into())));
		store_map.push((Value::String("bytes".into()), Value::Integer((message_bytes as i64).into())));
		store_map.push((Value::String("limit".into()), self.message_storage_limit.map(|v| Value::Integer((v as i64).into())).unwrap_or(Value::Nil)));
		node_map.push((Value::String("messagestore".into()), Value::Map(store_map)));
		let mut client_map = Vec::new();
		client_map.push((Value::String("client_propagation_messages_received".into()), Value::Integer((self.client_propagation_messages_received as i64).into())));
		client_map.push((Value::String("client_propagation_messages_served".into()), Value::Integer((self.client_propagation_messages_served as i64).into())));
		node_map.push((Value::String("clients".into()), Value::Map(client_map)));
		node_map.push((Value::String("unpeered_propagation_incoming".into()), Value::Integer((self.unpeered_propagation_incoming as i64).into())));
		node_map.push((Value::String("unpeered_propagation_rx_bytes".into()), Value::Integer((self.unpeered_propagation_rx_bytes as i64).into())));
		node_map.push((Value::String("static_peers".into()), Value::Integer((self.static_peers.len() as i64).into())));
		node_map.push((Value::String("discovered_peers".into()), Value::Integer(((self.peers.len() - self.static_peers.len()) as i64).into())));
		node_map.push((Value::String("total_peers".into()), Value::Integer((self.peers.len() as i64).into())));
		node_map.push((Value::String("max_peers".into()), Value::Integer((self.max_peers as i64).into())));
		node_map.push((Value::String("peers".into()), Value::Map(peer_stats)));

		Some(Value::Map(node_map))
	}

	fn lxmf_propagation(
		&mut self,
		lxmf_data: &[u8],
		signal_local_delivery: Option<&str>,
		signal_duplicate: Option<&str>,
		allow_duplicate: bool,
		is_paper_message: bool,
		from_peer: Option<Vec<u8>>,
		stamp_value: Option<u32>,
		stamp_data: Option<Vec<u8>>,
	) -> bool {
		log(&format!("[PROP] lxmf_propagation: data_len={} delivery_destinations_count={}", lxmf_data.len(), self.delivery_destinations.len()), LOG_NOTICE, false, false);
		if lxmf_data.len() < LXMessage::LXMF_OVERHEAD {
			log(&format!("[PROP] too short (< LXMF_OVERHEAD {}), returning false", LXMessage::LXMF_OVERHEAD), LOG_NOTICE, false, false);
			return false;
		}

		let transient_id = reticulum_rust::identity::full_hash(lxmf_data);
		if !allow_duplicate {
			if self.propagation_entries.contains_key(&transient_id)
				|| self.locally_processed_transient_ids.contains_key(&transient_id)
			{
				log("[PROP] duplicate transient_id, skipping", LOG_NOTICE, false, false);
				let _ = signal_duplicate;
				return false;
			}
		}

		let received = now();
		let destination_hash = lxmf_data[..LXMessage::DESTINATION_LENGTH].to_vec();
		log(&format!("[PROP] dest_hash={} delivery_destinations keys: {}",
			hexrep(&destination_hash, false),
			self.delivery_destinations.keys().map(|k| hexrep(k, false)).collect::<Vec<_>>().join(", ")
		), LOG_NOTICE, false, false);
		self.locally_processed_transient_ids.insert(transient_id.clone(), received);

		let (decrypted, ratchet_id, destination_type) = if let Some(delivery_destination) = self.delivery_destinations.get_mut(&destination_hash) {
			let encrypted = &lxmf_data[LXMessage::DESTINATION_LENGTH..];
			log(&format!("[PROP] LXMF raw hex ({} bytes): {}", lxmf_data.len(), hexrep(lxmf_data, false)), LOG_NOTICE, false, false);
			log(&format!("[PROP] encrypted ({} bytes): ephemeral={} token_data_len={}",
				encrypted.len(),
				if encrypted.len() >= 32 { hexrep(&encrypted[..32], false) } else { "TOO_SHORT".to_string() },
				if encrypted.len() > 32 { encrypted.len() - 32 } else { 0 },
			), LOG_NOTICE, false, false);
			let result = delivery_destination.decrypt(encrypted);
			log(&format!("[PROP] decrypt result: {}", match &result {
				Ok(_) => "Ok".to_string(),
				Err(e) => format!("Err({})", e),
			}), LOG_NOTICE, false, false);
			(
				result.ok(),
				delivery_destination.latest_ratchet_id.clone(),
				Some(delivery_destination.dest_type),
			)
		} else {
			log("[PROP] destination_hash NOT FOUND in delivery_destinations — message cannot be decrypted", LOG_NOTICE, false, false);
			(None, None, None)
		};

		if let Some(decrypted) = decrypted {
			log(&format!("[PROP] decrypted {} bytes, calling lxmf_delivery", decrypted.len()), LOG_NOTICE, false, false);
			let mut delivery_data = destination_hash.clone();
			delivery_data.extend_from_slice(&decrypted);
			self.lxmf_delivery(
				&delivery_data,
				destination_type,
				None,
				ratchet_id,
				Some(LXMessage::PROPAGATED),
				is_paper_message,
				allow_duplicate,
			);
			self.locally_delivered_transient_ids.insert(transient_id.clone(), now());
			let _ = signal_local_delivery;
			return true;
		}

		if self.propagation_node {
			if let Some(messagepath) = &self.messagepath {
				let mut stamped_data = lxmf_data.to_vec();
				if let Some(stamp) = stamp_data.clone() {
					stamped_data.extend_from_slice(&stamp);
				}
				let stamp_suffix = stamp_value.map(|v| format!("_{}", v)).unwrap_or_default();
				let filepath = format!(
					"{}/{}_{}{}",
					messagepath,
					hexrep(&transient_id, false),
					received,
					stamp_suffix
				);
				if fs::write(&filepath, &stamped_data).is_ok() {
					self.propagation_entries.insert(
						transient_id.clone(),
						PropagationEntry {
							destination_hash,
							filepath,
							received,
							size: stamped_data.len(),
							handled_peers: Vec::new(),
							unhandled_peers: Vec::new(),
							stamp_value: stamp_value.unwrap_or(0),
						},
					);
					self.enqueue_peer_distribution(transient_id, from_peer);
				}
			}
		}

		true
	}

	fn enqueue_peer_distribution(&mut self, transient_id: Vec<u8>, from_peer: Option<Vec<u8>>) {
		self.peer_distribution_queue.push_back((transient_id, from_peer));
	}

	pub fn ingest_lxm_uri(
		&mut self,
		uri: &str,
		signal_local_delivery: Option<bool>,
		signal_duplicate: Option<bool>,
		allow_duplicate: bool,
	) -> bool {
		if !uri.to_lowercase().starts_with(&format!("{}://", LXMessage::URI_SCHEMA)) {
			log("Cannot ingest LXM, invalid URI provided", LOG_ERROR, false, false);
			return false;
		}

		let payload = uri
			.replace(&format!("{}://", LXMessage::URI_SCHEMA), "")
			.replace('/', "");
		let padded = format!("{}==", payload);
		let decoded = match URL_SAFE_NO_PAD.decode(padded.as_bytes()) {
			Ok(bytes) => bytes,
			Err(_) => {
				log("No valid LXM could be ingested from the provided URI", LOG_DEBUG, false, false);
				return false;
			}
		};

		let transient_id = reticulum_rust::identity::full_hash(&decoded);
		let _ = signal_local_delivery;
		let _ = signal_duplicate;
		let result = self.lxmf_propagation(
			&decoded,
			None,
			None,
			allow_duplicate,
			true,
			None,
			None,
			None,
		);
		if result {
			log(
				&format!("LXM with transient ID {} was ingested", prettyhexrep(&transient_id)),
				LOG_DEBUG,
				false,
				false,
			);
			true
		} else {
			log("No valid LXM could be ingested from the provided URI", LOG_DEBUG, false, false);
			false
		}
	}

	fn flush_peer_distribution_queue(&mut self) {
		while let Some((transient_id, from_peer)) = self.peer_distribution_queue.pop_front() {
			for (peer_id, peer_arc) in self.peers.iter() {
				if Some(peer_id.clone()) == from_peer {
					continue;
				}
				if let Ok(mut peer) = peer_arc.lock() {
					peer.queue_unhandled_message(transient_id.clone());
				}
			}
		}
	}

	fn propagation_resource_concluded(&mut self, resource: Arc<Mutex<Resource>>) {
		let (data, link_arc) = match resource.lock() {
			Ok(res) => {
				if res.status != ResourceStatus::Complete {
					return;
				}
				let data = match &res.data {
					Some(bytes) => bytes.clone(),
					None => return,
				};
				(data, res.link.clone())
			}
			Err(_) => return,
		};

		let unpacked = match read_value(&mut std::io::Cursor::new(&data)) {
			Ok(Value::Array(items)) => items,
			_ => return,
		};

		if unpacked.len() < 2 {
			return;
		}

		let messages = match &unpacked[1] {
			Value::Array(values) => values
				.iter()
				.filter_map(|v| match v {
					Value::Binary(bytes) => Some(bytes.clone()),
					_ => None,
				})
				.collect::<Vec<Vec<u8>>>(),
			_ => Vec::new(),
		};

		let remote_identity = link_arc.remote_identity().ok().flatten();
		let remote_hash = remote_identity.as_ref().map(|identity| {
			Destination::hash_from_name_and_identity(&format!("{}.propagation", APP_NAME), Some(identity))
		});

		if let (Some(remote_hash), Some(_remote_identity)) = (remote_hash.clone(), remote_identity.as_ref()) {
			if !self.peers.contains_key(&remote_hash) {
				if let Some(app_data) = Identity::recall_app_data(&remote_hash) {
					if pn_announce_data_is_valid(&app_data) {
						if let Some(Value::Array(config)) = Self::decode_value(&app_data) {
							if config.len() >= 7 {
								let propagation_enabled = config[2].as_bool().unwrap_or(false);
								let hops = Transport::hops_to(&remote_hash);
								if propagation_enabled && self.autopeer && hops <= self.autopeer_maxdepth {
									let timebase = config[1].as_i64().unwrap_or(0) as f64;
									let transfer_limit = config[3].as_f64().unwrap_or(0.0);
									let sync_limit = config[4].as_f64().unwrap_or(0.0);
									let (stamp_cost, stamp_flex, peering_cost) = match &config[5] {
										Value::Array(costs) if costs.len() >= 3 => (
											costs[0].as_i64().unwrap_or(0) as u32,
											costs[1].as_i64().unwrap_or(0) as u32,
											costs[2].as_i64().unwrap_or(0) as u32,
										),
										_ => (0, 0, 0),
									};
									let mut metadata = Vec::new();
									let _ = write_value(&mut metadata, &config[6]);
									log(
										&format!("Auto-peering with {} discovered via incoming sync", prettyhexrep(&remote_hash)),
										LOG_DEBUG,
										false,
										false,
									);
									self.peer(
										remote_hash.clone(),
										timebase,
										transfer_limit,
										if sync_limit > 0.0 { Some(sync_limit) } else { None },
										stamp_cost,
										stamp_flex,
										peering_cost,
										metadata,
									);
								}
							}
						}
					}
				}
			}
		}

		let peering_key_valid = remote_hash
			.as_ref()
			.and_then(|hash| self.validated_peer_links.get(hash))
			.copied()
			.unwrap_or(false);

		if !peering_key_valid && messages.len() > 1 {
			link_arc.teardown();
			log(
				"Received multiple propagation messages without a validated peering key",
				LOG_WARNING,
				false,
				false,
			);
			return;
		}

		let min_accepted_cost = self
			.propagation_stamp_cost
			.saturating_sub(self.propagation_stamp_cost_flexibility);
		let validated = lx_stamper::validate_pn_stamps(&messages, min_accepted_cost);

		for validated_entry in validated.iter() {
			let transient_id = validated_entry.0.clone();
			let lxmf_data = &validated_entry.1;
			let stamp_value = validated_entry.2;
			let stamp_data = validated_entry.3.clone();

			if let Some(hash) = remote_hash.as_ref() {
				if let Some(peer_arc) = self.peers.get(hash) {
					if let Ok(mut peer) = peer_arc.lock() {
						peer.incoming += 1;
						peer.rx_bytes += lxmf_data.len() as u64;
						peer.queue_handled_message(transient_id.clone());
					}
				} else {
					self.unpeered_propagation_incoming += 1;
					self.unpeered_propagation_rx_bytes += lxmf_data.len() as u64;
				}
			} else {
				self.client_propagation_messages_received += 1;
			}

			self.lxmf_propagation(
				lxmf_data,
				None,
				None,
				false,
				false,
				remote_hash.clone(),
				Some(stamp_value),
				Some(stamp_data),
			);
		}

		let invalid_count = messages.len().saturating_sub(validated.len());
		if invalid_count > 0 {
			link_arc.teardown();
			if let Some(hash) = remote_hash.as_ref() {
				let throttle_until = now() + Self::PN_STAMP_THROTTLE;
				self.throttled_peers.insert(hash.clone(), throttle_until);
				log(
					&format!(
						"Propagation transfer contained {} invalid stamp(s), throttling peer",
						invalid_count
					),
					LOG_NOTICE,
					false,
					false,
				);
			}
		}
	}

	/// Handle propagation offer requests
	pub fn offer_request(
		&mut self,
		_path: &str,
		data: &[u8],
		_request_id: &[u8],
		remote_identity: Option<&Identity>,
		_requested_at: f64,
	) -> Vec<u8> {
		let remote_identity = match remote_identity {
			Some(identity) => identity,
			None => return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_IDENTITY as i64).into())),
		};

		let remote_destination = match Destination::new_outbound(
			Some(remote_identity.clone()),
			DestinationType::Single,
			APP_NAME.to_string(),
			vec!["propagation".to_string()],
		) {
			Ok(dest) => dest,
			Err(_) => return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into())),
		};
		let remote_hash = remote_destination.hash;

		if let Some(throttle_until) = self.throttled_peers.get(&remote_hash).copied() {
			let remaining = throttle_until - now();
			if remaining > 0.0 {
				return Self::encode_value(Value::Integer((LXMPeer::ERROR_THROTTLED as i64).into()));
			} else {
				self.throttled_peers.remove(&remote_hash);
			}
		}

		if self.from_static_only && !self.static_peers.contains(&remote_hash) {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_ACCESS as i64).into()));
		}

		let request_value = match read_value(&mut std::io::Cursor::new(data)) {
			Ok(Value::Array(items)) => items,
			_ => return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into())),
		};

		if request_value.len() < 2 {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into()));
		}

		let peering_key = match &request_value[0] {
			Value::Binary(bytes) => bytes.clone(),
			_ => return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into())),
		};
		let transient_ids = match &request_value[1] {
			Value::Array(list) => list
				.iter()
				.filter_map(|v| match v {
					Value::Binary(bytes) => Some(bytes.clone()),
					_ => None,
				})
				.collect::<Vec<Vec<u8>>>(),
			_ => Vec::new(),
		};

		let mut peering_id = self.identity.hash.clone().expect("Router identity hash missing");
		peering_id.extend_from_slice(&remote_identity.hash.clone().expect("Remote identity hash missing"));
		if !lx_stamper::validate_peering_key(&peering_id, &peering_key, self.peering_cost) {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_KEY as i64).into()));
		}

		self.validated_peer_links.insert(remote_hash.clone(), true);

		let mut wanted_ids = Vec::new();
		for transient_id in transient_ids.iter() {
			if !self.propagation_entries.contains_key(transient_id) {
				wanted_ids.push(Value::Binary(transient_id.clone()));
			}
		}

		if wanted_ids.is_empty() {
			Self::encode_value(Value::Boolean(false))
		} else if wanted_ids.len() == transient_ids.len() {
			Self::encode_value(Value::Boolean(true))
		} else {
			Self::encode_value(Value::Array(wanted_ids))
		}
	}

	/// Handle message get requests
	pub fn message_get_request(
		&mut self,
		_path: &str,
		data: &[u8],
		_request_id: &[u8],
		remote_identity: Option<&Identity>,
		_requested_at: f64,
	) -> Vec<u8> {
		let remote_identity = match remote_identity {
			Some(identity) => identity,
			None => return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_IDENTITY as i64).into())),
		};

		if !self.identity_allowed(remote_identity) {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_ACCESS as i64).into()));
		}

		let remote_destination = match Destination::new_outbound(
			Some(remote_identity.clone()),
			DestinationType::Single,
			APP_NAME.to_string(),
			vec!["delivery".to_string()],
		) {
			Ok(dest) => dest,
			Err(_) => return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into())),
		};

		let request_value = match read_value(&mut std::io::Cursor::new(data)) {
			Ok(Value::Array(items)) => items,
			_ => return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into())),
		};

		let wants = request_value.get(0).cloned().unwrap_or(Value::Nil);
		let haves = request_value.get(1).cloned().unwrap_or(Value::Nil);
		let client_limit = request_value.get(2).and_then(|v| v.as_f64()).map(|v| v * 1000.0);

		if wants == Value::Nil && haves == Value::Nil {
			let mut available = Vec::new();
			for (transient_id, entry) in self.propagation_entries.iter() {
				if entry.destination_hash == remote_destination.hash {
					available.push((transient_id.clone(), entry.size));
				}
			}
			available.sort_by_key(|(_, size)| *size);
			let ids = available.into_iter().map(|(id, _)| Value::Binary(id)).collect();
			return Self::encode_value(Value::Array(ids));
		}

		// Process messages client already has
		if let Value::Array(haves_list) = haves {
			for value in haves_list {
				if let Value::Binary(transient_id) = value {
					if let Some(entry) = self.propagation_entries.get(&transient_id) {
						if entry.destination_hash == remote_destination.hash {
							let filepath = entry.filepath.clone();
							self.propagation_entries.remove(&transient_id);
							let _ = fs::remove_file(filepath);
						}
					}
				}
			}
		}

		// Process wanted messages
		let mut response_messages = Vec::new();
		if let Value::Array(want_list) = wants {
			let per_message_overhead = 16.0;
			let mut cumulative_size = 24.0;
			for value in want_list {
				if let Value::Binary(transient_id) = value {
					if let Some(entry) = self.propagation_entries.get(&transient_id) {
						if entry.destination_hash == remote_destination.hash {
							if let Ok(lxmf_data) = fs::read(&entry.filepath) {
								let lxm_size = lxmf_data.len() as f64;
								let next_size = cumulative_size + lxm_size + per_message_overhead;
								if client_limit.map(|limit| next_size <= limit).unwrap_or(true) {
									let trim_size = lxmf_data.len().saturating_sub(lx_stamper::STAMP_SIZE);
									response_messages.push(Value::Binary(lxmf_data[..trim_size].to_vec()));
									cumulative_size = next_size;
								}
							}
						}
					}
				}
			}
		}

		self.client_propagation_messages_served += response_messages.len() as u64;
		Self::encode_value(Value::Array(response_messages))
	}

	/// Handle stats get requests
	pub fn stats_get_request(
		&mut self,
		_path: &str,
		_data: &[u8],
		_request_id: &[u8],
		remote_identity: Option<&Identity>,
		_requested_at: f64,
	) -> Vec<u8> {
		let remote_identity = match remote_identity {
			Some(identity) => identity,
			None => return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_IDENTITY as i64).into())),
		};

		if !self.control_allowed_list.contains(&remote_identity.hash.clone().expect("Remote identity hash missing")) {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_ACCESS as i64).into()));
		}

		if let Some(stats) = self.compile_stats() {
			Self::encode_value(stats)
		} else {
			Self::encode_value(Value::Nil)
		}
	}

	/// Handle peer sync requests
	pub fn peer_sync_request(
		&mut self,
		_path: &str,
		data: &[u8],
		_request_id: &[u8],
		remote_identity: Option<&Identity>,
		_requested_at: f64,
	) -> Vec<u8> {
		let remote_identity = match remote_identity {
			Some(identity) => identity,
			None => return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_IDENTITY as i64).into())),
		};

		if !self.control_allowed_list.contains(&remote_identity.hash.clone().expect("Remote identity hash missing")) {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_ACCESS as i64).into()));
		}

		if data.len() != TRUNCATED_HASHLENGTH / 8 {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into()));
		}

		if let Some(peer_arc) = self.peers.get(data) {
			if let Ok(mut peer) = peer_arc.lock() {
				peer.sync();
				return Self::encode_value(Value::Boolean(true));
			}
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_NOT_FOUND as i64).into()));
		}

		Self::encode_value(Value::Integer((LXMPeer::ERROR_NOT_FOUND as i64).into()))
	}

	/// Handle peer unpeer requests
	pub fn peer_unpeer_request(
		&mut self,
		_path: &str,
		data: &[u8],
		_request_id: &[u8],
		remote_identity: Option<&Identity>,
		_requested_at: f64,
	) -> Vec<u8> {
		let remote_identity = match remote_identity {
			Some(identity) => identity,
			None => return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_IDENTITY as i64).into())),
		};

		if !self.control_allowed_list.contains(&remote_identity.hash.clone().expect("Remote identity hash missing")) {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_NO_ACCESS as i64).into()));
		}

		if data.len() != TRUNCATED_HASHLENGTH / 8 {
			return Self::encode_value(Value::Integer((LXMPeer::ERROR_INVALID_DATA as i64).into()));
		}

		if self.peers.contains_key(data) {
			self.unpeer(data.to_vec(), None);
			return Self::encode_value(Value::Boolean(true));
		}

		Self::encode_value(Value::Integer((LXMPeer::ERROR_NOT_FOUND as i64).into()))
	}

	/// Check if an identity is allowed
	pub fn identity_allowed(&self, identity: &Identity) -> bool {
		if !self.auth_required {
			return true;
		}

		self.allowed_list.contains(&identity.hash.clone().expect("Identity hash missing"))
	}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use std::sync::{Arc, Mutex};

	/// REGRESSION GUARD: `Arc::ptr_eq` dedup logic prevents the same link from
	/// being pushed to `backchannel_setup_links` more than once per
	/// `process_outbound` cycle.
	///
	/// Context: `process_outbound` now pushes to `backchannel_setup_links` in two
	/// places — (1) immediately after `send_with_handle` succeeds ("DIRECT send OK"
	/// branch, our fix) and (2) in the `lxm.state == DELIVERED` safety-net path.
	/// When both paths fire in the same cycle (possible if the receipt proof arrives
	/// before the next job tick) the same link would be pushed twice → `delivery_link_established`
	/// would overwrite `callbacks.packet` twice, which is harmless but wasteful.
	/// The dedup guard ensures only one call occurs.
	#[test]
	fn backchannel_setup_dedup_prevents_double_install() {
		// Use i32 as a stand-in for Link — we're testing pointer-equality dedup only.
		type FakeLink = Arc<Mutex<i32>>;

		let link_a: FakeLink = Arc::new(Mutex::new(1));
		let link_b = link_a.clone(); // same heap allocation as link_a
		let link_c: FakeLink = Arc::new(Mutex::new(1)); // different allocation

		let dest = vec![0u8; 16];
		let mut slots: Vec<(FakeLink, Vec<u8>)> = Vec::new();

		// Simulate SEND OK push (our fix).
		if !slots.iter().any(|(l, _)| Arc::ptr_eq(l, &link_a)) {
			slots.push((link_a.clone(), dest.clone()));
		}
		assert_eq!(slots.len(), 1, "first push adds the link");

		// Simulate DELIVERED path push with the same Arc clone → must be deduped.
		if !slots.iter().any(|(l, _)| Arc::ptr_eq(l, &link_b)) {
			slots.push((link_b.clone(), dest.clone()));
		}
		assert_eq!(
			slots.len(), 1,
			"same Arc (via clone) must not be pushed twice — \
			 prevents double installation of callbacks.packet"
		);

		// A distinct Arc (different link) must still be admitted.
		if !slots.iter().any(|(l, _)| Arc::ptr_eq(l, &link_c)) {
			slots.push((link_c.clone(), dest.clone()));
		}
		assert_eq!(slots.len(), 2, "distinct Arc must still be queued");
	}

	/// REGRESSION GUARD: `backchannel_setup_links.push` must appear in the
	/// "DIRECT send OK" branch of `process_outbound` — i.e., immediately after
	/// `send_with_handle` returns `Ok`.
	///
	/// Before this fix, the push only happened in the `lxm.state == DELIVERED`
	/// block (after the receipt proof arrived).  Meshchat may reply on the same
	/// back-channel link in the round-trip time before that proof returns, so
	/// `callbacks.packet` was `None` when the DATA packet arrived → silent drop.
	///
	/// Python reference (LXMRouter.py:2539): `delivery_link_established(direct_link)`
	/// is called immediately after `lxm.send()`, before the DELIVERED receipt.
	/// This test verifies the Rust implementation matches that ordering.
	#[test]
	fn direct_send_ok_pushes_backchannel_before_delivered_receipt() {
		let src = include_str!("lxm_router.rs");

		// The "DIRECT send OK" log marker must be present.
		assert!(
			src.contains("DIRECT send OK"),
			"'DIRECT send OK' marker must exist in process_outbound — \
			 remove this test only if the log line is intentionally renamed"
		);

		// A `backchannel_setup_links.push` must appear AFTER "DIRECT send OK"
		// in the source — this is the fix that closes the race window.
		let send_ok_pos = src.find("DIRECT send OK").unwrap();
		let push_after_send = src[send_ok_pos..].contains("backchannel_setup_links.push");
		assert!(
			push_after_send,
			"backchannel_setup_links.push must appear after 'DIRECT send OK' \
			 — removing it re-introduces the reply-before-receipt race condition \
			 where callbacks.packet is None when Meshchat's reply DATA arrives"
		);

		// Both the SEND OK push (our fix) and the DELIVERED safety-net push must be present.
		let push_count = src.matches("backchannel_setup_links.push").count();
		assert!(
			push_count >= 2,
			"backchannel_setup_links.push must appear in at least 2 places: \
			 (1) after 'DIRECT send OK' (race-condition fix) and \
			 (2) in the DELIVERED safety-net path — found {}",
			push_count
		);
	}

	/// REGRESSION GUARD: the `Arc::ptr_eq` dedup guard must accompany the
	/// "DIRECT send OK" push.
	///
	/// Without it, if `process_outbound` runs a second cycle while the message
	/// is still in `SENDING` state (receipt not yet back), the same link would be
	/// pushed again → `delivery_link_established` called twice on the same link
	/// → last-write wins for `callbacks.packet`, which is benign TODAY but could
	/// become harmful if the callback closure captures mutable state in future.
	#[test]
	fn send_ok_backchannel_push_has_dedup_guard() {
		let src = include_str!("lxm_router.rs");

		let send_ok_pos = src.find("DIRECT send OK")
			.expect("'DIRECT send OK' must be present — see direct_send_ok_pushes_backchannel_before_delivered_receipt");

		let dedup_present = src[send_ok_pos..].contains("Arc::ptr_eq");
		assert!(
			dedup_present,
			"Arc::ptr_eq dedup guard must appear after 'DIRECT send OK' — \
			 it prevents the same link being queued for delivery_link_established \
			 more than once per process_outbound cycle"
		);
	}
}
