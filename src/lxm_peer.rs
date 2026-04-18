use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use rmp_serde::{decode::from_slice, encode::to_vec_named};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{Link, LinkHandle};
use reticulum_rust::resource::{Resource, ResourceData, ResourceStatus};
use reticulum_rust::transport::Transport;
use reticulum_rust::{log, prettyhexrep, prettysize, prettyspeed, prettytime, LOG_DEBUG, LOG_ERROR, LOG_NOTICE, LOG_VERBOSE, LOG_WARNING};

use crate::lx_stamper;
use crate::lxmf::APP_NAME;
use crate::lxm_router::LXMRouter;

fn now() -> f64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs_f64())
		.unwrap_or(0.0)
}

#[derive(Serialize, Deserialize)]
struct LXMPeerState {
	peering_timebase: f64,
	alive: bool,
	last_heard: f64,
	link_establishment_rate: Option<f64>,
	sync_transfer_rate: Option<f64>,
	propagation_transfer_limit: Option<f64>,
	propagation_sync_limit: Option<f64>,
	propagation_stamp_cost: Option<u32>,
	propagation_stamp_cost_flexibility: Option<u32>,
	peering_cost: Option<u32>,
	sync_strategy: Option<u8>,
	offered: Option<u64>,
	outgoing: Option<u64>,
	incoming: Option<u64>,
	rx_bytes: Option<u64>,
	tx_bytes: Option<u64>,
	last_sync_attempt: Option<f64>,
	peering_key: Option<(Vec<u8>, u32)>,
	metadata: Option<Vec<u8>>,
	destination_hash: Vec<u8>,
	handled_ids: Vec<Vec<u8>>,
	unhandled_ids: Vec<Vec<u8>>,
}

pub struct LXMPeer {
	pub alive: bool,
	pub last_heard: f64,
	pub sync_strategy: u8,
	pub peering_key: Option<(Vec<u8>, u32)>,
	pub peering_cost: Option<u32>,
	pub metadata: Option<Vec<u8>>,

	pub next_sync_attempt: f64,
	pub last_sync_attempt: f64,
	pub sync_backoff: f64,
	pub peering_timebase: f64,
	pub link_establishment_rate: f64,
	pub sync_transfer_rate: f64,

	pub propagation_transfer_limit: Option<f64>,
	pub propagation_sync_limit: Option<f64>,
	pub propagation_stamp_cost: Option<u32>,
	pub propagation_stamp_cost_flexibility: Option<u32>,
	pub currently_transferring_messages: Option<Vec<Vec<u8>>>,

	pub handled_messages_queue: VecDeque<Vec<u8>>,
	pub unhandled_messages_queue: VecDeque<Vec<u8>>,

	pub offered: u64,
	pub outgoing: u64,
	pub incoming: u64,
	pub rx_bytes: u64,
	pub tx_bytes: u64,

	pub _hm_count: usize,
	pub _um_count: usize,
	pub _hm_counts_synced: bool,
	pub _um_counts_synced: bool,

	pub link: Option<LinkHandle>,
	pub state: u8,
	pub last_offer: Vec<Vec<u8>>,
	pub current_sync_transfer_started: Option<f64>,

	pub router: Weak<Mutex<LXMRouter>>,
	pub self_handle: Option<Weak<Mutex<LXMPeer>>>,
	pub destination_hash: Vec<u8>,
	pub identity: Option<Identity>,
	pub destination: Option<Destination>,
	peering_key_lock: Mutex<()>,
}

impl LXMPeer {
	pub const OFFER_REQUEST_PATH: &'static str = "/offer";
	pub const MESSAGE_GET_PATH: &'static str = "/get";

	pub const IDLE: u8 = 0x00;
	pub const LINK_ESTABLISHING: u8 = 0x01;
	pub const LINK_READY: u8 = 0x02;
	pub const REQUEST_SENT: u8 = 0x03;
	pub const RESPONSE_RECEIVED: u8 = 0x04;
	pub const RESOURCE_TRANSFERRING: u8 = 0x05;

	pub const ERROR_NO_IDENTITY: u8 = 0xf0;
	pub const ERROR_NO_ACCESS: u8 = 0xf1;
	pub const ERROR_INVALID_KEY: u8 = 0xf3;
	pub const ERROR_INVALID_DATA: u8 = 0xf4;
	pub const ERROR_INVALID_STAMP: u8 = 0xf5;
	pub const ERROR_THROTTLED: u8 = 0xf6;
	pub const ERROR_NOT_FOUND: u8 = 0xfd;
	pub const ERROR_TIMEOUT: u8 = 0xfe;

	pub const STRATEGY_LAZY: u8 = 0x01;
	pub const STRATEGY_PERSISTENT: u8 = 0x02;
	pub const DEFAULT_SYNC_STRATEGY: u8 = Self::STRATEGY_PERSISTENT;

	pub const MAX_UNREACHABLE: f64 = 14.0 * 24.0 * 60.0 * 60.0;
	pub const SYNC_BACKOFF_STEP: f64 = 12.0 * 60.0;
	pub const PATH_REQUEST_GRACE: f64 = 7.5;

	pub fn from_bytes(peer_bytes: &[u8], router: Weak<Mutex<LXMRouter>>) -> Result<Self, String> {
		let state: LXMPeerState = from_slice(peer_bytes).map_err(|e| e.to_string())?;
		let mut peer = LXMPeer::new(router.clone(), state.destination_hash.clone(), state.sync_strategy.unwrap_or(Self::DEFAULT_SYNC_STRATEGY));

		peer.peering_timebase = state.peering_timebase;
		peer.alive = state.alive;
		peer.last_heard = state.last_heard;
		peer.link_establishment_rate = state.link_establishment_rate.unwrap_or(0.0);
		peer.sync_transfer_rate = state.sync_transfer_rate.unwrap_or(0.0);
		peer.propagation_transfer_limit = state.propagation_transfer_limit;
		peer.propagation_sync_limit = state.propagation_sync_limit.or(state.propagation_transfer_limit);
		peer.propagation_stamp_cost = state.propagation_stamp_cost;
		peer.propagation_stamp_cost_flexibility = state.propagation_stamp_cost_flexibility;
		peer.peering_cost = state.peering_cost;
		peer.sync_strategy = state.sync_strategy.unwrap_or(Self::DEFAULT_SYNC_STRATEGY);
		peer.offered = state.offered.unwrap_or(0);
		peer.outgoing = state.outgoing.unwrap_or(0);
		peer.incoming = state.incoming.unwrap_or(0);
		peer.rx_bytes = state.rx_bytes.unwrap_or(0);
		peer.tx_bytes = state.tx_bytes.unwrap_or(0);
		peer.last_sync_attempt = state.last_sync_attempt.unwrap_or(0.0);
		peer.peering_key = state.peering_key;
		peer.metadata = state.metadata;

		let mut hm_count = 0;
		let mut um_count = 0;
		if let Some(router) = router.upgrade() {
			if let Ok(mut router) = router.lock() {
				for transient_id in state.handled_ids {
					if router.propagation_entries.contains_key(&transient_id) {
						peer.add_handled_message(&mut router, transient_id);
						hm_count += 1;
					}
				}

				for transient_id in state.unhandled_ids {
					if router.propagation_entries.contains_key(&transient_id) {
						peer.add_unhandled_message(&mut router, transient_id);
						um_count += 1;
					}
				}
			}
		}

		peer._hm_count = hm_count;
		peer._um_count = um_count;
		peer._hm_counts_synced = true;
		peer._um_counts_synced = true;
		Ok(peer)
	}

	pub fn to_bytes(&mut self, router: &LXMRouter) -> Result<Vec<u8>, String> {
		let handled_ids = self.handled_messages(router);
		let unhandled_ids = self.unhandled_messages(router);

		let state = LXMPeerState {
			peering_timebase: self.peering_timebase,
			alive: self.alive,
			last_heard: self.last_heard,
			link_establishment_rate: Some(self.link_establishment_rate),
			sync_transfer_rate: Some(self.sync_transfer_rate),
			propagation_transfer_limit: self.propagation_transfer_limit,
			propagation_sync_limit: self.propagation_sync_limit,
			propagation_stamp_cost: self.propagation_stamp_cost,
			propagation_stamp_cost_flexibility: self.propagation_stamp_cost_flexibility,
			peering_cost: self.peering_cost,
			sync_strategy: Some(self.sync_strategy),
			offered: Some(self.offered),
			outgoing: Some(self.outgoing),
			incoming: Some(self.incoming),
			rx_bytes: Some(self.rx_bytes),
			tx_bytes: Some(self.tx_bytes),
			last_sync_attempt: Some(self.last_sync_attempt),
			peering_key: self.peering_key.clone(),
			metadata: self.metadata.clone(),
			destination_hash: self.destination_hash.clone(),
			handled_ids,
			unhandled_ids,
		};

		to_vec_named(&state).map_err(|e| e.to_string())
	}

	pub fn new(router: Weak<Mutex<LXMRouter>>, destination_hash: Vec<u8>, sync_strategy: u8) -> Self {
		let identity = Identity::recall(&destination_hash);
		let destination = identity.as_ref().and_then(|identity| {
			Destination::new_outbound(
				Some(identity.clone()),
				DestinationType::Single,
				APP_NAME.to_string(),
				vec!["propagation".to_string()],
			)
			.ok()
		});

		LXMPeer {
			alive: false,
			last_heard: 0.0,
			sync_strategy,
			peering_key: None,
			peering_cost: None,
			metadata: None,
			next_sync_attempt: 0.0,
			last_sync_attempt: 0.0,
			sync_backoff: 0.0,
			peering_timebase: 0.0,
			link_establishment_rate: 0.0,
			sync_transfer_rate: 0.0,
			propagation_transfer_limit: None,
			propagation_sync_limit: None,
			propagation_stamp_cost: None,
			propagation_stamp_cost_flexibility: None,
			currently_transferring_messages: None,
			handled_messages_queue: VecDeque::new(),
			unhandled_messages_queue: VecDeque::new(),
			offered: 0,
			outgoing: 0,
			incoming: 0,
			rx_bytes: 0,
			tx_bytes: 0,
			_hm_count: 0,
			_um_count: 0,
			_hm_counts_synced: false,
			_um_counts_synced: false,
			link: None,
			state: Self::IDLE,
			last_offer: Vec::new(),
			current_sync_transfer_started: None,
			router,
			self_handle: None,
			destination_hash,
			identity,
			destination,
			peering_key_lock: Mutex::new(()),
		}
	}

	pub fn peering_key_ready(&mut self) -> bool {
		if self.peering_cost.is_none() {
			return false;
		}
		if let Some((_, value)) = &self.peering_key {
			if *value >= self.peering_cost.unwrap_or(0) {
				return true;
			}
			log(
				&format!(
					"Peering key value mismatch for {}, scheduling regeneration",
					self
				),
				LOG_WARNING,
				false,
				false,
			);
			self.peering_key = None;
		}
		false
	}

	pub fn peering_key_value(&self) -> Option<u32> {
		self.peering_key.as_ref().map(|(_, value)| *value)
	}

	pub fn generate_peering_key(&mut self) -> bool {
		let peering_cost = match self.peering_cost {
			Some(cost) => cost,
			None => return false,
		};

		let _guard = match self.peering_key_lock.lock() {
			Ok(guard) => guard,
			Err(_) => return false,
		};

		if self.peering_key.is_some() {
			return true;
		}

		if let Some(router) = self.router.upgrade() {
			if let Ok(router) = router.lock() {
				if self.identity.is_none() {
					self.identity = Identity::recall(&self.destination_hash);
				}

				let identity = match &self.identity {
					Some(identity) => identity,
					None => {
						log(
							&format!("Could not recall identity for {}", prettyhexrep(&self.destination_hash)),
							LOG_ERROR,
							false,
							false,
						);
						return false;
					}
				};

				let identity_hash = match identity.hash.as_ref() {
					Some(hash) => hash,
					None => {
						log(
							&format!("Missing identity hash for {}", prettyhexrep(&self.destination_hash)),
							LOG_ERROR,
							false,
							false,
						);
						return false;
					}
				};
				let router_hash = match router.identity.hash.as_ref() {
					Some(hash) => hash,
					None => {
						log("Missing router identity hash", LOG_ERROR, false, false);
						return false;
					}
				};
				let mut key_material = Vec::with_capacity(identity_hash.len() + router_hash.len());
				key_material.extend_from_slice(identity_hash);
				key_material.extend_from_slice(router_hash);
				let (key, value) = lx_stamper::generate_stamp(
					&key_material,
					peering_cost,
					lx_stamper::WORKBLOCK_EXPAND_ROUNDS_PEERING,
				);

				if value >= peering_cost {
					if let Some(key) = key {
						self.peering_key = Some((key, value));
						log(
							&format!("Peering key successfully generated for {}", self),
							LOG_NOTICE,
							false,
							false,
						);
						return true;
					}
				}
			}
		}

		false
	}

	pub fn sync(&mut self) {
		log(
			&format!(
				"Initiating LXMF Propagation Node sync with peer {}",
				prettyhexrep(&self.destination_hash)
			),
			LOG_DEBUG,
			false,
			false,
		);
		self.last_sync_attempt = now();

		let sync_time_reached = now() > self.next_sync_attempt;
		let stamp_costs_known = self.propagation_stamp_cost.is_some()
			&& self.propagation_stamp_cost_flexibility.is_some()
			&& self.peering_cost.is_some();
		let peering_key_ready = self.peering_key_ready();
		let sync_checks = sync_time_reached && stamp_costs_known && peering_key_ready;

		if !sync_checks {
			let postpone_reason = if !sync_time_reached {
				if self.last_sync_attempt > self.last_heard {
					self.alive = false;
				}
				" due to previous failures"
			} else if !stamp_costs_known {
				" since its required stamp costs are not yet known"
			} else {
				" since a peering key has not been generated yet"
			};
			if !peering_key_ready {
				let _ = self.generate_peering_key();
			}

			let delay = self.next_sync_attempt - now();
			let postpone_delay = if delay > 0.0 {
				format!(" for {}", prettytime(delay, false, false))
			} else {
				String::new()
			};
			log(
				&format!(
					"Postponing sync with peer {}{}{}",
					prettyhexrep(&self.destination_hash),
					postpone_delay,
					postpone_reason
				),
				LOG_DEBUG,
				false,
				false,
			);
			return;
		}

		if !Transport::has_path(&self.destination_hash) {
			log(
				&format!(
					"No path to peer {} exists, requesting...",
					prettyhexrep(&self.destination_hash)
				),
				LOG_DEBUG,
				false,
				false,
			);
			Transport::request_path(&self.destination_hash, None, None, None, None);
			std::thread::sleep(std::time::Duration::from_secs_f64(Self::PATH_REQUEST_GRACE));
		}

		if !Transport::has_path(&self.destination_hash) {
			log(
				&format!(
					"Path request was not answered, retrying sync with peer {} later",
					prettyhexrep(&self.destination_hash)
				),
				LOG_DEBUG,
				false,
				false,
			);
			return;
		}

		if self.identity.is_none() {
			self.identity = Identity::recall(&self.destination_hash);
			if let Some(identity) = &self.identity {
				self.destination = Destination::new_outbound(
					Some(identity.clone()),
					DestinationType::Single,
					APP_NAME.to_string(),
					vec!["propagation".to_string()],
				)
				.ok();
			}
		}

		if self.destination.is_none() {
			log(
				&format!(
					"Could not request sync to peer {} since its identity could not be recalled",
					prettyhexrep(&self.destination_hash)
				),
				LOG_ERROR,
				false,
				false,
			);
			return;
		}

		if let Some(router) = self.router.upgrade() {
			if let Ok(router) = router.lock() {
				if self.unhandled_messages(&router).is_empty() {
					log(
						&format!("Sync requested for {}, but no unhandled messages exist", self),
						LOG_DEBUG,
						false,
						false,
					);
					return;
				}
			}
		}

		if self.currently_transferring_messages.is_some() {
			log(
				&format!(
					"Sync requested for {}, but current message transfer index was not clear. Aborting.",
					self
				),
				LOG_ERROR,
				false,
				false,
			);
			return;
		}

		if self.state == Self::IDLE {
			log(
				&format!("Establishing link for sync to peer {}...", prettyhexrep(&self.destination_hash)),
				LOG_DEBUG,
				false,
				false,
			);
			self.sync_backoff += Self::SYNC_BACKOFF_STEP;
			self.next_sync_attempt = now() + self.sync_backoff;
			if let Some(destination) = self.destination.clone() {
				if let Ok(link) = Link::new_outbound(destination, reticulum_rust::link::MODE_AES256_CBC) {
					self.link = Some(LinkHandle::spawn(link));
					self.state = Self::LINK_ESTABLISHING;
				}
			}
			return;
		}

		if self.state == Self::LINK_READY {
			self.alive = true;
			self.last_heard = now();
			self.sync_backoff = 0.0;
			let min_accepted_cost = self
				.propagation_stamp_cost
				.unwrap_or(0)
				.saturating_sub(self.propagation_stamp_cost_flexibility.unwrap_or(0))
				as i32;

			log(
				&format!(
					"Synchronisation link to peer {} established, preparing sync offer...",
					prettyhexrep(&self.destination_hash)
				),
				LOG_DEBUG,
				false,
				false,
			);

			let mut unhandled_entries: Vec<(Vec<u8>, f64, u64)> = Vec::new();
			let mut purged_ids = Vec::new();
			let mut low_value_ids = Vec::new();

			if let Some(router) = self.router.upgrade() {
				if let Ok(mut router) = router.lock() {
					for transient_id in self.unhandled_messages(&router) {
						if let Some(entry) = router.propagation_entries.get(&transient_id) {
							if router.get_stamp_value(&transient_id).unwrap_or(0) < min_accepted_cost as u32 {
								low_value_ids.push(transient_id.clone());
							} else {
								unhandled_entries.push((
									transient_id.clone(),
									router.get_weight(&transient_id),
									entry.size as u64,
								));
							}
						} else {
							purged_ids.push(transient_id.clone());
						}
					}

					for transient_id in purged_ids {
						log(
							&format!(
								"Dropping unhandled message {} for peer {} since it no longer exists",
								prettyhexrep(&transient_id),
								prettyhexrep(&self.destination_hash)
							),
							LOG_DEBUG,
							false,
							false,
						);
						self.remove_unhandled_message(&mut router, &transient_id);
					}

					for transient_id in low_value_ids {
						log(
							&format!(
								"Dropping unhandled message {} for peer {} since stamp value is lower than peer requirement",
								prettyhexrep(&transient_id),
								prettyhexrep(&self.destination_hash)
							),
							LOG_DEBUG,
							false,
							false,
						);
						self.remove_unhandled_message(&mut router, &transient_id);
					}
				}
			}

			unhandled_entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
			let per_message_overhead = 16.0;
			let mut cumulative_size = 24.0;
			let mut unhandled_ids = Vec::new();

			for entry in unhandled_entries {
				let transient_id = entry.0;
				let lxm_size = entry.2 as f64;
				let lxm_transfer_size = lxm_size + per_message_overhead;
				let next_size = cumulative_size + lxm_transfer_size;

				if let Some(limit) = self.propagation_transfer_limit {
					if lxm_transfer_size > limit * 1000.0 {
						if let Some(router) = self.router.upgrade() {
							if let Ok(mut router) = router.lock() {
								self.remove_unhandled_message(&mut router, &transient_id);
								self.add_handled_message(&mut router, transient_id.clone());
							}
						}
						continue;
					}
				}

				if let Some(sync_limit) = self.propagation_sync_limit {
					if next_size >= sync_limit * 1000.0 {
						continue;
					}
				}

				cumulative_size += lxm_transfer_size;
				unhandled_ids.push(transient_id);
			}

			if let Some((key, _)) = &self.peering_key {
				let offer = Value::Array(vec![
					Value::Binary(key.clone()),
					Value::Array(unhandled_ids.iter().map(|id| Value::Binary(id.clone())).collect()),
				]);
				let mut buf = Vec::new();
				let _ = rmpv::encode::write_value(&mut buf, &offer);

				if let Some(link) = self.link.clone() {
					let weak = self.self_handle.clone();
					let response_cb = weak.clone().and_then(|weak| {
						Some(Arc::new(move |receipt: reticulum_rust::link::RequestReceipt| {
							if let Some(peer) = weak.upgrade() {
								if let Ok(mut peer) = peer.lock() {
									peer.offer_response(receipt);
								}
							}
						}) as Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>)
					});

					let failed_cb = weak.and_then(|weak| {
						Some(Arc::new(move |receipt: reticulum_rust::link::RequestReceipt| {
							if let Some(peer) = weak.upgrade() {
								if let Ok(mut peer) = peer.lock() {
									peer.request_failed(receipt);
								}
							}
						}) as Arc<dyn Fn(reticulum_rust::link::RequestReceipt) + Send + Sync>)
					});

					if let Err(e) = link.request(
						Self::OFFER_REQUEST_PATH.to_string(),
						buf,
						response_cb,
						failed_cb,
						None,
					) {
						log(&format!("Peer sync request failed: {}", e), LOG_ERROR, false, false);
					} else {
						self.last_offer = unhandled_ids;
						self.state = Self::REQUEST_SENT;
					}
				}
			}
		}
	}

	pub fn request_failed(&mut self, _receipt: reticulum_rust::link::RequestReceipt) {
		log(
			&format!("Sync request to peer {} failed", self),
			LOG_DEBUG,
			false,
			false,
		);
		self.link = None;
		self.state = Self::IDLE;
	}

	pub fn offer_response(&mut self, receipt: reticulum_rust::link::RequestReceipt) {
		self.state = Self::RESPONSE_RECEIVED;
		let response = match receipt.response {
			Some(data) => rmpv::decode::read_value(&mut std::io::Cursor::new(data)).ok(),
			None => None,
		};

		if let Some(Value::Integer(code)) = response.as_ref() {
			let code = code.as_i64().unwrap_or(0) as u8;
			if code == Self::ERROR_NO_IDENTITY {
				log(
					"Remote peer indicated that no identification was received, retrying...",
					LOG_VERBOSE,
					false,
					false,
				);
				self.state = Self::LINK_READY;
				self.sync();
				return;
			} else if code == Self::ERROR_NO_ACCESS {
				log("Remote indicated that access was denied, breaking peering", LOG_VERBOSE, false, false);
				if let Some(router) = self.router.upgrade() {
					if let Ok(mut router) = router.lock() {
						router.unpeer(self.destination_hash.clone(), None);
					}
				}
				return;
			} else if code == Self::ERROR_THROTTLED {
				let throttle_time = LXMRouter::PN_STAMP_THROTTLE as f64;
				log(
					&format!(
						"Remote indicated that we're throttled, postponing sync for {}",
						prettytime(throttle_time, false, false)
					),
					LOG_VERBOSE,
					false,
					false,
				);
				self.next_sync_attempt = now() + throttle_time;
				return;
			}
		}

		let mut wanted_messages: Vec<Vec<u8>> = Vec::new();
		let mut wanted_message_ids: Vec<Vec<u8>> = Vec::new();

		match response {
			Some(Value::Boolean(false)) => {
				if let Some(router) = self.router.upgrade() {
					if let Ok(mut router) = router.lock() {
						for transient_id in self.last_offer.clone() {
							self.add_handled_message(&mut router, transient_id.clone());
							self.remove_unhandled_message(&mut router, &transient_id);
						}
					}
				}
			}
			Some(Value::Boolean(true)) => {
				if let Some(router) = self.router.upgrade() {
					if let Ok(router) = router.lock() {
						for transient_id in self.last_offer.clone() {
							if let Some(entry) = router.propagation_entries.get(&transient_id) {
								wanted_messages.push(entry.filepath.as_bytes().to_vec());
								wanted_message_ids.push(transient_id.clone());
							}
						}
					}
				}
			}
			Some(Value::Array(list)) => {
				let wanted_ids: Vec<Vec<u8>> = list
					.iter()
					.filter_map(|v| match v {
						Value::Binary(bytes) => Some(bytes.clone()),
						_ => None,
					})
					.collect();

				if let Some(router) = self.router.upgrade() {
					if let Ok(mut router) = router.lock() {
						for transient_id in self.last_offer.clone() {
							if !wanted_ids.contains(&transient_id) {
								self.add_handled_message(&mut router, transient_id.clone());
								self.remove_unhandled_message(&mut router, &transient_id);
							}
						}

						for transient_id in wanted_ids {
							if let Some(entry) = router.propagation_entries.get(&transient_id) {
								wanted_messages.push(entry.filepath.as_bytes().to_vec());
								wanted_message_ids.push(transient_id.clone());
							}
						}
					}
				}
			}
			_ => {}
		}

		if !wanted_messages.is_empty() {
			log(
				&format!(
					"Peer {} wanted {} of the available messages",
					prettyhexrep(&self.destination_hash),
					wanted_messages.len()
				),
				LOG_VERBOSE,
				false,
				false,
			);

			let mut lxm_list = Vec::new();
			if let Some(router) = self.router.upgrade() {
				if let Ok(router) = router.lock() {
					for message_entry in &wanted_message_ids {
						if let Some(entry) = router.propagation_entries.get(message_entry) {
							if let Ok(data) = std::fs::read(&entry.filepath) {
								lxm_list.push(data);
							}
						}
					}
				}
			}

			let payload = Value::Array(vec![
				Value::F64(now()),
				Value::Array(lxm_list.iter().map(|d| Value::Binary(d.clone())).collect()),
			]);
			let mut buf = Vec::new();
			let _ = rmpv::encode::write_value(&mut buf, &payload);
			log(
				&format!("Total transfer size for this sync is {}", prettysize(buf.len() as f64, "")),
				LOG_VERBOSE,
				false,
				false,
			);

			if let Some(link) = self.link.clone() {
				let resource_data = Some(ResourceData::Bytes(buf));
				let weak = self.self_handle.clone();
				let callback = weak.clone().map(|weak| {
					Arc::new(move |resource: Arc<Mutex<Resource>>| {
						if let Some(peer) = weak.upgrade() {
							if let Ok(mut peer) = peer.lock() {
								peer.resource_concluded(resource);
							}
						}
					}) as Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>
				});

				// Create with advertise=false; use advertise_shared() so the
				// watchdog & link-registered resource share the same state.
				let resource = Resource::new_internal(
					resource_data,
					link.clone(),
					None,
					false,
					reticulum_rust::resource::AutoCompressOption::Enabled,
					callback,
					None,
					None,
					1,
					None,
					None,
					false,
					0,
				)
				.map_err(|e| {
					log(&format!("Failed to create sync resource: {}", e), LOG_ERROR, false, false);
					e
				});

				if let Ok(resource) = resource {
					let resource_arc = Arc::new(Mutex::new(resource));
					Resource::advertise_shared(resource_arc.clone());
					self.currently_transferring_messages = Some(wanted_message_ids);
					self.current_sync_transfer_started = Some(now());
					self.state = Self::RESOURCE_TRANSFERRING;
					let _ = resource_arc;
				}
			}
		} else {
			log(
				&format!(
					"Peer {} did not request any available messages, sync complete",
					prettyhexrep(&self.destination_hash)
				),
				LOG_VERBOSE,
				false,
				false,
			);
			self.offered += self.last_offer.len() as u64;
			self.link = None;
			self.state = Self::IDLE;
		}
	}

	pub fn resource_concluded(&mut self, resource: Arc<Mutex<Resource>>) {
		if let Ok(resource) = resource.lock() {
			if resource.status == ResourceStatus::Complete {
				if let Some(transfers) = self.currently_transferring_messages.clone() {
					if let Some(router) = self.router.upgrade() {
						if let Ok(mut router) = router.lock() {
							for transient_id in transfers.iter() {
								self.add_handled_message(&mut router, transient_id.clone());
								self.remove_unhandled_message(&mut router, transient_id);
							}
						}
					}
				}
				self.link = None;
				self.state = Self::IDLE;
				if let Some(started) = self.current_sync_transfer_started {
					let rate = (resource.get_transfer_size() as f64 * 8.0) / (now() - started);
					self.sync_transfer_rate = rate;
					log(
						&format!(
							"Syncing messages to peer {} completed at {}",
							prettyhexrep(&self.destination_hash),
							prettyspeed(rate, "")
						),
						LOG_VERBOSE,
						false,
						false,
						);
				}
				self.alive = true;
				self.last_heard = now();
				self.offered += self.last_offer.len() as u64;
				if let Some(transfers) = self.currently_transferring_messages.clone() {
					self.outgoing += transfers.len() as u64;
				}
				self.tx_bytes += resource.get_data_size() as u64;

				self.currently_transferring_messages = None;
				self.current_sync_transfer_started = None;

				if self.sync_strategy == Self::STRATEGY_PERSISTENT {
					if let Some(router) = self.router.upgrade() {
						if let Ok(router) = router.lock() {
							if self.unhandled_message_count(&router) > 0 {
								self.sync();
							}
						}
					}
				}
			} else {
				log(
					&format!("Resource transfer for LXMF peer sync failed to {}", self),
					LOG_VERBOSE,
					false,
					false,
				);
				self.link = None;
				self.state = Self::IDLE;
				self.currently_transferring_messages = None;
				self.current_sync_transfer_started = None;
			}
		}
	}

	pub fn link_established(&mut self, _link: LinkHandle) {
		self.state = Self::LINK_READY;
		self.next_sync_attempt = 0.0;
		self.sync();
	}

	pub fn link_closed(&mut self, _link: LinkHandle) {
		self.link = None;
		self.state = Self::IDLE;
	}

	pub fn queued_items(&self) -> bool {
		!self.handled_messages_queue.is_empty() || !self.unhandled_messages_queue.is_empty()
	}

	pub fn queue_unhandled_message(&mut self, transient_id: Vec<u8>) {
		self.unhandled_messages_queue.push_back(transient_id);
	}

	pub fn queue_handled_message(&mut self, transient_id: Vec<u8>) {
		self.handled_messages_queue.push_back(transient_id);
	}

	pub fn process_queues(&mut self, router: &mut LXMRouter) {
		while let Some(transient_id) = self.handled_messages_queue.pop_back() {
			self.add_handled_message(router, transient_id.clone());
			self.remove_unhandled_message(router, &transient_id);
		}

		while let Some(transient_id) = self.unhandled_messages_queue.pop_back() {
			if !self.handled_messages(router).contains(&transient_id)
				&& !self.unhandled_messages(router).contains(&transient_id)
			{
				self.add_unhandled_message(router, transient_id);
			}
		}
	}

	pub fn handled_messages(&mut self, router: &LXMRouter) -> Vec<Vec<u8>> {
		let handled: Vec<Vec<u8>> = router
			.propagation_entries
			.iter()
			.filter_map(|(tid, entry)| {
				if entry.handled_peers.contains(&self.destination_hash) {
					Some(tid.clone())
				} else {
					None
				}
			})
			.collect();
		self._hm_count = handled.len();
		self._hm_counts_synced = true;
		handled
	}

	pub fn unhandled_messages(&mut self, router: &LXMRouter) -> Vec<Vec<u8>> {
		let unhandled: Vec<Vec<u8>> = router
			.propagation_entries
			.iter()
			.filter_map(|(tid, entry)| {
				if entry.unhandled_peers.contains(&self.destination_hash) {
					Some(tid.clone())
				} else {
					None
				}
			})
			.collect();
		self._um_count = unhandled.len();
		self._um_counts_synced = true;
		unhandled
	}

	pub fn handled_message_count(&mut self, router: &LXMRouter) -> usize {
		if !self._hm_counts_synced {
			self._hm_count = self.handled_messages(router).len();
		}
		self._hm_count
	}

	pub fn unhandled_message_count(&mut self, router: &LXMRouter) -> usize {
		if !self._um_counts_synced {
			self._um_count = self.unhandled_messages(router).len();
		}
		self._um_count
	}

	pub fn acceptance_rate(&self) -> f64 {
		if self.offered == 0 {
			0.0
		} else {
			self.outgoing as f64 / self.offered as f64
		}
	}

	pub fn add_handled_message(&mut self, router: &mut LXMRouter, transient_id: Vec<u8>) {
		if let Some(entry) = router.propagation_entries.get_mut(&transient_id) {
			if !entry.handled_peers.contains(&self.destination_hash) {
				entry.handled_peers.push(self.destination_hash.clone());
				self._hm_counts_synced = false;
			}
		}
	}

	pub fn add_unhandled_message(&mut self, router: &mut LXMRouter, transient_id: Vec<u8>) {
		if let Some(entry) = router.propagation_entries.get_mut(&transient_id) {
			if !entry.unhandled_peers.contains(&self.destination_hash) {
				entry.unhandled_peers.push(self.destination_hash.clone());
				self._um_counts_synced = false;
			}
		}
	}

	pub fn remove_handled_message(&mut self, router: &mut LXMRouter, transient_id: &Vec<u8>) {
		if let Some(entry) = router.propagation_entries.get_mut(transient_id) {
			entry.handled_peers.retain(|hash| hash != &self.destination_hash);
			self._hm_counts_synced = false;
		}
	}

	pub fn remove_unhandled_message(&mut self, router: &mut LXMRouter, transient_id: &Vec<u8>) {
		if let Some(entry) = router.propagation_entries.get_mut(transient_id) {
			entry.unhandled_peers.retain(|hash| hash != &self.destination_hash);
			self._um_counts_synced = false;
		}
	}

	pub fn name(&self) -> Option<String> {
		if let Some(metadata) = &self.metadata {
			if let Ok(Value::Map(map)) = rmpv::decode::read_value(&mut std::io::Cursor::new(metadata)) {
				for (key, value) in map {
					if let Value::Integer(meta_key) = key {
						if meta_key.as_u64().unwrap_or(0) as u8 == crate::lxmf::PN_META_NAME {
							if let Value::Binary(val_bytes) = value {
								return String::from_utf8(val_bytes.clone()).ok();
							}
						}
					}
				}
			}
		}
		None
	}
}

impl std::fmt::Display for LXMPeer {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if !self.destination_hash.is_empty() {
			write!(f, "{}", prettyhexrep(&self.destination_hash))
		} else {
			write!(f, "<Unknown>")
		}
	}
}
