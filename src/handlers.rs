use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rmpv::Value;

use reticulum_rust::transport::{AnnounceHandler, AnnounceCallback};

use crate::lx_message::LXMessage;
use crate::lxmf::{APP_NAME, display_name_from_app_data, pn_announce_data_is_valid, stamp_cost_from_app_data};
use crate::lxm_router::LXMRouter;

fn now() -> f64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs_f64())
		.unwrap_or(0.0)
}

pub fn delivery_announce_handler(router: Arc<Mutex<LXMRouter>>) -> AnnounceHandler {
	let callback: AnnounceCallback = Arc::new(move |destination_hash, _identity, app_data, _announce_hash, _is_path_response| {
		if let Ok(mut router) = router.lock() {
			let display_name = display_name_from_app_data(Some(app_data));

			// Always notify external listener (e.g. iOS) about every LXMF
			// delivery announce so peerLastSeen is populated for deliveryMethod()
			// regardless of whether the destination is in our watched set.
			if let Some(ref cb) = router.announce_callback {
				cb(destination_hash, display_name.clone());
			}

			// Fast path: skip heavy processing for destinations we don't care about.
			// Only update stamp cost and trigger outbound if watched OR has pending.
			let is_watched = router.watched_destinations.contains(destination_hash);
			let has_pending = if !is_watched {
				router.pending_outbound.iter().any(|msg| {
					msg.lock().ok().map(|lxm| lxm.destination_hash == destination_hash).unwrap_or(false)
				})
			} else {
				false
			};

			if !is_watched && !has_pending {
				return;
			}

			let stamp_cost = stamp_cost_from_app_data(Some(app_data))
				.and_then(|value| if value >= 0 { Some(value as u32) } else { None });

			router.update_stamp_cost(destination_hash, stamp_cost);

			let mut should_trigger = false;
			for message in router.pending_outbound.iter() {
				if let Ok(mut lxm) = message.lock() {
					if lxm.destination_hash == destination_hash
						&& (lxm.method == LXMessage::DIRECT || lxm.method == LXMessage::OPPORTUNISTIC)
					{
						lxm.next_delivery_attempt = Some(now());
						should_trigger = true;
					}
				}
			}

			if should_trigger {
				router.process_outbound();
			}

			// App links: if this destination is in app_links and no active
			// link exists, establish one now that the path is available.
			if router.app_links.contains_key(destination_hash)
				&& router.peer_link_status(destination_hash) == 0
			{
				router.establish_app_link(destination_hash);
			}
		}
	});

	AnnounceHandler {
		aspect_filter: Some(format!("{}.delivery", APP_NAME)),
		receive_path_responses: true,
		callback,
	}
}

pub fn propagation_announce_handler(router: Arc<Mutex<LXMRouter>>) -> AnnounceHandler {
	let callback: AnnounceCallback = Arc::new(move |destination_hash, _identity, app_data, _announce_hash, is_path_response| {
		if let Ok(mut router) = router.lock() {
			if !router.propagation_node {
				return;
			}

			if !pn_announce_data_is_valid(app_data) {
				return;
			}

			let config = match rmpv::decode::read_value(&mut std::io::Cursor::new(app_data)) {
				Ok(Value::Array(items)) => items,
				_ => return,
			};

			if config.len() < 7 {
				return;
			}

			let node_timebase = config[1].as_i64().unwrap_or(0) as i64;
			let propagation_enabled = config[2].as_bool().unwrap_or(false);
			let transfer_limit = config[3].as_i64().unwrap_or(0) as i64;
			let sync_limit = config[4].as_i64().unwrap_or(0) as i64;
			let (stamp_cost, stamp_flex, peering_cost) = match &config[5] {
				Value::Array(costs) if costs.len() >= 3 => {
					(
						costs[0].as_i64().unwrap_or(0) as i64,
						costs[1].as_i64().unwrap_or(0) as i64,
						costs[2].as_i64().unwrap_or(0) as i64,
					)
				}
				_ => (0, 0, 0),
			};
			let metadata_value = config[6].clone();
			let mut metadata = Vec::new();
			let _ = rmpv::encode::write_value(&mut metadata, &metadata_value);

			if router.static_peers.contains(&destination_hash.to_vec()) {
				if !is_path_response || router.peers.get(destination_hash).map(|peer| peer.lock().ok().map(|p| p.last_heard == 0.0)).flatten().unwrap_or(true) {
					router.peer(
						destination_hash.to_vec(),
						node_timebase as f64,
						transfer_limit as f64,
						if sync_limit > 0 { Some(sync_limit as f64) } else { None },
						stamp_cost as u32,
						stamp_flex as u32,
						peering_cost as u32,
						metadata,
					);
				}
			} else if router.autopeer && !is_path_response {
				if propagation_enabled {
					router.peer(
						destination_hash.to_vec(),
						node_timebase as f64,
						transfer_limit as f64,
						if sync_limit > 0 { Some(sync_limit as f64) } else { None },
						stamp_cost as u32,
						stamp_flex as u32,
						peering_cost as u32,
						metadata,
					);
				} else {
					router.unpeer(destination_hash.to_vec(), Some(node_timebase as f64));
				}
			}
		}
	});

	AnnounceHandler {
		aspect_filter: Some(format!("{}.propagation", APP_NAME)),
		receive_path_responses: true,
		callback,
	}
}

/// Create an announce handler that re-establishes an app-link for a specific
/// destination aspect whenever an announce (or path-response) arrives.
///
/// The `delivery_announce_handler` only fires for `lxmf.delivery`, so
/// app-links to other aspects (e.g. `rfed.channel`) need their own handlers.
/// Callers register one handler per extra aspect they care about.
///
/// # Arguments
/// * `router`        – shared LXMRouter (the one holding `app_links`).
/// * `aspect_filter` – full dot-separated name of the aspect to watch,
///   e.g. `"rfed.channel"` or `"rfed.notify"`.
pub fn app_link_reconnect_handler(
	router: Arc<Mutex<LXMRouter>>,
	aspect_filter: String,
) -> AnnounceHandler {
	let callback: AnnounceCallback = Arc::new(move |destination_hash, _identity, _app_data, _announce_hash, _is_path_response| {
		// Decide under the lock, then drop the guard BEFORE calling
		// establish_app_link.  establish_app_link calls LinkHandle::initiate(),
		// which blocks on the link actor's response and can take seconds
		// while Transport::outbound paces packets.  Holding the router mutex
		// across that round-trip serialised every other router caller — most
		// visibly freezing the UI thread inside `app_link_status()` — and
		// deadlocked when multiple back-to-back announces fired the handler.
		let should_reconnect = match router.lock() {
			Ok(router) => {
				router.app_links.contains_key(destination_hash)
					&& router.app_link_status(destination_hash) == LXMRouter::APP_LINK_DISCONNECTED
			}
			Err(_) => false,
		};
		if !should_reconnect {
			return;
		}
		// Hand the blocking work to a background thread so the announce
		// handler returns immediately.  Cloning the Arc is cheap.
		let router_for_thread = router.clone();
		let dest = destination_hash.to_vec();
		std::thread::spawn(move || {
			if let Ok(mut router) = router_for_thread.lock() {
				// Route through the announce-trigger entry point: it re-checks
				// under the lock and consults the per-spec `attempt_in_flight`
				// gate so duplicate announces collapse to a single LR.
				router.app_link_announce_received(&dest);
			}
		});
	});

	AnnounceHandler {
		aspect_filter: Some(aspect_filter),
		receive_path_responses: true,
		callback,
	}
}
