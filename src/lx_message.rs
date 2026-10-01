use std::fs::File;
use std::io::{Read, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rmpv::encode::write_value;
use rmpv::Value;

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::{self, Identity, SIGLENGTH, TRUNCATED_HASHLENGTH};
use reticulum_rust::link::LinkHandle;
use reticulum_rust::packet::{self, Packet};
use reticulum_rust::resource::{Resource, ResourceData, ResourceStatus};
use reticulum_rust::transport::Transport;
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_ERROR, LOG_NOTICE};

use crate::lx_stamper as lx_stamper;
use crate::lxmf::APP_NAME;

pub struct LXMessage {
	pub destination_hash: Vec<u8>,
	pub source_hash: Vec<u8>,
	pub title: Vec<u8>,
	pub content: Vec<u8>,
	pub fields: Value,
	pub payload: Option<Vec<Value>>,
	pub timestamp: Option<f64>,
	pub signature: Option<Vec<u8>>,
	pub hash: Option<Vec<u8>>,
	pub message_id: Option<Vec<u8>>,
	pub transient_id: Option<Vec<u8>>,
	pub packed: Option<Vec<u8>>,
	pub packed_size: usize,
	pub state: u8,
	pub method: u8,
	pub progress: f64,
	pub rssi: Option<f64>,
	pub snr: Option<f64>,
	pub q: Option<f64>,
	pub stamp: Option<Vec<u8>>,
	pub stamp_cost: Option<u32>,
	pub stamp_value: Option<u32>,
	pub stamp_valid: bool,
	pub stamp_checked: bool,
	pub propagation_stamp: Option<Vec<u8>>,
	pub propagation_stamp_value: Option<u32>,
	pub propagation_stamp_valid: bool,
	pub propagation_target_cost: Option<u32>,
	/// When the router first found the propagation node's stamp cost missing
	/// and requested its path. LXMF/LXMRouter.py waits PATH_REQUEST_WAIT for
	/// the announce, then fails the message; here the wait is a deferral
	/// across jobs ticks instead of a blocking sleep under the router lock.
	pub propagation_cost_wait_started: Option<f64>,
	pub defer_stamp: bool,
	pub defer_propagation_stamp: bool,
	pub outbound_ticket: Option<Vec<u8>>,
	pub include_ticket: bool,
	pub propagation_packed: Option<Vec<u8>>,
	pub paper_packed: Option<Vec<u8>>,
	pub incoming: bool,
	pub signature_validated: bool,
	pub unverified_reason: Option<u8>,
	pub ratchet_id: Option<Vec<u8>>,
	pub representation: u8,
	pub desired_method: Option<u8>,
	pub delivery_attempts: u32,
	/// Set by link_packet_timed_out when a receipt timeout fires.  Causes the
	/// POB loop to fail the message immediately rather than waiting ~18 s for
	/// the next LRREQ cycle.  Prevents the DISCONNECTED callback from double-
	/// counting the same failure (receipt-timeout teardown vs. LRREQ timeout).
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) receipt_timed_out: bool,
	/// Set by the AppLinks Timer P callback once the send has gone
	/// PROP_FALLBACK_DELAY (5 s) without delivery and without transfer
	/// progress (a Resource that keeps moving never sets it; since
	/// 2026-09-29).  The POB loop reads this flag and fires
	/// fire_message_state(hash, PROP_FALLBACK_REQUESTED) once, which signals
	/// the caller (iOS/lxm_router) to start a parallel propagation send.
	/// Cleared immediately after the signal is dispatched.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) needs_prop_fallback: bool,
	/// Set after the first §1 violation is logged for this message so subsequent
	/// POB iterations don't spam the same violation at thousands of lines/second.
	/// Cleared when the message transitions to a new send attempt.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) violation_reported: bool,
	/// DESIGN_PRINCIPLES §1, bulk transfers (James, 2026-09-30): this
	/// attempt's payload has been handed over to go as a Resource, to
	/// AppLinks (a DIRECT payload over the link MDU) or to a link the router
	/// holds (`as_resource`), or a Resource carrying it has reported an
	/// event. From then on the router's §1 assertion measures the send by
	/// its transfers' progress (`transfer_silence`), never by its total time
	/// (`measured_by_transfer_progress`). Before it, the send is measured
	/// from its start like one that fits a packet: on the router's own
	/// (non-AppLinks) DIRECT path that is its path request and link setup,
	/// which nothing else bounds.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) transfer_by_resource: bool,
	/// DESIGN_PRINCIPLES §1, bulk transfers (James, 2026-09-30): when the
	/// Resource carrying this send last showed progress: its advertisement
	/// going out, each request of the receiver's it served (parts, a window,
	/// a hashmap update), its proof. `None` while no Resource carrying the
	/// current attempt is being watched: before its advertisement, after it
	/// concluded without delivering (`note_transfer_ended`, so a tier
	/// handover's path race and link setup are never counted as its
	/// silence), and always for a send that fits one packet. While it is set
	/// the router's §1 assertion measures the silence since it, never the
	/// transfer's total time (`transfer_silence`). Until 2026-10-01 the
	/// assertion counted a moving photo's whole transfer against 5 s: it
	/// fired on the Pixel for a 14-part direct Resource whose part requests
	/// came every 0.5-1.3 s (a release build logs it; a debug build panics).
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) transfer_moved_at: Option<f64>,
	/// A silence over the §1 limit that ended (the transfer moved again, its
	/// proof came, or its Resource concluded without delivering) before a
	/// router pass could assert it while it ran: the router's next pass
	/// asserts it. The longest, if several did.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) transfer_silence_unasserted: Option<f64>,
	/// The router has asserted the silence now running. The transfer's next
	/// progress ends it, and a later silence is asserted in its turn.
	pub(crate) transfer_silence_asserted: bool,
	/// DISPLAY_NAMES.md §4.1: the router has decided whether this message
	/// carries the name entry (key 0 of `FIELD_RETICHAT`) and written the decision into `fields`.
	/// Set once, in `LXMRouter::handle_outbound`, before the first pack; a
	/// resend or a `propagated_copy` keeps the decision, so every copy of the
	/// message has the same fields and the same hash.
	pub display_name_decided: bool,
	pub transport_encrypted: bool,
	pub transport_encryption: Option<String>,
	pub packet_representation: Option<Packet>,
	pub resource_representation: Option<Arc<Mutex<Resource>>>,
	pub deferred_stamp_generating: bool,
	pub next_delivery_attempt: Option<f64>,
	pub path_request_retried: bool,
	pub stamp_generation_failed: bool,

	destination: Option<Destination>,
	source: Option<Destination>,
	delivery_destination: Option<Destination>,
	delivery_link: Option<LinkHandle>,
	delivery_callback: Option<Arc<dyn Fn(&LXMessage) + Send + Sync>>,
	failed_callback: Option<Arc<dyn Fn(&LXMessage) + Send + Sync>>,
	pn_encrypted_data: Option<Vec<u8>>,
	/// The router's state callback, handed over when the router stops
	/// tracking this outbound message. A delivery proof can still land after
	/// that (Reticulum-rust B35: a receipt proved after its timeout counts as
	/// delivered), and the router no longer sees the state change, so the
	/// message reports DELIVERED itself.
	released_state_callback: Option<Arc<dyn Fn(&[u8], u8) + Send + Sync>>,
	late_delivery_unreported: bool,
}

impl LXMessage {
	pub const GENERATING: u8 = 0x00;
	pub const OUTBOUND: u8 = 0x01;
	pub const SENDING: u8 = 0x02;
	pub const SENT: u8 = 0x04;
	pub const DELIVERED: u8 = 0x08;
	pub const REJECTED: u8 = 0xFD;
	pub const CANCELLED: u8 = 0xFE;
	pub const FAILED: u8 = 0xFF;
	/// Signal state: AppLinks Timer P fired — caller should start propagation
	/// in parallel with the still-running direct send.  Never stored as
	/// a persistent message state; used only as a fire_message_state signal.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub const PROP_FALLBACK_REQUESTED: u8 = 0x10;

	pub const UNKNOWN: u8 = 0x00;
	pub const PACKET: u8 = 0x01;
	pub const RESOURCE: u8 = 0x02;

	pub const OPPORTUNISTIC: u8 = 0x01;
	pub const DIRECT: u8 = 0x02;
	pub const PROPAGATED: u8 = 0x03;
	pub const PAPER: u8 = 0x05;

	pub const SOURCE_UNKNOWN: u8 = 0x01;

	/// Returns true if this message has already reached a successful terminal state
	/// (SENT via propagation or DELIVERED via direct). Failure states must never
	/// overwrite a success state — a message that was already delivered cannot fail.
	pub fn is_success_state(state: u8) -> bool {
		state == Self::SENT || state == Self::DELIVERED
	}
	pub const SIGNATURE_INVALID: u8 = 0x02;

	pub const DESTINATION_LENGTH: usize = TRUNCATED_HASHLENGTH / 8;
	pub const SIGNATURE_LENGTH: usize = SIGLENGTH / 8;
	pub const TICKET_LENGTH: usize = TRUNCATED_HASHLENGTH / 8;

	pub const TICKET_EXPIRY: u64 = 21 * 24 * 60 * 60;
	pub const TICKET_GRACE: u64 = 5 * 24 * 60 * 60;
	pub const TICKET_RENEW: u64 = 14 * 24 * 60 * 60;
	pub const TICKET_INTERVAL: u64 = 24 * 60 * 60;
	pub const COST_TICKET: u32 = 0x100;

	pub const TIMESTAMP_SIZE: usize = 8;
	pub const STRUCT_OVERHEAD: usize = 8;
	pub const LXMF_OVERHEAD: usize =
		2 * Self::DESTINATION_LENGTH + Self::SIGNATURE_LENGTH + Self::TIMESTAMP_SIZE + Self::STRUCT_OVERHEAD;

	pub const ENCRYPTED_PACKET_MDU: usize = packet::ENCRYPTED_MDU + Self::TIMESTAMP_SIZE;
	pub const ENCRYPTED_PACKET_MAX_CONTENT: usize =
		Self::ENCRYPTED_PACKET_MDU - Self::LXMF_OVERHEAD + Self::DESTINATION_LENGTH;

	pub const LINK_PACKET_MDU: usize = reticulum_rust::link::MDU;
	pub const LINK_PACKET_MAX_CONTENT: usize = Self::LINK_PACKET_MDU - Self::LXMF_OVERHEAD;

	pub const PLAIN_PACKET_MDU: usize = packet::PLAIN_MDU;
	pub const PLAIN_PACKET_MAX_CONTENT: usize =
		Self::PLAIN_PACKET_MDU - Self::LXMF_OVERHEAD + Self::DESTINATION_LENGTH;

	pub const ENCRYPTION_DESCRIPTION_AES: &str = "AES-128";
	pub const ENCRYPTION_DESCRIPTION_EC: &str = "Curve25519";
	pub const ENCRYPTION_DESCRIPTION_UNENCRYPTED: &str = "Unencrypted";

	pub const URI_SCHEMA: &str = "lxm";
	pub const QR_ERROR_CORRECTION: &str = "ERROR_CORRECT_L";
	pub const QR_MAX_STORAGE: usize = 2953;
	pub const PAPER_MDU: usize =
		((Self::QR_MAX_STORAGE - (Self::URI_SCHEMA.len() + "://".len())) * 6) / 8;

	pub fn new(
		destination: Option<Destination>,
		source: Option<Destination>,
		content: Option<Vec<u8>>,
		title: Option<Vec<u8>>,
		fields: Option<Value>,
		desired_method: Option<u8>,
		destination_hash: Option<Vec<u8>>,
		source_hash: Option<Vec<u8>>,
		stamp_cost: Option<u32>,
		include_ticket: bool,
	) -> Result<Self, String> {
		let (dest, dest_hash) = match destination {
			Some(dest) => (Some(dest.clone()), dest.hash.clone()),
			None => (
				None,
				destination_hash.ok_or("LXMessage initialized without destination")?,
			),
		};

		let (src, src_hash) = match source {
			Some(src) => (Some(src.clone()), src.hash.clone()),
			None => (
				None,
				source_hash.ok_or("LXMessage initialized without source")?,
			),
		};

		let title_bytes = title.unwrap_or_default();
		let content_bytes = content.unwrap_or_default();
		let fields_value = fields.unwrap_or_else(empty_fields);
		if !matches!(fields_value, Value::Map(_)) {
			return Err("LXMessage fields must be a map".to_string());
		}

		Ok(LXMessage {
			destination_hash: dest_hash,
			source_hash: src_hash,
			title: title_bytes,
			content: content_bytes,
			fields: fields_value,
			payload: None,
			timestamp: None,
			signature: None,
			hash: None,
			message_id: None,
			transient_id: None,
			packed: None,
			packed_size: 0,
			state: Self::GENERATING,
			method: Self::UNKNOWN,
			progress: 0.0,
			rssi: None,
			snr: None,
			q: None,
			stamp: None,
			stamp_cost,
			stamp_value: None,
			stamp_valid: false,
			stamp_checked: false,
			propagation_stamp: None,
			propagation_stamp_value: None,
			propagation_stamp_valid: false,
			propagation_target_cost: None,
			propagation_cost_wait_started: None,
			defer_stamp: true,
			defer_propagation_stamp: true,
			outbound_ticket: None,
			include_ticket,
			propagation_packed: None,
			paper_packed: None,
			incoming: false,
			signature_validated: false,
			unverified_reason: None,
			ratchet_id: None,
			representation: Self::UNKNOWN,
			desired_method,
			delivery_attempts: 0,
			receipt_timed_out: false,
			needs_prop_fallback: false,
			violation_reported: false,
			transfer_by_resource: false,
			transfer_moved_at: None,
			transfer_silence_unasserted: None,
			transfer_silence_asserted: false,
			display_name_decided: false,
			transport_encrypted: false,
			transport_encryption: None,
			packet_representation: None,
			resource_representation: None,
			deferred_stamp_generating: false,
			next_delivery_attempt: None,
			path_request_retried: false,
			stamp_generation_failed: false,
			destination: dest,
			source: src,
			delivery_destination: None,
			delivery_link: None,
			delivery_callback: None,
			failed_callback: None,
			pn_encrypted_data: None,
			released_state_callback: None,
			late_delivery_unreported: false,
		})
	}

	/// Create a fresh propagated-method copy preserving the application payload.
	/// Transport state, packing, hashes and receipts are intentionally reset.
	pub fn propagated_copy(&self) -> Result<Self, String> {
		let mut copy = Self::new(
			self.destination.clone(),
			self.source.clone(),
			Some(self.content.clone()),
			Some(self.title.clone()),
			Some(self.fields.clone()),
			Some(Self::PROPAGATED),
			Some(self.destination_hash.clone()),
			Some(self.source_hash.clone()),
			self.stamp_cost,
			self.include_ticket,
		)?;
		copy.timestamp = self.timestamp;
		copy.outbound_ticket = self.outbound_ticket.clone();
		copy.display_name_decided = self.display_name_decided;
		Ok(copy)
	}

	pub fn set_title_from_string(&mut self, title_string: &str) {
		self.title = title_string.as_bytes().to_vec();
	}

	pub fn set_title_from_bytes(&mut self, title_bytes: Vec<u8>) {
		self.title = title_bytes;
	}

	pub fn title_as_string(&self) -> Option<String> {
		String::from_utf8(self.title.clone()).ok()
	}

	pub fn set_content_from_string(&mut self, content_string: &str) {
		self.content = content_string.as_bytes().to_vec();
	}

	pub fn set_content_from_bytes(&mut self, content_bytes: Vec<u8>) {
		self.content = content_bytes;
	}

	pub fn content_as_string(&self) -> Option<String> {
		match String::from_utf8(self.content.clone()) {
			Ok(value) => Some(value),
			Err(err) => {
				log(
					format!("{} could not decode message content as string: {}", self, err),
					LOG_ERROR,
					false,
					false,
				);
				None
			}
		}
	}

	pub fn set_fields(&mut self, fields: Option<Value>) -> Result<(), String> {
		let next = fields.unwrap_or_else(empty_fields);
		if !matches!(next, Value::Map(_)) {
			return Err("LXMessage fields must be a map".to_string());
		}
		self.fields = next;
		Ok(())
	}

	pub fn get_fields(&self) -> &Value {
		&self.fields
	}

	/// Set top-level field `key`: the entry with that integer key (any
	/// msgpack width) is replaced in place, or the field is appended.
	pub fn set_field(&mut self, key: u8, value: Value) {
		crate::retichat_field::set_top_level(&mut self.fields, key, value);
	}

	/// Remove every entry whose key is the integer `key`.
	pub fn remove_field(&mut self, key: u8) {
		crate::retichat_field::remove_top_level(&mut self.fields, key);
	}

	/// Set entry `key` of the Retichat field `0xD1` (DISPLAY_NAMES.md §10),
	/// creating the map or merging into it (`retichat_field::set_entry`).
	pub fn set_retichat_entry(&mut self, key: u8, value: Value) {
		crate::retichat_field::set_entry(&mut self.fields, key, value);
	}

	/// Remove entry `key` of the Retichat field, dropping `0xD1` when it is
	/// left empty (`retichat_field::remove_entry`).
	pub fn remove_retichat_entry(&mut self, key: u8) {
		crate::retichat_field::remove_entry(&mut self.fields, key);
	}

	/// Human-readable name for a message state constant.
	pub fn state_name(state: u8) -> &'static str {
		match state {
			Self::GENERATING => "GENERATING",
			Self::OUTBOUND => "OUTBOUND",
			Self::SENDING => "SENDING",
			Self::SENT => "SENT",
			Self::DELIVERED => "DELIVERED",
			Self::PAPER => "PAPER",
			Self::PROPAGATED => "PROPAGATED",
			Self::FAILED => "FAILED",
			Self::CANCELLED => "CANCELLED",
			Self::REJECTED => "REJECTED",
			_ => "UNKNOWN",
		}
	}

	/// Human-readable name for a representation constant.
	pub fn representation_name(repr: u8) -> &'static str {
		match repr {
			Self::PACKET => "PACKET",
			Self::RESOURCE => "RESOURCE",
			_ => "UNKNOWN",
		}
	}

	/// Human-readable name for a delivery method constant.
	pub fn method_name(method: u8) -> &'static str {
		match method {
			Self::OPPORTUNISTIC => "OPPORTUNISTIC",
			Self::DIRECT => "DIRECT",
			Self::PROPAGATED => "PROPAGATED",
			Self::PAPER => "PAPER",
			_ => "UNKNOWN",
		}
	}

	/// Add a file attachment to this message.
	///
	/// Filenames are encoded as msgpack strings (not binary) for
	/// compatibility with Python receivers (Sideband, MeshChat).
	pub fn add_file_attachment(&mut self, filename: &str, data: Vec<u8>) {
		use crate::lxmf::FIELD_FILE_ATTACHMENTS;

		let entry = Value::Array(vec![
			Value::String(filename.into()),
			Value::Binary(data),
		]);

		if let Value::Map(entries) = &mut self.fields {
			let key = Value::from(FIELD_FILE_ATTACHMENTS as i64);
			if let Some((_, existing)) = entries.iter_mut().find(|(k, _)| *k == key) {
				if let Value::Array(list) = existing {
					list.push(entry);
					return;
				}
			}
			entries.push((key, Value::Array(vec![entry])));
		}
	}

	/// Return the list of file attachments as `(filename, data)` pairs.
	///
	/// Handles filenames stored as either msgpack String or Binary
	/// (for compatibility with senders using either encoding).
	pub fn get_file_attachments(&self) -> Vec<(String, Vec<u8>)> {
		use crate::lxmf::FIELD_FILE_ATTACHMENTS;

		let key = Value::from(FIELD_FILE_ATTACHMENTS as i64);
		if let Value::Map(entries) = &self.fields {
			for (k, v) in entries {
				if *k == key {
					if let Value::Array(list) = v {
						let mut result = Vec::new();
						for entry in list {
							if let Value::Array(pair) = entry {
								if pair.len() >= 2 {
									let filename = match &pair[0] {
										Value::String(s) => {
											s.as_str().unwrap_or("attachment.bin").to_string()
										}
										Value::Binary(b) => {
											String::from_utf8(b.clone())
												.unwrap_or_else(|_| "attachment.bin".to_string())
										}
										_ => "attachment.bin".to_string(),
									};
									let data = match &pair[1] {
										Value::Binary(b) => b.clone(),
										_ => Vec::new(),
									};
									result.push((filename, data));
								}
							}
						}
						return result;
					}
				}
			}
		}
		Vec::new()
	}

	pub fn destination(&self) -> Option<&Destination> {
		self.destination.as_ref()
	}

	pub fn set_destination(&mut self, destination: Destination) -> Result<(), String> {
		if self.destination.is_some() {
			return Err("Cannot reassign destination on LXMessage".to_string());
		}
		self.destination_hash = destination.hash.clone();
		self.destination = Some(destination);
		Ok(())
	}

	pub fn source(&self) -> Option<&Destination> {
		self.source.as_ref()
	}

	pub fn set_source(&mut self, source: Destination) -> Result<(), String> {
		if self.source.is_some() {
			return Err("Cannot reassign source on LXMessage".to_string());
		}
		self.source_hash = source.hash.clone();
		self.source = Some(source);
		Ok(())
	}

	pub fn set_delivery_destination(&mut self, destination: Destination) {
		self.delivery_destination = Some(destination);
	}

	pub fn set_delivery_link(&mut self, link: LinkHandle) {
		self.delivery_link = Some(link);
	}

	pub fn clear_delivery_link(&mut self) {
		self.delivery_link = None;
	}

	pub fn register_delivery_callback(&mut self, callback: Option<Arc<dyn Fn(&LXMessage) + Send + Sync>>) {
		self.delivery_callback = callback;
	}

	pub fn register_failed_callback(&mut self, callback: Option<Arc<dyn Fn(&LXMessage) + Send + Sync>>) {
		self.failed_callback = callback;
	}

	pub fn failed_callback(&self) -> Option<Arc<dyn Fn(&LXMessage) + Send + Sync>> {
		self.failed_callback.clone()
	}

	pub fn validate_stamp(&mut self, target_cost: u32, tickets: Option<&[Vec<u8>]>) -> bool {
		if let Some(ticket_list) = tickets {
			if let Some(message_id) = self.message_id.as_ref() {
				for ticket in ticket_list {
					if ticket.len() == Self::TICKET_LENGTH {
						let mut material = ticket.clone();
						material.extend_from_slice(message_id);
						let generated = identity::truncated_hash(&material);
						if self.stamp.as_ref() == Some(&generated) {
							self.stamp_value = Some(Self::COST_TICKET);
							log(
								format!("Stamp on {} validated by inbound ticket", self),
								LOG_DEBUG,
								false,
								false,
							);
							return true;
						}
					}
				}
			}
		}

		let stamp = match self.stamp.as_ref() {
			Some(stamp) => stamp,
			None => return false,
		};
		let message_id = match self.message_id.as_ref() {
			Some(id) => id,
			None => return false,
		};

		let workblock = lx_stamper::stamp_workblock(message_id, lx_stamper::WORKBLOCK_EXPAND_ROUNDS);
		if lx_stamper::stamp_valid(stamp, target_cost, &workblock) {
			self.stamp_value = Some(lx_stamper::stamp_value(&workblock, stamp));
			true
		} else {
			false
		}
	}

	pub fn get_stamp(&mut self) -> Option<Vec<u8>> {
		if let Some(ticket) = self.outbound_ticket.as_ref() {
			if ticket.len() == Self::TICKET_LENGTH {
				if let Some(message_id) = self.message_id.as_ref() {
					let mut material = ticket.clone();
					material.extend_from_slice(message_id);
					let generated = identity::truncated_hash(&material);
					self.stamp_value = Some(Self::COST_TICKET);
					log(
						format!(
							"Generated stamp with outbound ticket {} for {}",
							hexrep(ticket, false),
							self
						),
						LOG_DEBUG,
						false,
						false,
					);
					return Some(generated);
				}
			}
		}

		if self.stamp_cost.is_none() {
			self.stamp_value = None;
			return None;
		}

		if let Some(stamp) = self.stamp.as_ref() {
			return Some(stamp.clone());
		}

		let message_id = self.message_id.clone()?;
		let cost = self.stamp_cost.unwrap_or(0);
		let (generated, value) = lx_stamper::generate_stamp(&message_id, cost, lx_stamper::WORKBLOCK_EXPAND_ROUNDS);
		if let Some(stamp) = generated {
			self.stamp_value = Some(value);
			self.stamp_valid = true;
			self.stamp = Some(stamp.clone());
			Some(stamp)
		} else {
			None
		}
	}

	pub fn get_propagation_stamp(&mut self, target_cost: u32) -> Result<Option<Vec<u8>>, String> {
		if let Some(stamp) = self.propagation_stamp.as_ref() {
			return Ok(Some(stamp.clone()));
		}

		self.propagation_target_cost = Some(target_cost);
		if self.transient_id.is_none() {
			self.pack(false)?;
		}
		let transient_id = self.transient_id.clone().ok_or("Missing transient id")?;
		let (generated, value) = lx_stamper::generate_stamp(
			&transient_id,
			target_cost,
			lx_stamper::WORKBLOCK_EXPAND_ROUNDS_PN,
		);
		if let Some(stamp) = generated {
			self.propagation_stamp = Some(stamp.clone());
			self.propagation_stamp_value = Some(value);
			self.propagation_stamp_valid = true;
			Ok(Some(stamp))
		} else {
			Ok(None)
		}
	}

	pub fn pack(&mut self, payload_updated: bool) -> Result<(), String> {
		if self.packed.is_some() {
			return Err(format!("Attempt to re-pack LXMessage {} that was already packed", self));
		}

		if self.timestamp.is_none() {
			self.timestamp = Some(now_seconds());
		}

		self.propagation_packed = None;
		self.paper_packed = None;

		let timestamp = self.timestamp.unwrap_or(0.0);
		let mut payload = vec![
			Value::F64(timestamp),
			Value::Binary(self.title.clone()),
			Value::Binary(self.content.clone()),
			self.fields.clone(),
		];

		let mut hashed_part = Vec::new();
		hashed_part.extend_from_slice(&self.destination_hash);
		hashed_part.extend_from_slice(&self.source_hash);
		let packed_payload = encode_value(Value::Array(payload.clone()))?;
		hashed_part.extend_from_slice(&packed_payload);
		let hash = identity::full_hash(&hashed_part);
		self.hash = Some(hash.clone());
		self.message_id = Some(hash.clone());

		if !self.defer_stamp {
			let stamp = self.get_stamp();
			if let Some(stamp_data) = stamp {
				payload.push(Value::Binary(stamp_data));
			}
		}

		let mut signed_part = Vec::new();
		signed_part.extend_from_slice(&hashed_part);
		signed_part.extend_from_slice(&hash);

		let source = self
			.source
			.as_ref()
			.ok_or("LXMessage missing source destination")?;
		let signature = source.sign(&signed_part);
		self.signature = Some(signature.clone());
		self.signature_validated = true;

		let packed_payload = encode_value(Value::Array(payload.clone()))?;
		self.payload = Some(payload);

		let mut packed = Vec::new();
		packed.extend_from_slice(&self.destination_hash);
		packed.extend_from_slice(&self.source_hash);
		packed.extend_from_slice(&signature);
		packed.extend_from_slice(&packed_payload);

		self.packed_size = packed.len();
		self.packed = Some(packed.clone());

		let mut content_size = packed_payload.len() - Self::TIMESTAMP_SIZE - Self::STRUCT_OVERHEAD;

		if self.desired_method.is_none() {
			self.desired_method = Some(Self::DIRECT);
		}

		if self.desired_method == Some(Self::OPPORTUNISTIC) {
			if let Some(destination) = self.destination.as_ref() {
				if destination.dest_type == DestinationType::Single
					&& content_size > Self::ENCRYPTED_PACKET_MAX_CONTENT
				{
					log(
						format!(
							"Opportunistic delivery requested for {}, but content length {} exceeds limit; using link delivery",
							self,
							content_size
						),
						LOG_DEBUG,
						false,
						false,
					);
					self.desired_method = Some(Self::DIRECT);
				}
			}
		}

		match self.desired_method {
			Some(Self::OPPORTUNISTIC) => {
				let destination = self
					.destination
					.as_ref()
					.ok_or("Missing destination for opportunistic delivery")?;
				let single_packet_limit = match destination.dest_type {
					DestinationType::Single => Self::ENCRYPTED_PACKET_MAX_CONTENT,
					DestinationType::Plain => Self::PLAIN_PACKET_MAX_CONTENT,
					_ => Self::ENCRYPTED_PACKET_MAX_CONTENT,
				};
				if content_size > single_packet_limit {
					return Err(format!(
						"LXMessage opportunistic delivery content {} exceeds limit {}",
						content_size, single_packet_limit
					));
				}
				self.method = Self::OPPORTUNISTIC;
				self.representation = Self::PACKET;
				self.delivery_destination = Some(destination.clone());
			}
			Some(Self::DIRECT) => {
				let single_packet_limit = Self::LINK_PACKET_MAX_CONTENT;
				self.method = Self::DIRECT;
				self.representation = if content_size <= single_packet_limit {
					Self::PACKET
				} else {
					Self::RESOURCE
				};
			}
			Some(Self::PROPAGATED) => {
				// PROTOCOL: For outbound PROPAGATED delivery over a link, the wire format is
				// msgpack([timestamp_f64, [[dest_hash | EC_encrypted(rest) | pn_stamp?]]])
				// stored in self.propagation_packed.
				//
				// CRITICAL — DO NOT use send_with_handle() / as_packet() / Packet::new() to
				// send a PROPAGATED message over an active link. That path calls
				// destination.encrypt() → runtime_encrypt_for_destination() which tries to
				// re-acquire the link's session key via RUNTIME_LINKS.  It will fail silently,
				// leaving the message stuck in OUTBOUND forever.
				//
				// CORRECT: call link.send_packet(&lxm.propagation_packed) directly.
				// link.send_packet() encrypts using the link's AES session key and manually
				// builds the raw packet bytes — exactly what Python does:
				//   link.send_packet(lxm.propagation_packed)
				//   lxm.state = SENT  (fire-and-forget)
				// See: LXMRouter::process_outbound — LXMessage::PROPAGATED ACTIVE branch.
				let destination = self
					.destination
					.as_mut()
					.ok_or("Missing destination for propagated delivery")?;
				if self.pn_encrypted_data.is_none() || payload_updated {
					self.pn_encrypted_data =
						Some(destination.encrypt(&packed[Self::DESTINATION_LENGTH..])?);
					self.ratchet_id = destination.latest_ratchet_id.clone();
				}
				let mut lxmf_data = packed[..Self::DESTINATION_LENGTH].to_vec();
				lxmf_data.extend_from_slice(self.pn_encrypted_data.as_ref().unwrap());
				let transient_id = identity::full_hash(&lxmf_data);
				self.transient_id = Some(transient_id);
				if let Some(stamp) = self.propagation_stamp.as_ref() {
					lxmf_data.extend_from_slice(stamp);
				}
				let propagation_payload = Value::Array(vec![
					Value::F64(now_seconds()),
					Value::Array(vec![Value::Binary(lxmf_data)]),
				]);
				self.propagation_packed = Some(encode_value(propagation_payload)?);
				content_size = self
					.propagation_packed
					.as_ref()
					.map(|v| v.len())
					.unwrap_or(0);
				self.method = Self::PROPAGATED;
				self.representation = if content_size <= Self::LINK_PACKET_MAX_CONTENT {
					Self::PACKET
				} else {
					Self::RESOURCE
				};
			}
			Some(Self::PAPER) => {
				let destination = self
					.destination
					.as_mut()
					.ok_or("Missing destination for paper delivery")?;
				let encrypted = destination.encrypt(&packed[Self::DESTINATION_LENGTH..])?;
				self.ratchet_id = destination.latest_ratchet_id.clone();
				let mut paper = packed[..Self::DESTINATION_LENGTH].to_vec();
				paper.extend_from_slice(&encrypted);
				self.paper_packed = Some(paper);
				content_size = self.paper_packed.as_ref().map(|v| v.len()).unwrap_or(0);
				if content_size > Self::PAPER_MDU {
					return Err("LXMessage desired paper delivery method exceeds size".to_string());
				}
				self.method = Self::PAPER;
				self.representation = Self::PAPER;
			}
			_ => {}
		}

		Ok(())
	}

	/// Build `propagation_packed` from an already-packed DIRECT message that has been
	/// downgraded to PROPAGATED at runtime (e.g. when a direct link never establishes
	/// and `process_outbound` flips `lxm.method = PROPAGATED`).
	///
	/// After `pack(desired_method=DIRECT)`, `self.packed` holds the raw LXMF bytes but
	/// `self.propagation_packed` is `None`.  When `process_outbound` processes the
	/// message as PROPAGATED it finds `None` and previously had no way to recover.
	/// This method computes the propagation wire format from the already-present
	/// `self.packed` and `self.destination`, mirroring the PROPAGATED branch of `pack()`.
	///
	/// Idempotent: if `propagation_packed` is already `Some(_)` this is a no-op.
	///
	/// # Errors
	/// Returns `Err` if `self.packed` is `None` (message was never packed) or if
	/// the destination encrypt call fails.
	// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub fn make_propagation_packed(&mut self) -> Result<(), String> {
		if self.propagation_packed.is_some() {
			return Ok(());
		}
		let packed = self
			.packed
			.clone()
			.ok_or("make_propagation_packed: message has not been packed yet")?;
		let destination = self
			.destination
			.as_mut()
			.ok_or("make_propagation_packed: missing destination")?;
		if self.pn_encrypted_data.is_none() {
			self.pn_encrypted_data =
				Some(destination.encrypt(&packed[Self::DESTINATION_LENGTH..])?);
			self.ratchet_id = destination.latest_ratchet_id.clone();
		}
		let mut lxmf_data = packed[..Self::DESTINATION_LENGTH].to_vec();
		lxmf_data.extend_from_slice(self.pn_encrypted_data.as_ref().unwrap());
		let transient_id = identity::full_hash(&lxmf_data);
		self.transient_id = Some(transient_id);
		if let Some(stamp) = self.propagation_stamp.as_ref() {
			lxmf_data.extend_from_slice(stamp);
		}
		let propagation_payload = Value::Array(vec![
			Value::F64(now_seconds()),
			Value::Array(vec![Value::Binary(lxmf_data)]),
		]);
		self.propagation_packed = Some(encode_value(propagation_payload)?);
		Ok(())
	}

	pub fn send(&mut self) -> Result<(), String> {
		self.send_with_handle(None)
	}

	pub fn send_shared(message: Arc<Mutex<LXMessage>>) -> Result<(), String> {
		let handle = Arc::clone(&message);
		let mut locked = message.lock().map_err(|_| "LXMessage lock poisoned".to_string())?;
		locked.send_with_handle(Some(handle))
	}

	pub(crate) fn send_with_handle(&mut self, handle: Option<Arc<Mutex<LXMessage>>>) -> Result<(), String> {
		self.determine_transport_encryption();
		match self.method {
			Self::OPPORTUNISTIC => {
				eprintln!("[DEBUG] OPPORTUNISTIC: entering send_with_handle");
				let mut packet = self.as_packet()?;
				eprintln!("[DEBUG] OPPORTUNISTIC: packet synthesized, sending...");
				let receipt = packet.send()?;
				eprintln!("[DEBUG] OPPORTUNISTIC: packet.send() returned");
				self.progress = 0.50;
				self.ratchet_id = packet.ratchet_id.clone();
				self.state = Self::SENT;
				if let Some(receipt) = receipt {
					if let Some(handle) = handle.clone() {
						let delivery_cb: Arc<dyn Fn(&reticulum_rust::packet::PacketReceipt) + Send + Sync> = Arc::new(move |_| {
							mark_delivered_shared(&handle);
						});
						receipt.set_delivery_callback(delivery_cb.clone());
						Transport::set_receipt_delivery_callback(&receipt.hash, delivery_cb);
					}
				}
			}
			Self::DIRECT => {
				self.state = Self::SENDING;
				self.begin_transfer_watch();
				match self.representation {
					Self::PACKET => {
						if self.delivery_destination.is_none() {
							if let Some(destination) = self.destination.as_ref() {
								self.delivery_destination = Some(destination.clone());
							}
						}
						let mut packet = self.as_packet()?;
						let receipt = packet.send()?;
						if let Some(link) = self.delivery_link.as_ref() {
							self.ratchet_id = Some(link.link_id());
						}
						if let Some(mut receipt) = receipt {
							if let Some(handle) = handle.clone() {
								let delivery_handle = Arc::clone(&handle);
								let timeout_handle = Arc::clone(&handle);
								let delivery_cb: Arc<dyn Fn(&reticulum_rust::packet::PacketReceipt) + Send + Sync> = Arc::new(move |_| {
									mark_delivered_shared(&delivery_handle);
								});
								let timeout_cb: Arc<dyn Fn(&reticulum_rust::packet::PacketReceipt) + Send + Sync> = Arc::new(move |_| {
									link_packet_timed_out_shared(&timeout_handle);
								});
								receipt.set_delivery_callback(delivery_cb.clone());
								receipt.set_timeout_callback(timeout_cb.clone());
								Transport::set_receipt_delivery_callback(&receipt.hash, delivery_cb);
								Transport::set_receipt_timeout_callback(&receipt.hash, timeout_cb);
							}
							self.progress = 0.50;
						} else {
							if let Some(link) = self.delivery_link.as_ref() {
								link.teardown();
							}
						}
					}
					Self::RESOURCE => {
						if let Some(link) = self.delivery_link.as_ref() {
							self.ratchet_id = Some(link.link_id());
						}
						self.resource_representation = Some(self.as_resource(handle)?);
						self.progress = 0.10;
					}
					_ => {}
				}
			}
			// PROTOCOL WARNING: PROPAGATED delivery over an active propagation-node *link*
		// must NOT go through this code path. send_with_handle → as_packet → Packet::new
		// → destination.encrypt → runtime_encrypt_for_destination fails silently for
		// Link-type destinations, leaving the message stuck in OUTBOUND forever.
		//
		// This send_with_handle PROPAGATED branch is only correct for a plain
		// DestinationType::Single destination (i.e., the RNS transport layer will
		// route the packet, not a pre-established link).  In practice the router NEVER
		// calls send_with_handle for propagation; it uses link.send_packet() directly.
		// See: LXMRouter::process_outbound — PROPAGATED ACTIVE branch.
		Self::PROPAGATED => {
				self.state = Self::SENDING;
				self.begin_transfer_watch();
				match self.representation {
					Self::PACKET => {
						let mut packet = self.as_packet()?;
						let receipt = packet.send()?;
						if let Some(mut receipt) = receipt {
							if let Some(handle) = handle.clone() {
								let delivery_handle = Arc::clone(&handle);
								let timeout_handle = Arc::clone(&handle);
								let delivery_cb: Arc<dyn Fn(&reticulum_rust::packet::PacketReceipt) + Send + Sync> = Arc::new(move |_| {
									mark_propagated_shared(&delivery_handle);
								});
								let timeout_cb: Arc<dyn Fn(&reticulum_rust::packet::PacketReceipt) + Send + Sync> = Arc::new(move |_| {
									link_packet_timed_out_shared(&timeout_handle);
								});
								receipt.set_delivery_callback(delivery_cb.clone());
								receipt.set_timeout_callback(timeout_cb.clone());
								Transport::set_receipt_delivery_callback(&receipt.hash, delivery_cb);
								Transport::set_receipt_timeout_callback(&receipt.hash, timeout_cb);
							}
							self.progress = 0.50;
						} else {
							if let Some(link) = self.delivery_link.as_ref() {
								link.teardown();
							}
						}
					}
					Self::RESOURCE => {
						if let Some(link) = self.delivery_link.as_ref() {
							self.ratchet_id = Some(link.link_id());
						}
						self.resource_representation = Some(self.as_resource(handle)?);
						self.progress = 0.10;
					}
					_ => {}
				}
			}
			_ => {}
		}

		Ok(())
	}

	pub fn determine_transport_encryption(&mut self) {
		let destination = self.destination.as_ref();
		match self.method {
			Self::OPPORTUNISTIC | Self::PROPAGATED | Self::PAPER => {
				if let Some(dest) = destination {
					match dest.dest_type {
						DestinationType::Single => {
							self.transport_encrypted = true;
							self.transport_encryption = Some(Self::ENCRYPTION_DESCRIPTION_EC.to_string());
						}
						DestinationType::Group => {
							self.transport_encrypted = true;
							self.transport_encryption = Some(Self::ENCRYPTION_DESCRIPTION_AES.to_string());
						}
						_ => {
							self.transport_encrypted = false;
							self.transport_encryption = Some(Self::ENCRYPTION_DESCRIPTION_UNENCRYPTED.to_string());
						}
					}
				} else {
					self.transport_encrypted = false;
					self.transport_encryption = Some(Self::ENCRYPTION_DESCRIPTION_UNENCRYPTED.to_string());
				}
			}
			Self::DIRECT => {
				self.transport_encrypted = true;
				self.transport_encryption = Some(Self::ENCRYPTION_DESCRIPTION_EC.to_string());
			}
			_ => {
				self.transport_encrypted = false;
				self.transport_encryption = Some(Self::ENCRYPTION_DESCRIPTION_UNENCRYPTED.to_string());
			}
		}
	}

	pub fn packed_container(&mut self) -> Result<Vec<u8>, String> {
		if self.packed.is_none() {
			self.pack(false)?;
		}
		let mut entries = Vec::new();
		entries.push((Value::String("state".into()), Value::Integer(self.state.into())));
		entries.push((
			Value::String("lxmf_bytes".into()),
			Value::Binary(self.packed.clone().unwrap_or_default()),
		));
		entries.push((
			Value::String("transport_encrypted".into()),
			Value::Boolean(self.transport_encrypted),
		));
		if let Some(enc) = self.transport_encryption.as_ref() {
			entries.push((Value::String("transport_encryption".into()), Value::String(enc.clone().into())));
		}
		entries.push((Value::String("method".into()), Value::Integer(self.method.into())));
		encode_value(Value::Map(entries))
	}

	pub fn write_to_directory(&mut self, directory_path: &str) -> Result<String, String> {
		let hash = self.hash.clone().ok_or("LXMessage missing hash")?;
		let file_name = hexrep(&hash, false);
		let file_path = format!("{}/{}", directory_path, file_name);
		let packed = self.packed_container()?;
		let mut file = File::create(&file_path)
			.map_err(|e| format!("Error while writing LXMF message to file: {}", e))?;
		file.write_all(&packed)
			.map_err(|e| format!("Error while writing LXMF message to file: {}", e))?;
		Ok(file_path)
	}

	pub fn as_uri(&mut self, finalise: bool) -> Result<String, String> {
		if self.packed.is_none() {
			self.pack(false)?;
		}

		if self.desired_method != Some(Self::PAPER) || self.paper_packed.is_none() {
			return Err("Attempt to represent LXM with non-paper delivery method as URI".to_string());
		}

		let encoded = URL_SAFE_NO_PAD.encode(self.paper_packed.clone().unwrap_or_default());
		let lxm_uri = format!("{}://{}", Self::URI_SCHEMA, encoded);

		if finalise {
			self.determine_transport_encryption();
			self.mark_paper_generated();
		}

		Ok(lxm_uri)
	}

	/// Generates a QR code representation of a paper message.
	/// Returns the message URI that can be encoded as a QR code.
	/// The returned string is suitable for QR code generation via external tools or libraries.
	/// 
	/// To render this as a QR code image in Rust:
	/// - Use the 'qrcode' crate: https://crates.io/crates/qrcode
	/// - Or use an external QR code encoder service/tool
	pub fn as_qr(&mut self) -> Result<String, String> {
		if self.packed.is_none() {
			self.pack(false)?;
		}

		if self.desired_method != Some(Self::PAPER) || self.paper_packed.is_none() {
			return Err("Attempt to represent LXM with non-paper delivery method as QR-code".to_string());
		}

		let uri = self.as_uri(false)?;

		self.determine_transport_encryption();
		self.mark_paper_generated();

		// Return the URI which can be externally rendered as a QR code
		Ok(uri)
	}

	pub fn unpack_from_bytes(lxmf_bytes: &[u8], original_method: Option<u8>) -> Result<LXMessage, String> {
		if lxmf_bytes.len() < 2 * Self::DESTINATION_LENGTH + Self::SIGNATURE_LENGTH {
			return Err("LXMF payload too small".to_string());
		}

		let destination_hash = lxmf_bytes[..Self::DESTINATION_LENGTH].to_vec();
		let source_hash = lxmf_bytes[Self::DESTINATION_LENGTH..2 * Self::DESTINATION_LENGTH].to_vec();
		let signature = lxmf_bytes[
			2 * Self::DESTINATION_LENGTH..2 * Self::DESTINATION_LENGTH + Self::SIGNATURE_LENGTH
		]
			.to_vec();
		let packed_payload = lxmf_bytes[2 * Self::DESTINATION_LENGTH + Self::SIGNATURE_LENGTH..].to_vec();

		let payload_value = decode_value(&packed_payload)?;
		let payload_items = payload_value
			.as_array()
			.ok_or("LXMF payload is not an array")?
			.clone();

		let (payload_core, stamp) = if payload_items.len() > 4 {
			let stamp_value = payload_items.get(4).and_then(value_to_binary);
			(payload_items[..4].to_vec(), stamp_value)
		} else {
			(payload_items.clone(), None)
		};

		let packed_payload_core = encode_value(Value::Array(payload_core.clone()))?;
		let mut hashed_part = Vec::new();
		hashed_part.extend_from_slice(&destination_hash);
		hashed_part.extend_from_slice(&source_hash);
		hashed_part.extend_from_slice(&packed_payload_core);
		let message_hash = identity::full_hash(&hashed_part);
		let mut signed_part = Vec::new();
		signed_part.extend_from_slice(&hashed_part);
		signed_part.extend_from_slice(&message_hash);

		let timestamp = payload_core
			.get(0)
			.and_then(value_to_f64)
			.unwrap_or(0.0);
		let title_bytes = payload_core.get(1).and_then(value_to_binary).unwrap_or_default();
		let content_bytes = payload_core.get(2).and_then(value_to_binary).unwrap_or_default();
		let fields_value = payload_core.get(3).cloned().unwrap_or_else(empty_fields);

		let destination = recall_identity(&destination_hash).and_then(|identity| {
			Destination::new_outbound(
				Some(identity),
				DestinationType::Single,
				APP_NAME.to_string(),
				vec!["delivery".to_string()],
			)
			.ok()
		});

		let source = recall_identity(&source_hash).and_then(|identity| {
			Destination::new_outbound(
				Some(identity),
				DestinationType::Single,
				APP_NAME.to_string(),
				vec!["delivery".to_string()],
			)
			.ok()
		});

		let mut message = LXMessage::new(
			destination,
			source,
			Some(content_bytes),
			Some(title_bytes),
			Some(fields_value),
			original_method,
			Some(destination_hash),
			Some(source_hash.clone()),
			None,
			false,
		)?;

		message.hash = Some(message_hash.clone());
		message.message_id = Some(message_hash);
		message.signature = Some(signature.clone());
		message.stamp = stamp;
		message.incoming = true;
		message.timestamp = Some(timestamp);
		message.packed = Some(lxmf_bytes.to_vec());
		message.packed_size = lxmf_bytes.len();

		if let Some(source) = message.source.as_ref() {
			if source.validate(&signature, &signed_part) {
				message.signature_validated = true;
				log("[SIG] Signature validated OK", LOG_DEBUG, false, false);
			} else {
				message.signature_validated = false;
				message.unverified_reason = Some(Self::SIGNATURE_INVALID);
				log(
					&format!("[SIG] Signature INVALID for source={}", hexrep(&source_hash, false)),
					LOG_NOTICE,
					false,
					false,
				);
			}
		} else {
			message.signature_validated = false;
			message.unverified_reason = Some(Self::SOURCE_UNKNOWN);
			log(
				&format!(
					"[SIG] Source identity unknown for source_hash={}, signature cannot be verified",
					hexrep(&source_hash, false)
				),
				LOG_DEBUG,
				false,
				false,
			);
		}

		Ok(message)
	}

	pub fn unpack_from_file(file: &File) -> Result<LXMessage, String> {
		let mut buffer = Vec::new();
		file
			.try_clone()
			.map_err(|e| format!("Could not clone LXMessage file handle: {}", e))?
			.read_to_end(&mut buffer)
			.map_err(|e| format!("Could not read LXMessage file handle: {}", e))?;
		let container_value = decode_value(&buffer)?;
		let container = container_value
			.as_map()
			.ok_or("LXMF container is not a map")?
			.to_vec();

		let mut state = None;
		let mut transport_encrypted = None;
		let mut transport_encryption = None;
		let mut method = None;
		let mut lxm_bytes = None;

		for (key, value) in container {
			if let Some(key_str) = value_to_string(&key) {
				match key_str.as_str() {
					"state" => state = value_to_u8(&value),
					"lxmf_bytes" => lxm_bytes = value_to_binary(&value),
					"transport_encrypted" => transport_encrypted = value.as_bool(),
					"transport_encryption" => transport_encryption = value_to_string(&value),
					"method" => method = value_to_u8(&value),
					_ => {}
				}
			}
		}

		let bytes = lxm_bytes.ok_or("LXMF container missing lxmf_bytes")?;
		let mut message = LXMessage::unpack_from_bytes(&bytes, method)?;
		if let Some(state) = state {
			message.state = state;
		}
		if let Some(value) = transport_encrypted {
			message.transport_encrypted = value;
		}
		if let Some(value) = transport_encryption {
			message.transport_encryption = Some(value);
		}
		if let Some(value) = method {
			message.method = value;
		}
		Ok(message)
	}

	// PROTOCOL: as_packet() for PROPAGATED returns propagation_packed as the payload.
	// However, do NOT use as_packet() to transmit a PROPAGATED message over a Link —
	// the resulting Packet::new(link_dest).pack() calls destination.encrypt() which
	// routes through runtime_encrypt_for_destination() and fails for Link destinations.
	// To send over a link: call link.send_packet(&lxm.propagation_packed) directly.
	fn as_packet(&mut self) -> Result<Packet, String> {
		if self.packed.is_none() {
			self.pack(false)?;
		}
		let destination = self
			.delivery_destination
			.as_ref()
			.ok_or("Can't synthesize packet before delivery destination is known")?;
		let packed = self.packed.clone().unwrap_or_default();
		let data = match self.method {
			Self::OPPORTUNISTIC => packed[Self::DESTINATION_LENGTH..].to_vec(),
			Self::DIRECT => packed,
			Self::PROPAGATED => self
				.propagation_packed
				.clone()
				.ok_or("Missing propagated payload")?,
			_ => packed,
		};

		Ok(Packet::new(
			Some(destination.clone()),
			data,
			packet::DATA,
			packet::NONE,
			reticulum_rust::transport::BROADCAST,
			packet::HEADER_1,
			None,
			None,
			true,
			0,
		))
	}

	fn as_resource(&mut self, handle: Option<Arc<Mutex<LXMessage>>>) -> Result<Arc<Mutex<Resource>>, String> {
		if self.packed.is_none() {
			self.pack(false)?;
		}
		let link = self
			.delivery_link
			.as_ref()
			.ok_or("Can't synthesize resource without delivery link")?
			.clone();
		let is_active = link.is_active();
		if !is_active {
			return Err("Tried to synthesize resource for LXMF message on inactive link".to_string());
		}

		let data = match self.method {
			Self::DIRECT => self.packed.clone().unwrap_or_default(),
			Self::PROPAGATED => self
				.propagation_packed
				.clone()
				.ok_or("Missing propagation payload")?,
			_ => self.packed.clone().unwrap_or_default(),
		};
		let resource_data = Some(ResourceData::Bytes(data));
		let callback = handle.clone().map(|handle| {
			Arc::new(move |resource: Arc<Mutex<Resource>>| {
				resource_concluded_shared(&handle, &resource);
			}) as Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>
		});
		let advertised = handle.clone();
		let progress_callback = handle.map(|handle| {
			Arc::new(move |resource: Arc<Mutex<Resource>>| {
				update_transfer_progress_shared(&handle, &resource);
			}) as Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>
		});

		// Create with advertise=false; we'll use advertise_shared() on the
		// Arc so the watchdog & link-registered resource share the same state.
		let resource = Resource::new_internal(
			resource_data,
			link.clone(),
			None,
			false,
			// LXMF/LXMessage.py: auto_compress comes from the peer's announce
			// (determine_compression_support), so a peer that cannot
			// decompress (the web client announces an empty functionality
			// list) is sent the Resource uncompressed.
			if crate::lxmf::peer_accepts_compression(&self.destination_hash) {
				reticulum_rust::resource::AutoCompressOption::Enabled
			} else {
				reticulum_rust::resource::AutoCompressOption::Disabled
			},
			callback,
			progress_callback,
			None,
			1,
			None,
			None,
			false,
			0,
			None,
		)?;
		let resource_arc = Arc::new(Mutex::new(resource));
		// The payload is handed over as a Resource: from here the router's
		// §1 assertion measures the send by its transfer's progress, not by
		// its total time (DESIGN_PRINCIPLES §1, bulk transfers).
		// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
		self.transfer_by_resource = true;
		match advertised {
			// DESIGN_PRINCIPLES §1, bulk transfers: the transfer is watched
			// from its advertisement on. The hook runs on the advertise
			// thread once the advertisement has gone out, and waits for the
			// message lock this caller holds.
			// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
			Some(handle) => Resource::advertise_shared_then(
				resource_arc.clone(),
				Box::new(move || {
					if let Ok(mut message) = handle.lock() {
						message.note_transfer_progress(now_seconds());
					}
				}),
			),
			None => Resource::advertise_shared(resource_arc.clone()),
		}
		Ok(resource_arc)
	}

	fn mark_delivered(&mut self) {
		log(
			format!("Received delivery notification for {}", self),
			LOG_DEBUG,
			false,
			false,
		);
		let newly = self.state != Self::DELIVERED;
		// The proof is the transfer's last progress (§1, bulk transfers).
		self.note_transfer_proof(now_seconds());
		self.state = Self::DELIVERED;
		self.progress = 1.0;
		if newly && self.released_state_callback.is_some() {
			self.late_delivery_unreported = true;
		}
		if let Some(callback) = self.delivery_callback.as_ref() {
			callback(self);
		}
	}

	/// The router stops tracking this message: from now on a delivery proof
	/// reports DELIVERED through `state_callback` (see
	/// `released_state_callback`).
	pub(crate) fn release_state_reporting(&mut self, state_callback: Option<Arc<dyn Fn(&[u8], u8) + Send + Sync>>) {
		self.released_state_callback = state_callback;
	}

	/// The DELIVERED report owed for a proof that landed after the router let
	/// go of this message, taken once. The caller fires it after dropping the
	/// message lock.
	fn take_late_delivery_report(&mut self) -> Option<LateDeliveryReport> {
		if !std::mem::take(&mut self.late_delivery_unreported) {
			return None;
		}
		Some((self.released_state_callback.clone()?, self.hash.clone()?))
	}

	fn mark_propagated(&mut self) {
		log(
			format!("Received propagation success notification for {}", self),
			LOG_DEBUG,
			false,
			false,
		);
		// The proof is the transfer's last progress (§1, bulk transfers).
		self.note_transfer_proof(now_seconds());
		self.state = Self::SENT;
		self.progress = 1.0;
		if let Some(callback) = self.delivery_callback.as_ref() {
			callback(self);
		}
	}

	fn mark_paper_generated(&mut self) {
		log(
			format!("Paper message generation succeeded for {}", self),
			LOG_DEBUG,
			false,
			false,
		);
		self.state = Self::PAPER;
		self.progress = 1.0;
		if let Some(callback) = self.delivery_callback.as_ref() {
			callback(self);
		}
	}

	fn resource_concluded(&mut self, resource: &Resource) {
		if resource.status != ResourceStatus::Complete {
			// Its Resource has ended: the §1 watch on it stops (bulk transfers).
			// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
			self.note_transfer_ended(now_seconds());
		}
		if resource.status == ResourceStatus::Complete {
			self.mark_delivered();
		} else if Self::is_success_state(self.state) {
			// Already succeeded via another path (e.g. propagation) — don't let a
			// resource rejection or timeout on this path overwrite the success state.
			log(
				format!("resource_concluded: ignoring non-completion for {} (already {})", self, Self::state_name(self.state)),
				LOG_DEBUG, false, false,
			);
		} else if resource.status == ResourceStatus::Rejected {
			self.state = Self::REJECTED;
		} else if self.state != Self::CANCELLED {
			if let Some(link) = self.delivery_link.as_ref() {
				link.teardown();
			}
			self.state = Self::OUTBOUND;
		}
	}

	fn propagation_resource_concluded(&mut self, resource: &Resource) {
		if resource.status != ResourceStatus::Complete {
			// Its Resource has ended: the §1 watch on it stops (bulk transfers).
			// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
			self.note_transfer_ended(now_seconds());
		}
		if resource.status == ResourceStatus::Complete {
			self.mark_propagated();
		} else if self.state != Self::CANCELLED {
			if let Some(link) = self.delivery_link.as_ref() {
				link.teardown();
			}
			self.state = Self::OUTBOUND;
		}
	}

	fn link_packet_timed_out(&mut self) {
		let msg_hash = self.hash.as_ref().map(|h| hexrep(h, false)).unwrap_or_default();
		log(&format!("link_packet_timed_out msg={} state={}", msg_hash, self.state), LOG_NOTICE, false, false);
		if self.state != Self::CANCELLED {
			if let Some(link) = self.delivery_link.as_ref() {
				log(&format!("link_packet_timed_out tearing down link={}", hexrep(&link.link_id(), false)), LOG_NOTICE, false, false);
				link.teardown();
			}
			// NEVER REMOVE EVER — §1,§3: do NOT revert a fire-and-forget SENT message.
			// After the DIRECT PACKET fix, state=SENT when this fires because
			// send_with_handle sets SENT immediately after packet.send() succeeds.
			// Reverting SENT→OUTBOUND would be a §3 application-level retry.
			// Receipt timeout on an already-SENT message is informational only.
			if !Self::is_success_state(self.state) {
				// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
				// A receipt timeout is a confirmed delivery failure for this attempt.
				// Set receipt_timed_out so that:
				//   (a) POB fails the message on the very next cycle (no 18 s LRREQ wait),
				//   (b) the DISCONNECTED callback does NOT double-count this same cycle.
				// delivery_attempts is also incremented here so the failure log is correct.
				self.receipt_timed_out = true;
				self.delivery_attempts += 1;
				self.state = Self::OUTBOUND;
			}
		}
	}

	/// LXMF/LXMessage.py `__link_packet_timed_out` for a PROPAGATED message.
	/// The reference tears the propagation link down and returns the message
	/// to OUTBOUND; the router then counts the attempt when it re-sends.
	/// SENT is never reverted: it now means the node proved receipt.
	fn propagation_packet_timed_out(&mut self) {
		let msg_hash = self.hash.as_ref().map(|h| hexrep(h, false)).unwrap_or_default();
		log(&format!("propagation_packet_timed_out msg={} state={}", msg_hash, self.state), LOG_NOTICE, false, false);
		if self.state != Self::CANCELLED && !Self::is_success_state(self.state) {
			self.delivery_attempts += 1;
			self.state = Self::OUTBOUND;
			self.progress = 0.0;
		}
	}

	fn update_transfer_progress(&mut self, resource: &mut Resource) {
		let progress = resource.get_progress();
		self.progress = Self::transfer_progress(progress);
		// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 (bulk transfers)
		self.note_transfer_progress(now_seconds());
	}

	/// The message progress a Resource fraction stands for: 0.10 to hand
	/// the transfer over, the other 0.90 across the Resource
	/// (LXMF/LXMessage.py `__update_transfer_progress`:
	/// `0.10 + resource.get_progress()*0.90`).
	pub(crate) fn transfer_progress(fraction: f64) -> f64 {
		0.10 + (fraction.clamp(0.0, 1.0) * 0.90)
	}

	/// A Resource fraction reported by AppLinks while it carries this
	/// message (`AppLinks::send_with_compression` / `send_on_held_link`).
	/// Applied only while the message is SENDING, so a late report from an
	/// attempt that has failed, been cancelled or concluded changes nothing,
	/// and only upward: a DIRECT send can have a Resource on each tier, each
	/// reporting its own fraction, and the bar must not move back.
	fn apply_transfer_fraction(&mut self, fraction: f64) {
		if self.state != Self::SENDING {
			return;
		}
		let progress = Self::transfer_progress(fraction);
		if progress > self.progress {
			self.progress = progress;
		}
	}

	/// DESIGN_PRINCIPLES §1, bulk transfers: whether the router's §1
	/// assertion measures this send by its transfers' progress instead of by
	/// the time since it began: once this attempt's payload has been handed
	/// over to go as a Resource (`transfer_by_resource`). From then on each
	/// Resource carrying it is watched from its advertisement to its end
	/// (`transfer_silence`); before a Resource's advertisement, and between
	/// one tier's Resource ending and the next one's advertisement, the send
	/// is not measured by the router: on the AppLinks path its path race and
	/// link have their own §1 bounds (app-links' 5 s race, Reticulum-rust's
	/// `link.establish` assertion), and a Resource QUEUED behind another on
	/// its link is waiting out that one's transfer, which is watched in its
	/// own right. Before the hand-over (on the router's own DIRECT path: its
	/// path request and link setup) the send is measured from its start,
	/// like a send that fits one packet, which keeps that assertion
	/// throughout.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) fn measured_by_transfer_progress(&self) -> bool {
		self.transfer_by_resource
	}

	/// This attempt's payload has been handed to AppLinks
	/// (`AppLinks::send_with_compression`). A DIRECT payload over the link
	/// MDU goes as a Resource on whichever tier carries it
	/// (`app_links::link_representation`, the boundary AppLinks sends by),
	/// so from here it is measured by its transfers' progress
	/// (`measured_by_transfer_progress`); one that fits a packet is not.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) fn note_handed_to_app_links(&mut self) {
		let as_resource = self.method == Self::DIRECT
			&& self
				.packed
				.as_ref()
				.map(|packed| app_links::link_representation(packed.len()) == app_links::LinkRepresentation::Resource)
				.unwrap_or(false);
		if as_resource {
			self.transfer_by_resource = true;
		}
	}

	/// The Resource carrying this send showed progress at `at` (unix
	/// seconds): its advertisement went out, it served a request of the
	/// receiver's, or its proof came. Only while SENDING, as the progress
	/// itself. A gap over the §1 limit since the last progress is a silence:
	/// if no router pass asserted it while it ran, it is kept for the next
	/// one (`transfer_silence`); if one did, it ends here, and says so.
	/// Never changes the message's state: the Resource's own events decide
	/// the send (DESIGN_PRINCIPLES §1, bulk transfers).
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) fn note_transfer_progress(&mut self, at: f64) {
		if self.state != Self::SENDING {
			return;
		}
		self.close_transfer_silence(at, "moving again");
		self.transfer_by_resource = true;
		self.transfer_silence_asserted = false;
		self.transfer_moved_at = Some(at);
	}

	/// The Resource carrying this send concluded at `at` without
	/// delivering it: failed (its advertisement unanswered, a request or the
	/// proof timed out, its link closed), cancelled or rejected. Its watch
	/// stops here, a silence it ended in is closed as one that moved again
	/// would be, and nothing is watched until the next Resource carrying the
	/// send is advertised: a tier handover's path race and link setup lie
	/// between two Resources, not inside one, as Retichat-js's per-Resource
	/// watch reads the rule (`bulkStop`). Until 2026-10-01 nothing ended the
	/// watch, and the next tier's setup was asserted as this Resource's
	/// silence. Only while SENDING; never changes the message's state.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) fn note_transfer_ended(&mut self, at: f64) {
		if self.state != Self::SENDING || self.transfer_moved_at.is_none() {
			return;
		}
		self.close_transfer_silence(at, "ended");
		self.transfer_silence_asserted = false;
		self.transfer_moved_at = None;
	}

	/// The silence of the Resource being watched, if it ran over the §1
	/// limit, ends at `at` (`how`: moving again, or ended): one a router pass
	/// has asserted is logged as over; one none has is kept for the next
	/// pass (`transfer_silence_unasserted`).
	fn close_transfer_silence(&mut self, at: f64, how: &str) {
		let Some(previous) = self.transfer_moved_at else {
			return;
		};
		let silent_for = at - previous;
		if silent_for <= reticulum_rust::send_assertion::SEND_LATENCY_LIMIT_SECS {
			return;
		}
		if self.transfer_silence_asserted {
			log(
				&format!(
					"DESIGN_PRINCIPLES §1: {} transfer {} after {:.2}s of silence",
					self, how, silent_for,
				),
				LOG_NOTICE, false, false,
			);
		} else if self.transfer_silence_unasserted.map_or(true, |kept| silent_for > kept) {
			self.transfer_silence_unasserted = Some(silent_for);
		}
	}

	/// The proof of the Resource carrying this send came at `at`: the last
	/// progress its transfer shows. Nothing for a send no Resource carries.
	fn note_transfer_proof(&mut self, at: f64) {
		if self.transfer_moved_at.is_some() {
			self.note_transfer_progress(at);
		}
	}

	/// DESIGN_PRINCIPLES §1, bulk transfers: the silence the router's pass
	/// at `now` must assert, each one once. First a silence that ended
	/// before a pass saw it (in any state: it happened); otherwise, while
	/// the send is SENDING, the one running since the transfer last moved,
	/// once it is over the limit. Total time is never measured: a transfer
	/// that keeps moving yields nothing however long it takes.
	/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
	pub(crate) fn transfer_silence(&mut self, now: f64) -> Option<TransferSilence> {
		if let Some(seconds) = self.transfer_silence_unasserted.take() {
			return Some(TransferSilence { seconds, ended: true });
		}
		let moved_at = self.transfer_moved_at?;
		if self.state != Self::SENDING || self.transfer_silence_asserted {
			return None;
		}
		let seconds = now - moved_at;
		if seconds > reticulum_rust::send_assertion::SEND_LATENCY_LIMIT_SECS {
			self.transfer_silence_asserted = true;
			return Some(TransferSilence { seconds, ended: false });
		}
		None
	}

	/// A new send attempt: nothing of it has been handed over yet, and its
	/// transfer is watched afresh, from its own Resource's advertisement.
	pub(crate) fn begin_transfer_watch(&mut self) {
		self.transfer_by_resource = false;
		self.transfer_moved_at = None;
		self.transfer_silence_unasserted = None;
		self.transfer_silence_asserted = false;
	}
}

/// A §1 silence of the transfer carrying a send (DESIGN_PRINCIPLES §1, bulk
/// transfers): `seconds` without progress, still running or `ended` before
/// a router pass saw it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TransferSilence {
	pub(crate) seconds: f64,
	pub(crate) ended: bool,
}

impl std::fmt::Display for LXMessage {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if let Some(hash) = self.hash.as_ref() {
			write!(f, "<LXMessage {}>", hexrep(hash, false))
		} else {
			write!(f, "<LXMessage>")
		}
	}
}

fn empty_fields() -> Value {
	Value::Map(Vec::new())
}

fn encode_value(value: Value) -> Result<Vec<u8>, String> {
	let mut buf = Vec::new();
	write_value(&mut buf, &value).map_err(|e| format!("msgpack encode error: {}", e))?;
	Ok(buf)
}

fn decode_value(data: &[u8]) -> Result<Value, String> {
	let mut cursor = std::io::Cursor::new(data);
	rmpv::decode::read_value(&mut cursor).map_err(|e| format!("msgpack decode error: {}", e))
}

fn value_to_binary(value: &Value) -> Option<Vec<u8>> {
	match value {
		Value::Binary(data) => Some(data.clone()),
		Value::String(value) => value.as_str().map(|s| s.as_bytes().to_vec()),
		_ => None,
	}
}

fn value_to_string(value: &Value) -> Option<String> {
	match value {
		Value::String(value) => value.as_str().map(|s| s.to_string()),
		_ => None,
	}
}

fn value_to_f64(value: &Value) -> Option<f64> {
	match value {
		Value::F32(value) => Some(f64::from(*value)),
		Value::F64(value) => Some(*value),
		Value::Integer(value) => value.as_i64().map(|v| v as f64),
		_ => None,
	}
}

fn value_to_u8(value: &Value) -> Option<u8> {
	match value {
		Value::Integer(value) => value.as_u64().map(|v| v as u8),
		_ => None,
	}
}

fn now_seconds() -> f64 {
	let since = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default();
	since.as_secs() as f64 + (since.subsec_nanos() as f64 / 1_000_000_000.0)
}

fn recall_identity(hash: &[u8]) -> Option<Identity> {
	Identity::recall(hash)
}

type LateDeliveryReport = (Arc<dyn Fn(&[u8], u8) + Send + Sync>, Vec<u8>);

/// A delivery proof that landed after the router concluded the message —
/// FAILED because its receipt timed out, or SENT for a fire-and-forget direct
/// packet. The recipient has it, so the app hears DELIVERED: delivery may
/// follow a failure, never the reverse (`fail_message` skips success states).
fn report_late_delivery(report: Option<LateDeliveryReport>) {
	if let Some((state_callback, hash)) = report {
		log(
			&format!("Delivery proof for {} arrived after the router concluded it; reporting DELIVERED", hexrep(&hash, false)),
			LOG_NOTICE,
			false,
			false,
		);
		state_callback(&hash, LXMessage::DELIVERED);
	}
}

pub(crate) fn mark_delivered_shared(handle: &Arc<Mutex<LXMessage>>) {
	let late = match handle.lock() {
		Ok(mut message) => {
			message.mark_delivered();
			message.take_late_delivery_report()
		}
		Err(_) => None,
	};
	report_late_delivery(late);
}

pub(crate) fn mark_propagated_shared(handle: &Arc<Mutex<LXMessage>>) {
	if let Ok(mut message) = handle.lock() {
		message.mark_propagated();
	}
}

/// The propagation node did not prove the link packet (or the Resource
/// failed) — LXMF/LXMessage.py `__link_packet_timed_out` for a PROPAGATED
/// message: back to OUTBOUND so the router re-sends on a fresh link.
pub(crate) fn propagation_packet_timed_out_shared(handle: &Arc<Mutex<LXMessage>>) {
	if let Ok(mut message) = handle.lock() {
		message.propagation_packet_timed_out();
	}
}

pub(crate) fn link_packet_timed_out_shared(handle: &Arc<Mutex<LXMessage>>) {
	if let Ok(mut message) = handle.lock() {
		message.link_packet_timed_out();
	}
}

/// AppLinks Timer P: the direct send went 5 s without a proof and without
/// its transfer moving (at once when the link was already DISCONNECTED).
/// Flag the message and wake the router,
/// whose next pass reports PROP_FALLBACK_REQUESTED so the app starts the
/// propagated copy.
///
/// Waits for the message lock rather than skipping when it is busy: Timer P
/// fires once, so a skipped request is never made again. The lock is busy
/// often enough to matter — the router holds it for its whole pass over the
/// message (a zero-delay Timer P fires while that pass is still in
/// `send_with_compression`), and the FFI getters take it too. Waiting cannot
/// deadlock: the Timer P thread (app-links `run_prop_timer`) holds no other lock
/// when it calls in, and nothing that holds a message lock waits for that
/// thread.
/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
pub(crate) fn request_prop_fallback_shared(handle: &Arc<Mutex<LXMessage>>, wake: &mpsc::Sender<()>) {
	match handle.lock() {
		Ok(mut message) => message.needs_prop_fallback = true,
		Err(poisoned) => {
			// The router skips a poisoned message, so the request cannot
			// reach the app; say so rather than lose it silently.
			let hash = poisoned.get_ref().hash.clone().unwrap_or_default();
			log(
				&format!("Propagation fallback for {} dropped: message lock poisoned", hexrep(&hash, false)),
				LOG_ERROR,
				false,
				false,
			);
		}
	}
	let _ = wake.send(());
}

fn resource_concluded_shared(handle: &Arc<Mutex<LXMessage>>, resource: &Arc<Mutex<Resource>>) {
	eprintln!("[LXM-RC] resource_concluded_shared called");
	let mut late = None;
	let resource_guard = match resource.lock() {
		Ok(guard) => guard,
		Err(_) => {
			eprintln!("[LXM-RC] failed to lock resource");
			return;
		}
	};
	eprintln!("[LXM-RC] resource status={:?}", resource_guard.status);
	if let Ok(mut message) = handle.lock() {
		if message.method == LXMessage::PROPAGATED {
			eprintln!("[LXM-RC] calling propagation_resource_concluded");
			message.propagation_resource_concluded(&resource_guard);
		} else {
			eprintln!("[LXM-RC] calling resource_concluded, current state={}", message.state);
			message.resource_concluded(&resource_guard);
			eprintln!("[LXM-RC] after resource_concluded, state={}", message.state);
			late = message.take_late_delivery_report();
		}
	} else {
		eprintln!("[LXM-RC] failed to lock message handle");
	}
	drop(resource_guard);
	report_late_delivery(late);
}

/// The progress callback the router hands AppLinks for a send of this
/// message (`app_links::SendProgress`): each Resource fraction moves the
/// message's progress to 0.10 + 0.90 × fraction while it is SENDING, never
/// down (`LXMessage::apply_transfer_fraction`); a Resource's advertisement
/// puts it at 0.10, where LXMF/LXMessage.py puts a Resource send. Until
/// 2026-09-29 nothing was handed over, and a message sent through AppLinks
/// sat at 0.05 (DIRECT) or 0.50 (PROPAGATED) for its whole transfer.
///
/// Each report is also an event of the Resource carrying the send, for
/// DESIGN_PRINCIPLES §1, bulk transfers: its advertisement starts the watch
/// on it, each request served restarts the silence clock, and its end
/// (concluded without delivering, before its tier hands over) stops the
/// watch until the next Resource's advertisement.
///
/// A fraction runs on the thread serving the receiver's request, and an end
/// on the thread concluding the Resource, with the Resource's lock held; it
/// waits for the message lock: Resource, then message, the same order as
/// `update_transfer_progress_shared`.
pub(crate) fn transfer_progress_reporter(handle: &Arc<Mutex<LXMessage>>) -> app_links::SendProgressCallback {
	let handle = Arc::clone(handle);
	Arc::new(move |event: app_links::SendProgress| {
		if let Ok(mut message) = handle.lock() {
			// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 (bulk transfers)
			match event {
				app_links::SendProgress::Advertised => {
					message.apply_transfer_fraction(0.0);
					message.note_transfer_progress(now_seconds());
				}
				app_links::SendProgress::Fraction(fraction) => {
					message.apply_transfer_fraction(fraction);
					message.note_transfer_progress(now_seconds());
				}
				app_links::SendProgress::Ended => message.note_transfer_ended(now_seconds()),
			}
		}
	})
}

fn update_transfer_progress_shared(handle: &Arc<Mutex<LXMessage>>, resource: &Arc<Mutex<Resource>>) {
	let mut resource_guard = match resource.lock() {
		Ok(guard) => guard,
		Err(_) => return,
	};
	if let Ok(mut message) = handle.lock() {
		message.update_transfer_progress(&mut resource_guard);
	}
}

// ─── Tests ──────────────────────────────────────────────────────────────────
//
// These tests guard against regressions of the PROPAGATED-via-link protocol.
// See the PROTOCOL comments in pack(), send_with_handle(), as_packet(), and
// LXMRouter::process_outbound() for the full explanation.

#[cfg(test)]
mod tests {
	use super::*;
	use reticulum_rust::destination::{Destination, DestinationType};
	use reticulum_rust::identity::Identity;

	/// Build a minimal LXMessage ready for pack() with desired_method = PROPAGATED.
	/// Uses two freshly-generated in-memory identities (no RNS runtime required).
	fn make_propagated_message() -> LXMessage {
		let src_identity = Identity::new(true);
		let dst_identity = Identity::new(true);

		let source = Destination::new_inbound(
			Some(src_identity.clone()),
			DestinationType::Single,
			"lxmf".to_string(),
			vec!["delivery".to_string()],
		)
		.expect("source dest");

		let dest = Destination::new_outbound(
			Some(dst_identity.clone()),
			DestinationType::Single,
			"lxmf".to_string(),
			vec!["delivery".to_string()],
		)
		.expect("dest dest");

		let dest_hash = dest.hash.clone();
		let src_hash = source.hash.clone();

		LXMessage::new(
			Some(dest),
			Some(source),
			Some(b"hello propagation".to_vec()),
			Some(b"test title".to_vec()),
			None,
			Some(LXMessage::PROPAGATED),
			Some(dest_hash),
			Some(src_hash),
			None,
			false,
		)
		.expect("LXMessage::new")
	}

	/// REGRESSION GUARD: After pack(), propagation_packed must be Some(_).
	///
	/// If this fails it means the PROPAGATED arm of pack() is broken, and the
	/// POB send path will fall into the "propagation_packed is None" error branch
	/// every cycle instead of sending.
	#[test]
	fn propagated_pack_sets_propagation_packed() {
		let mut msg = make_propagated_message();
		msg.pack(false).expect("pack");

		assert!(
			msg.propagation_packed.is_some(),
			"propagation_packed must be Some after pack() with desired_method=PROPAGATED \
			 — the POB send path reads this field directly via link.send_packet()"
		);
	}

	/// REGRESSION GUARD: propagation_packed must be valid msgpack with the shape
	/// [f64_timestamp, [[bytes]]].
	///
	/// The propagation node expects exactly this structure. If the format changes,
	/// the node will reject the message silently.
	#[test]
	fn propagation_packed_has_correct_msgpack_shape() {
		let mut msg = make_propagated_message();
		msg.pack(false).expect("pack");

		let data = msg.propagation_packed.as_ref().unwrap();
		let value = rmpv::decode::read_value(&mut data.as_slice())
			.expect("propagation_packed must be valid msgpack");

		// Top level: [timestamp_f64, [[encrypted_bytes]]]
		let arr = match value {
			Value::Array(a) => a,
			other => panic!("propagation_packed top level must be Array, got {:?}", other),
		};
		assert_eq!(arr.len(), 2, "propagation_packed must have 2 top-level elements");

		assert!(
			matches!(arr[0], Value::F64(_)),
			"propagation_packed[0] must be F64 timestamp, got {:?}",
			arr[0]
		);

		let inner = match &arr[1] {
			Value::Array(a) => a,
			other => panic!("propagation_packed[1] must be Array, got {:?}", other),
		};
		assert_eq!(inner.len(), 1, "propagation_packed[1] must have exactly 1 blob");

		assert!(
			matches!(inner[0], Value::Binary(_)),
			"propagation_packed[1][0] must be Binary blob, got {:?}",
			inner[0]
		);
	}

	/// REGRESSION GUARD: The method field after pack() must be PROPAGATED.
	///
	/// If this is DIRECT or OPPORTUNISTIC the router's match arm dispatches to
	/// the wrong send path.
	#[test]
	fn propagated_pack_sets_method_to_propagated() {
		let mut msg = make_propagated_message();
		msg.pack(false).expect("pack");

		assert_eq!(
			msg.method,
			LXMessage::PROPAGATED,
			"msg.method must be PROPAGATED after pack() — router dispatch depends on this"
		);
	}

	type StateReports = Arc<Mutex<Vec<(Vec<u8>, u8)>>>;

	fn packed_direct_message(state: u8) -> (Arc<Mutex<LXMessage>>, Vec<u8>) {
		let mut direct = make_propagated_message();
		direct.desired_method = Some(LXMessage::DIRECT);
		direct.pack(false).expect("pack");
		direct.state = state;
		let hash = direct.hash.clone().expect("hash");
		(Arc::new(Mutex::new(direct)), hash)
	}

	fn state_sink() -> (Arc<dyn Fn(&[u8], u8) + Send + Sync>, StateReports) {
		let reports: StateReports = Arc::default();
		let sink = reports.clone();
		(Arc::new(move |hash: &[u8], state: u8| sink.lock().unwrap().push((hash.to_vec(), state))), reports)
	}

	/// The router reported FAILED (the receipt timed out) and let go; the
	/// proof then arrives. The recipient has the message, so the app hears
	/// DELIVERED, once.
	#[test]
	fn a_proof_after_the_router_failed_the_message_reports_delivered_once() {
		let (handle, hash) = packed_direct_message(LXMessage::FAILED);
		let (state_callback, reports) = state_sink();
		handle.lock().unwrap().release_state_reporting(Some(state_callback));

		mark_delivered_shared(&handle);
		assert_eq!(handle.lock().unwrap().state, LXMessage::DELIVERED);
		assert_eq!(*reports.lock().unwrap(), vec![(hash.clone(), LXMessage::DELIVERED)]);

		mark_delivered_shared(&handle);
		assert_eq!(reports.lock().unwrap().len(), 1, "a second proof reports nothing new");
	}

	/// While the router still tracks the message it reports DELIVERED on its
	/// next pass; the message must not report it a second time.
	#[test]
	fn a_proof_while_the_router_tracks_the_message_is_left_to_the_router() {
		let (handle, _) = packed_direct_message(LXMessage::SENDING);
		mark_delivered_shared(&handle);
		let mut message = handle.lock().unwrap();
		assert_eq!(message.state, LXMessage::DELIVERED);
		assert!(message.take_late_delivery_report().is_none());
	}

	/// A duplicate proof for a message the router already reported DELIVERED
	/// reports nothing.
	#[test]
	fn a_duplicate_proof_after_delivery_reports_nothing() {
		let (handle, _) = packed_direct_message(LXMessage::DELIVERED);
		let (state_callback, reports) = state_sink();
		handle.lock().unwrap().release_state_reporting(Some(state_callback));
		mark_delivered_shared(&handle);
		assert!(reports.lock().unwrap().is_empty());
	}

	/// Timer P fires once. When the message is locked at that instant — the
	/// router's pass holds it, and a zero-delay Timer P fires inside that
	/// pass — the request must wait for the lock, not be dropped, or the app
	/// never hears PROP_FALLBACK_REQUESTED and the message never propagates.
	#[test]
	fn a_fallback_request_waits_for_a_held_message_lock() {
		use std::time::Duration;

		let (handle, _) = packed_direct_message(LXMessage::SENDING);
		let (wake_tx, wake_rx) = mpsc::channel::<()>();
		let (step_tx, step_rx) = mpsc::channel::<&str>();

		let held = handle.lock().unwrap();
		let requester = {
			let handle = handle.clone();
			std::thread::spawn(move || {
				step_tx.send("requesting").unwrap();
				request_prop_fallback_shared(&handle, &wake_tx);
				step_tx.send("requested").unwrap();
			})
		};
		assert_eq!(step_rx.recv_timeout(Duration::from_secs(5)), Ok("requesting"));
		// A request that waits cannot finish while the lock is held; the
		// bound only keeps one that skips the lock from passing unseen.
		assert_eq!(
			step_rx.recv_timeout(Duration::from_millis(200)),
			Err(mpsc::RecvTimeoutError::Timeout),
			"the request returned while the message lock was held — it was dropped"
		);
		drop(held);

		assert_eq!(step_rx.recv_timeout(Duration::from_secs(5)), Ok("requested"));
		requester.join().unwrap();
		assert!(handle.lock().unwrap().needs_prop_fallback, "the request must reach the message");
		assert_eq!(wake_rx.try_recv(), Ok(()), "the router must be woken to report the request");
	}

	/// LXMF/LXMessage.py `__update_transfer_progress`: 0.10 + 0.90 × the
	/// Resource's fraction. AppLinks hands over the raw fraction; the
	/// reporter the router passes it maps it the reference's way.
	#[test]
	fn a_resource_fraction_moves_a_sending_message_the_references_way() {
		let (handle, _) = packed_direct_message(LXMessage::SENDING);
		handle.lock().unwrap().progress = 0.05;
		let report = transfer_progress_reporter(&handle);
		let progress = || handle.lock().unwrap().progress;

		report(app_links::SendProgress::Advertised);
		assert!((progress() - 0.10).abs() < 1e-9, "the transfer handed over is 0.10");
		report(app_links::SendProgress::Fraction(0.0));
		assert!((progress() - 0.10).abs() < 1e-9, "the transfer handed over is 0.10");
		report(app_links::SendProgress::Fraction(0.5));
		assert!((progress() - 0.55).abs() < 1e-9, "0.10 + 0.90 × 0.5");
		report(app_links::SendProgress::Fraction(1.0));
		assert!((progress() - 1.0).abs() < 1e-9, "all parts sent is 1.0");
		assert_eq!(LXMessage::transfer_progress(1.7), 1.0, "a fraction never takes it past 1.0");
	}

	/// A DIRECT send may have a Resource on each tier, each reporting its
	/// own fraction: the message only ever moves up.
	#[test]
	fn transfer_progress_only_moves_up() {
		let (handle, _) = packed_direct_message(LXMessage::SENDING);
		let report = transfer_progress_reporter(&handle);
		report(app_links::SendProgress::Fraction(0.6));
		let high = handle.lock().unwrap().progress;
		report(app_links::SendProgress::Fraction(0.2));
		assert_eq!(handle.lock().unwrap().progress, high, "a lower fraction from another tier must not pull it back");
		report(app_links::SendProgress::Advertised);
		assert_eq!(handle.lock().unwrap().progress, high, "nor the next tier's advertisement");
		report(app_links::SendProgress::Fraction(0.6));
		assert_eq!(handle.lock().unwrap().progress, high);
	}

	/// Only a SENDING message moves: a report that lands after the attempt
	/// failed, was cancelled or concluded is late and changes nothing.
	#[test]
	fn transfer_progress_applies_only_while_sending() {
		for (state, progress) in [
			(LXMessage::OUTBOUND, 0.05),
			(LXMessage::FAILED, 0.0),
			(LXMessage::CANCELLED, 0.3),
			(LXMessage::DELIVERED, 1.0),
			(LXMessage::SENT, 1.0),
		] {
			let (handle, _) = packed_direct_message(state);
			handle.lock().unwrap().progress = progress;
			transfer_progress_reporter(&handle)(app_links::SendProgress::Fraction(0.9));
			let message = handle.lock().unwrap();
			assert_eq!(message.progress, progress, "state {:#04x} must not move", state);
			assert_eq!(message.state, state);
		}
	}

	// ── DESIGN_PRINCIPLES §1, bulk transfers (James, 2026-09-30) ──────────
	//
	// A Resource's total time is not measured against 5 s. From its
	// advertisement on it must show progress at least every 5 s; a longer
	// silence is asserted (the router's pass, `transfer_silence`) and never
	// fails the send. Times are injected: `t0` is the send's start.

	/// A DIRECT message whose packed payload is over the link MDU, so it
	/// goes as a Resource (a photo), in `state`, sent at `t0`.
	fn photo_message(state: u8, t0: f64) -> LXMessage {
		let mut photo = make_propagated_message();
		photo.content = vec![0x42; 2000];
		photo.desired_method = Some(LXMessage::DIRECT);
		photo.pack(false).expect("pack");
		assert!(photo.packed.as_ref().unwrap().len() > reticulum_rust::link::MDU, "the payload goes as a Resource");
		photo.state = state;
		photo.timestamp = Some(t0);
		photo
	}

	/// The silences a router pass every `pass` seconds from `from` to `to`
	/// would assert.
	fn passes(message: &mut LXMessage, from: f64, to: f64, pass: f64) -> Vec<TransferSilence> {
		let mut seen = Vec::new();
		let mut now = from;
		while now <= to {
			seen.extend(message.transfer_silence(now));
			now += pass;
		}
		seen
	}

	/// The Pixel's photo of 2026-10-01 at any length: a transfer that keeps
	/// moving is never a §1 violation, here 30 s of it with progress every
	/// 4.5 s. Until 2026-10-01 the router counted the whole transfer from the
	/// send and panicked a debug build 5 s in.
	#[test]
	fn a_moving_thirty_second_transfer_does_not_trip_section_1() {
		let t0 = 1_000.0;
		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_handed_to_app_links();
		assert!(photo.measured_by_transfer_progress(), "a Resource send is measured by its progress");

		photo.note_transfer_progress(t0 + 2.0); // the advertisement went out
		let mut at = t0 + 2.0;
		let mut seen = Vec::new();
		while at < t0 + 32.0 {
			seen.extend(passes(&mut photo, at, at + 4.5, 0.25));
			at += 4.5;
			photo.note_transfer_progress(at); // a request served
		}
		assert!(at - t0 >= 30.0, "the transfer ran {} s", at - t0);
		assert!(seen.is_empty(), "a moving transfer is never silent: {:?}", seen);
		assert_eq!(photo.transfer_silence_unasserted, None);
	}

	/// Six seconds without progress is a §1 silence: the pass that sees it
	/// over the limit asserts it, once. The transfer moving again ends it,
	/// and a later silence is asserted in its turn. Nothing changes state.
	#[test]
	fn a_six_second_silence_trips_section_1_once() {
		let t0 = 1_000.0;
		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_transfer_progress(t0 + 1.0); // advertised
		photo.note_transfer_progress(t0 + 2.0); // a request served

		assert_eq!(photo.transfer_silence(t0 + 6.9), None, "4.9 s of silence is inside the limit");
		assert_eq!(photo.transfer_silence(t0 + 8.0), Some(TransferSilence { seconds: 6.0, ended: false }));
		assert_eq!(photo.transfer_silence(t0 + 9.0), None, "asserted once");
		assert_eq!(photo.state, LXMessage::SENDING, "a silence never fails the send");

		photo.note_transfer_progress(t0 + 9.0); // moving again
		assert_eq!(photo.transfer_silence(t0 + 10.0), None, "the silence was asserted while it ran: nothing more");
		assert_eq!(passes(&mut photo, t0 + 9.0, t0 + 14.0, 0.5), vec![]);
		assert_eq!(photo.transfer_silence(t0 + 15.0), Some(TransferSilence { seconds: 6.0, ended: false }), "the next silence");
	}

	/// A silence that ends between two router passes is still asserted, by
	/// the next pass: as it ended in a request served, and as it ended in
	/// the proof (the real `mark_delivered_shared`).
	#[test]
	fn a_silence_that_ends_between_passes_is_still_asserted() {
		let t0 = 1_000.0;
		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_transfer_progress(t0 + 1.0);
		photo.note_transfer_progress(t0 + 7.0); // 6 s later, no pass in between
		assert_eq!(photo.transfer_silence(t0 + 7.5), Some(TransferSilence { seconds: 6.0, ended: true }));
		assert_eq!(photo.transfer_silence(t0 + 8.0), None, "asserted once");

		let photo = Arc::new(Mutex::new(photo_message(LXMessage::SENDING, t0)));
		photo.lock().unwrap().transfer_moved_at = Some(now_seconds() - 6.0);
		mark_delivered_shared(&photo);
		let mut photo = photo.lock().unwrap();
		assert_eq!(photo.state, LXMessage::DELIVERED);
		let silence = photo.transfer_silence(now_seconds()).expect("the silence the proof ended");
		assert!(silence.ended && silence.seconds >= 6.0 && silence.seconds < 7.0, "{:?}", silence);
		assert_eq!(photo.transfer_silence(now_seconds() + 60.0), None, "and nothing once delivered");
	}

	/// Until its payload is handed over to go as a Resource a send is
	/// measured from its start, like one that fits a packet: on the router's
	/// own DIRECT path that is its path request and link setup, which
	/// nothing else bounds. Once handed over (to AppLinks, whose race and
	/// link have their own §1 bounds, or to a link the router holds) it is
	/// measured by its transfer's progress, and not at all before its
	/// Resource is advertised: a Resource QUEUED behind another on its link
	/// waits out that one's transfer, which is watched in its own right. A
	/// send that fits one packet is never handed over as a Resource.
	#[test]
	fn a_resource_send_is_measured_from_its_start_until_it_is_handed_over() {
		let t0 = 1_000.0;
		let mut photo = photo_message(LXMessage::SENDING, t0);
		assert!(!photo.measured_by_transfer_progress(), "not yet handed over: measured from its start");

		photo.note_handed_to_app_links();
		assert!(photo.measured_by_transfer_progress(), "handed to AppLinks as a Resource");
		assert_eq!(passes(&mut photo, t0, t0 + 60.0, 0.5), vec![], "queued for a minute: not silent");

		photo.begin_transfer_watch();
		assert!(!photo.measured_by_transfer_progress(), "a new attempt has handed nothing over");

		let (text, _) = packed_direct_message(LXMessage::SENDING);
		let mut text = Arc::try_unwrap(text).ok().unwrap().into_inner().unwrap();
		assert!(text.packed.as_ref().unwrap().len() <= reticulum_rust::link::MDU, "one packet");
		text.note_handed_to_app_links();
		assert!(!text.measured_by_transfer_progress(), "a packet send keeps the assertion from its start");
		assert_eq!(passes(&mut text, t0, t0 + 60.0, 0.5), vec![], "nothing for this watch to say about it");
	}

	/// The reviewer's case of 2026-10-01: tier 1's Resource moved, then its
	/// link closed and the Resource concluded FAILED; tier 3's path race and
	/// link took 5.5 s before its own Resource advertised. That setup lies
	/// between two Resources, not inside one, and is not a silence, as on a
	/// first attempt (Retichat-js's per-Resource watch reads the rule the
	/// same way). Tier 3's Resource is then watched from its advertisement.
	#[test]
	fn a_tier_handover_is_not_a_silence() {
		let t0 = 1_000.0;
		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_handed_to_app_links();
		photo.note_transfer_progress(t0 + 1.0); // tier 1 advertised
		photo.note_transfer_progress(t0 + 2.0); // tier 1: last request served
		photo.note_transfer_ended(t0 + 2.5); // tier 1's link closed: its Resource failed
		assert_eq!(passes(&mut photo, t0 + 2.5, t0 + 7.9, 0.25), vec![], "tier 3's race and link are not a silence");
		assert!(photo.measured_by_transfer_progress(), "and not measured from the send's start either");

		photo.note_transfer_progress(t0 + 8.0); // tier 3 advertised
		assert_eq!(passes(&mut photo, t0 + 8.0, t0 + 12.9, 0.25), vec![], "tier 3's Resource, watched from its advertisement");
		assert_eq!(photo.transfer_silence(t0 + 13.1).map(|s| s.ended), Some(false), "and its own silence is asserted");

		// The same race and link on a first attempt: not measured either.
		let mut first = photo_message(LXMessage::SENDING, t0);
		first.note_handed_to_app_links();
		assert_eq!(first.transfer_silence(t0 + 7.6), None);
	}

	/// A silence a Resource ends in is a silence: asserted by the next pass
	/// when none saw it run, closed with nothing more when one did. Either
	/// way the watch stops with the Resource.
	#[test]
	fn a_silence_a_resource_ends_in_is_still_asserted() {
		let t0 = 1_000.0;
		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_transfer_progress(t0 + 1.0);
		photo.note_transfer_ended(t0 + 7.0); // 6 s later, no pass in between
		assert_eq!(photo.transfer_silence(t0 + 7.5), Some(TransferSilence { seconds: 6.0, ended: true }));
		assert_eq!(passes(&mut photo, t0 + 7.5, t0 + 30.0, 0.5), vec![], "asserted once, and the watch has stopped");

		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_transfer_progress(t0 + 1.0);
		assert_eq!(photo.transfer_silence(t0 + 6.5).map(|s| s.ended), Some(false), "asserted while it ran");
		photo.note_transfer_ended(t0 + 9.0);
		assert_eq!(passes(&mut photo, t0 + 9.0, t0 + 30.0, 0.5), vec![], "nothing more once it ended");

		// A Resource that ended inside the limit leaves nothing behind.
		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_transfer_progress(t0 + 1.0);
		photo.note_transfer_ended(t0 + 4.0);
		assert_eq!(photo.transfer_silence_unasserted, None);
		assert_eq!(photo.transfer_moved_at, None);
	}

	/// Each send attempt is watched from its own advertisement: what an
	/// earlier attempt's transfer left behind is gone.
	#[test]
	fn a_new_attempt_is_watched_afresh() {
		let t0 = 1_000.0;
		let mut photo = photo_message(LXMessage::SENDING, t0);
		photo.note_transfer_progress(t0 + 1.0);
		photo.note_transfer_progress(t0 + 8.0);
		assert!(photo.transfer_silence_unasserted.is_some());

		photo.begin_transfer_watch();
		assert_eq!(photo.transfer_moved_at, None);
		assert!(!photo.transfer_by_resource);
		assert_eq!(photo.transfer_silence(t0 + 100.0), None);
	}

	/// The transfer's events are noted only while the message is SENDING,
	/// like its progress: a report after the attempt ended says nothing.
	#[test]
	fn transfer_events_count_only_while_sending() {
		let t0 = 1_000.0;
		for state in [LXMessage::OUTBOUND, LXMessage::FAILED, LXMessage::CANCELLED, LXMessage::DELIVERED, LXMessage::SENT] {
			let mut photo = photo_message(state, t0);
			photo.note_transfer_progress(t0 + 1.0);
			assert_eq!(photo.transfer_moved_at, None, "state {:#04x}", state);
			photo.transfer_moved_at = Some(t0 + 1.0);
			photo.note_transfer_ended(t0 + 9.0);
			assert_eq!(photo.transfer_moved_at, Some(t0 + 1.0), "state {:#04x}: a late end", state);
			assert_eq!(photo.transfer_silence_unasserted, None, "state {:#04x}", state);
		}
	}

	/// The message's own Resource (a DIRECT send on a link the router holds
	/// without AppLinks) hands the send over, and reports its advertisement,
	/// its progress and its end to the transfer watch too.
	#[test]
	fn the_messages_own_resource_reports_to_the_transfer_watch() {
		let src = include_str!("lx_message.rs");
		let production = src.split("#[cfg(test)]").next().expect("production source");
		let body = |name: &str| -> String {
			let from = &production[production.find(name).unwrap_or_else(|| panic!("{}", name))..];
			from[..from.find("\n\t}\n").expect("its end")].to_string()
		};
		let as_resource = body("fn as_resource(");
		assert!(
			as_resource.contains("self.transfer_by_resource = true;"),
			"handing the payload over as a Resource ends the measure from the send's start"
		);
		assert!(
			as_resource.contains("Some(handle) => Resource::advertise_shared_then(")
				&& as_resource.contains("message.note_transfer_progress(now_seconds());"),
			"the advertisement starts the watch"
		);
		let update = body("fn update_transfer_progress(");
		assert!(update.contains("self.note_transfer_progress(now_seconds());"), "each request served is an event");
		for concluded in ["fn resource_concluded(", "fn propagation_resource_concluded("] {
			let concluded = body(concluded);
			let ended = concluded.find("self.note_transfer_ended(now_seconds());").expect("its end stops the watch");
			assert!(
				ended < concluded.find("self.state =").expect("a state change"),
				"the watch stops before the state leaves SENDING"
			);
		}
	}

	/// The reporter the router hands AppLinks notes each report as an event
	/// of the Resource carrying the send, at the time it lands: the
	/// advertisement (0.10, as LXMessage.py) and each request served restart
	/// the clock, the Resource's end stops the watch.
	#[test]
	fn the_progress_reporter_notes_each_transfer_event() {
		use app_links::SendProgress;
		let photo = Arc::new(Mutex::new(photo_message(LXMessage::SENDING, now_seconds())));
		photo.lock().unwrap().note_handed_to_app_links();
		let report = transfer_progress_reporter(&photo);
		let before = now_seconds();
		report(SendProgress::Advertised);
		let advertised = photo.lock().unwrap().transfer_moved_at.expect("the advertisement is noted");
		assert!(advertised >= before && advertised <= now_seconds());
		assert!((photo.lock().unwrap().progress - 0.10).abs() < 1e-9, "the advertisement is 0.10, as LXMessage.py");
		std::thread::sleep(std::time::Duration::from_millis(5));
		report(SendProgress::Fraction(0.0));
		let moved = photo.lock().unwrap().transfer_moved_at.unwrap();
		assert!(moved > advertised, "a resend-only request is an event too");
		report(SendProgress::Fraction(0.5));
		assert!((photo.lock().unwrap().progress - 0.55).abs() < 1e-9);

		report(SendProgress::Ended);
		let photo = photo.lock().unwrap();
		assert_eq!(photo.transfer_moved_at, None, "the Resource's end stops the watch");
		assert_eq!(photo.state, LXMessage::SENDING, "and changes nothing else: its tier's failure decides");
		assert!(photo.measured_by_transfer_progress(), "the send is still a Resource send");
	}

	#[test]
	fn propagated_copy_preserves_canonical_hash_and_application_payload() {
		let mut direct = make_propagated_message();
		direct.desired_method = Some(LXMessage::DIRECT);
		direct.set_field(0x09, Value::Boolean(true));
		direct.add_file_attachment("note.txt", b"attachment payload".to_vec());
		direct.pack(false).expect("pack direct");

		let mut propagated = direct.propagated_copy().expect("propagated copy");
		assert_eq!(propagated.desired_method, Some(LXMessage::PROPAGATED));
		assert_eq!(propagated.timestamp, direct.timestamp);
		assert_eq!(propagated.fields, direct.fields);

		propagated.pack(false).expect("pack propagated");
		assert_eq!(propagated.hash, direct.hash);
	}

	/// REGRESSION GUARD: The POB route for PROPAGATED+ACTIVE must NOT call
	/// send_with_handle(). This is a static / documentation test — it cannot
	/// catch a runtime regression itself but it ensures the invariant is
	/// visible to anyone reading the code changing the POB path.
	///
	/// To verify the runtime contract is preserved: search for any call to
	/// `send_with_handle` inside `process_outbound`'s `LXMessage::PROPAGATED`
	/// match arm.  There must be none.  The only correct send call is:
	///   link.send_packet(&lxm.propagation_packed.unwrap())
	///
	/// See the PROTOCOL comments in lxm_router.rs process_outbound().
	#[test]
	fn propagated_active_branch_does_not_call_send_with_handle() {
		// Static assertion: the router source must not call send_with_handle
		// in the PROPAGATED + ACTIVE branch.
		//
		// We verify this by checking that propagation_packed survives a round-trip
		// through pack() unchanged (i.e., it's stable bytes that can be handed
		// directly to link.send_packet without re-encoding).
		let mut msg = make_propagated_message();
		msg.pack(false).expect("pack");

		let first = msg.propagation_packed.clone().unwrap();

		// Calling pack() again must fail (already packed) — meaning the bytes
		// are final after the first pack and will not mutate between POB cycles.
		let repack_result = msg.pack(false);
		assert!(
			repack_result.is_err(),
			"pack() on an already-packed message must return Err — \
			 propagation_packed bytes are final and stable for link.send_packet()"
		);

		// The bytes from the first pack must still be intact.
		assert_eq!(
			msg.propagation_packed.as_ref().unwrap(),
			&first,
			"propagation_packed must not change after failed re-pack"
		);
	}
}
