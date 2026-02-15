use std::fs::File;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rmpv::encode::write_value;
use rmpv::Value;

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::{self, Identity, SIGLENGTH, TRUNCATED_HASHLENGTH};
use reticulum_rust::link::Link;
use reticulum_rust::packet::{self, Packet};
use reticulum_rust::resource::{Resource, ResourceData, ResourceStatus};
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_ERROR};

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
	delivery_link: Option<Arc<Mutex<Link>>>,
	delivery_callback: Option<Arc<dyn Fn(&LXMessage) + Send + Sync>>,
	failed_callback: Option<Arc<dyn Fn(&LXMessage) + Send + Sync>>,
	pn_encrypted_data: Option<Vec<u8>>,
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

	pub const UNKNOWN: u8 = 0x00;
	pub const PACKET: u8 = 0x01;
	pub const RESOURCE: u8 = 0x02;

	pub const OPPORTUNISTIC: u8 = 0x01;
	pub const DIRECT: u8 = 0x02;
	pub const PROPAGATED: u8 = 0x03;
	pub const PAPER: u8 = 0x05;

	pub const SOURCE_UNKNOWN: u8 = 0x01;
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
		})
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

	pub fn set_field(&mut self, key: u8, value: Value) {
		if let Value::Map(entries) = &mut self.fields {
			let key_value = Value::from(key as i64);
			if let Some(existing) = entries.iter_mut().find(|(k, _)| *k == key_value) {
				existing.1 = value;
				return;
			}
			entries.push((key_value, value));
		}
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

	pub fn set_delivery_link(&mut self, link: Arc<Mutex<Link>>) {
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
				let destination = self
					.destination
					.as_ref()
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
					.as_ref()
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

	pub fn send(&mut self) -> Result<(), String> {
		self.send_with_handle(None)
	}

	pub fn send_shared(message: Arc<Mutex<LXMessage>>) -> Result<(), String> {
		let handle = Arc::clone(&message);
		let mut locked = message.lock().map_err(|_| "LXMessage lock poisoned".to_string())?;
		locked.send_with_handle(Some(handle))
	}

	fn send_with_handle(&mut self, handle: Option<Arc<Mutex<LXMessage>>>) -> Result<(), String> {
		self.determine_transport_encryption();
		match self.method {
			Self::OPPORTUNISTIC => {
				let mut packet = self.as_packet()?;
				let receipt = packet.send()?;
				self.progress = 0.50;
				self.ratchet_id = packet.ratchet_id.clone();
				self.state = Self::SENT;
				if let Some(mut receipt) = receipt {
					if let Some(handle) = handle.clone() {
						receipt.set_delivery_callback(Arc::new(move |_| {
							mark_delivered_shared(&handle);
						}));
					}
				}
			}
			Self::DIRECT => {
				self.state = Self::SENDING;
				match self.representation {
					Self::PACKET => {
						let mut packet = self.as_packet()?;
						let receipt = packet.send()?;
						if let Some(link) = self.delivery_link.as_ref() {
							if let Ok(link_guard) = link.lock() {
								self.ratchet_id = Some(link_guard.link_id.clone());
							}
						}
						if let Some(mut receipt) = receipt {
							if let Some(handle) = handle.clone() {
								let delivery_handle = Arc::clone(&handle);
								let timeout_handle = Arc::clone(&handle);
								receipt.set_delivery_callback(Arc::new(move |_| {
									mark_delivered_shared(&delivery_handle);
								}));
								receipt.set_timeout_callback(Arc::new(move |_| {
									link_packet_timed_out_shared(&timeout_handle);
								}));
							}
							self.progress = 0.50;
						} else {
							if let Some(link) = self.delivery_link.as_ref() {
								if let Ok(mut link_guard) = link.lock() {
									link_guard.teardown();
								}
							}
						}
					}
					Self::RESOURCE => {
						if let Some(link) = self.delivery_link.as_ref() {
							if let Ok(link_guard) = link.lock() {
								self.ratchet_id = Some(link_guard.link_id.clone());
							}
						}
						self.resource_representation = Some(self.as_resource(handle)?);
						self.progress = 0.10;
					}
					_ => {}
				}
			}
			Self::PROPAGATED => {
				self.state = Self::SENDING;
				match self.representation {
					Self::PACKET => {
						let mut packet = self.as_packet()?;
						let receipt = packet.send()?;
						if let Some(mut receipt) = receipt {
							if let Some(handle) = handle.clone() {
								let delivery_handle = Arc::clone(&handle);
								let timeout_handle = Arc::clone(&handle);
								receipt.set_delivery_callback(Arc::new(move |_| {
									mark_propagated_shared(&delivery_handle);
								}));
								receipt.set_timeout_callback(Arc::new(move |_| {
									link_packet_timed_out_shared(&timeout_handle);
								}));
							}
							self.progress = 0.50;
						} else {
							if let Some(link) = self.delivery_link.as_ref() {
								if let Ok(mut link_guard) = link.lock() {
									link_guard.teardown();
								}
							}
						}
					}
					Self::RESOURCE => {
						if let Some(link) = self.delivery_link.as_ref() {
							if let Ok(link_guard) = link.lock() {
								self.ratchet_id = Some(link_guard.link_id.clone());
							}
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
			Some(source_hash),
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
			} else {
				message.signature_validated = false;
				message.unverified_reason = Some(Self::SIGNATURE_INVALID);
			}
		} else {
			message.signature_validated = false;
			message.unverified_reason = Some(Self::SOURCE_UNKNOWN);
			log(
				"Unpacked LXMF message signature could not be validated, source identity unknown",
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
		let is_active = link.lock().map_err(|_| "Link lock poisoned")?.is_active();
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
		let progress_callback = handle.map(|handle| {
			Arc::new(move |resource: Arc<Mutex<Resource>>| {
				update_transfer_progress_shared(&handle, &resource);
			}) as Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>
		});

		let resource = Resource::new_internal(
			resource_data,
			link,
			None,
			true,
			reticulum_rust::resource::AutoCompressOption::Enabled,
			callback,
			progress_callback,
			None,
			0,
			None,
			None,
			false,
			0,
		)?;
		Ok(Arc::new(Mutex::new(resource)))
	}

	fn mark_delivered(&mut self) {
		log(
			format!("Received delivery notification for {}", self),
			LOG_DEBUG,
			false,
			false,
		);
		self.state = Self::DELIVERED;
		self.progress = 1.0;
		if let Some(callback) = self.delivery_callback.as_ref() {
			callback(self);
		}
	}

	fn mark_propagated(&mut self) {
		log(
			format!("Received propagation success notification for {}", self),
			LOG_DEBUG,
			false,
			false,
		);
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
		if resource.status == ResourceStatus::Complete {
			self.mark_delivered();
		} else if resource.status == ResourceStatus::Rejected {
			self.state = Self::REJECTED;
		} else if self.state != Self::CANCELLED {
			if let Some(link) = self.delivery_link.as_ref() {
				if let Ok(mut link_guard) = link.lock() {
					link_guard.teardown();
				}
			}
			self.state = Self::OUTBOUND;
		}
	}

	fn propagation_resource_concluded(&mut self, resource: &Resource) {
		if resource.status == ResourceStatus::Complete {
			self.mark_propagated();
		} else if self.state != Self::CANCELLED {
			if let Some(link) = self.delivery_link.as_ref() {
				if let Ok(mut link_guard) = link.lock() {
					link_guard.teardown();
				}
			}
			self.state = Self::OUTBOUND;
		}
	}

	fn link_packet_timed_out(&mut self) {
		if self.state != Self::CANCELLED {
			if let Some(link) = self.delivery_link.as_ref() {
				if let Ok(mut link) = link.lock() {
					link.teardown();
				}
			}
			self.state = Self::OUTBOUND;
		}
	}

	fn update_transfer_progress(&mut self, resource: &mut Resource) {
		let progress = resource.get_progress();
		self.progress = 0.10 + (progress * 0.90);
	}
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

fn recall_identity(_hash: &[u8]) -> Option<Identity> {
	None
}

fn mark_delivered_shared(handle: &Arc<Mutex<LXMessage>>) {
	if let Ok(mut message) = handle.lock() {
		message.mark_delivered();
	}
}

fn mark_propagated_shared(handle: &Arc<Mutex<LXMessage>>) {
	if let Ok(mut message) = handle.lock() {
		message.mark_propagated();
	}
}

fn link_packet_timed_out_shared(handle: &Arc<Mutex<LXMessage>>) {
	if let Ok(mut message) = handle.lock() {
		message.link_packet_timed_out();
	}
}

fn resource_concluded_shared(handle: &Arc<Mutex<LXMessage>>, resource: &Arc<Mutex<Resource>>) {
	let resource_guard = match resource.lock() {
		Ok(guard) => guard,
		Err(_) => return,
	};
	if let Ok(mut message) = handle.lock() {
		if message.method == LXMessage::PROPAGATED {
			message.propagation_resource_concluded(&resource_guard);
		} else {
			message.resource_concluded(&resource_guard);
		}
	}
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
