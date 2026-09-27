//! RFed channel posts: the LXMF message inside a channel envelope.
//!
//! One implementation of pack and unpack, shared by the iOS FFI
//! (`retichat-ffi`) and the Android JNI (`retichat-jni`) bridges, which are
//! thin wrappers over it. Until 2026-09-27 each bridge carried its own copy;
//! the key-binding check (DISPLAY_NAMES.md §2.3) and the Channel Display Name
//! (field 0xD1) now live here, once.
//!
//! ## Wire format (unchanged)
//!
//! A channel is a deterministic identity derived from its name
//! (`SHA-256(name)` as both the X25519 and the Ed25519 seed, mirroring
//! `ChannelKeypair::from_name` in RFed-rust). A post is
//!
//! ```text
//! channel_id_hash(16) | EC_encrypt_to_channel( b"RTID" | sender_pub(64) | source_hash(16) | signature(64) | msgpack_payload )
//! ```
//!
//! `channel_id_hash` is the channel IDENTITY hash, RFed's routing label. The
//! LXMF message is addressed to the channel's `lxmf.delivery` destination and
//! signed over that destination hash; the receiver derives it from the
//! channel name to rebuild the canonical LXMF bytes. The `RTID` prelude
//! carries the sender's 64-byte public key so the signature can be checked
//! without waiting for the sender's announce.
//!
//! ## Key binding (DISPLAY_NAMES.md §2.3)
//!
//! Unpack checks that the prelude key produces the claimed source hash as an
//! `lxmf.delivery` destination BEFORE remembering it, and rejects the post if
//! not. Without the check anyone who knows a channel's name could post as a
//! contact and overwrite that contact's stored key.

use sha2::{Digest, Sha256};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;

use crate::display_name::{self, NameField};
use crate::lx_message::LXMessage;
use crate::lxmf::FIELD_DISPLAY_NAME;

const LXMF_APP_NAME: &str = "lxmf";
const LXMF_DELIVERY_ASPECT: &str = "delivery";

/// Magic that opens the decrypted post: the sender's public key follows.
pub const PRELUDE_MAGIC: &[u8; 4] = b"RTID";
/// Magic plus `Identity::get_public_key()` (32 X25519 || 32 Ed25519).
pub const PRELUDE_LEN: usize = 4 + 64;
const HASH_LEN: usize = LXMessage::DESTINATION_LENGTH;

/// The channel's private key bytes: `SHA-256(name)` twice.
pub fn channel_private_key_bytes(name: &str) -> [u8; 64] {
	let seed: [u8; 32] = Sha256::digest(name.as_bytes()).into();
	let mut prv = [0u8; 64];
	prv[..32].copy_from_slice(&seed);
	prv[32..].copy_from_slice(&seed);
	prv
}

pub fn channel_identity(name: &str) -> Result<Identity, String> {
	Identity::from_bytes(&channel_private_key_bytes(name))
}

/// The channel's `lxmf.delivery` destination: what posts are addressed to
/// and signed over.
pub fn channel_destination(name: &str) -> Result<Destination, String> {
	Destination::new_outbound(
		Some(channel_identity(name)?),
		DestinationType::Single,
		LXMF_APP_NAME.to_string(),
		vec![LXMF_DELIVERY_ASPECT.to_string()],
	)
}

/// The channel identity hash: RFed's routing label, the first 16 bytes of a post.
pub fn channel_id_hash(name: &str) -> Result<Vec<u8>, String> {
	let hash = channel_identity(name)?.hash.ok_or("channel identity has no hash")?;
	if hash.len() != HASH_LEN {
		return Err("channel identity hash wrong length".into());
	}
	Ok(hash)
}

/// The `lxmf.delivery` destination hash an identity's public key produces.
pub fn lxmf_delivery_hash_for_public_key(public_key: &[u8]) -> Result<Vec<u8>, String> {
	let identity = Identity::from_public_key(public_key)?;
	let destination = Destination::new_outbound(
		Some(identity),
		DestinationType::Single,
		LXMF_APP_NAME.to_string(),
		vec![LXMF_DELIVERY_ASPECT.to_string()],
	)?;
	Ok(destination.hash)
}

/// The name a post carries (DISPLAY_NAMES.md §2.3): `Absent` puts no 0xD1
/// in the message (and the bytes are exactly the pre-name format), `Clear`
/// an empty 0xD1, `Name` the cleaned name.
pub type PostName = NameField;

/// Map the FFI/JNI `(state, bytes)` pair to a post name: 0 none, 1 clear,
/// 2 name (cleaned; a name that cleans to nothing is an error, since the
/// caller meant to send one).
pub fn post_name_from_state(state: u8, raw: &[u8]) -> Result<PostName, String> {
	match state {
		0 => Ok(NameField::Absent),
		1 => Ok(NameField::Clear),
		2 => display_name::clean(raw)
			.map(NameField::Name)
			.ok_or_else(|| "channel display name cleans to nothing; send state 0 (none) or 1 (clear)".to_string()),
		other => Err(format!("unknown display name state {other} (0 none, 1 clear, 2 name)")),
	}
}

/// A packed post.
#[derive(Debug, Clone)]
pub struct PackedPost {
	/// The LXMF timestamp baked into the signed payload, in milliseconds, so
	/// the caller can match its own post when RFed echoes it back.
	pub timestamp_ms: u64,
	/// `channel_id_hash(16) | EC_encrypted(...)`: the `rfed.channel` payload.
	pub wire: Vec<u8>,
}

impl PackedPost {
	/// The FFI/JNI output: `timestamp_ms u64 BE | wire`. Callers strip the
	/// first 8 bytes before sending.
	pub fn to_bridge_bytes(&self) -> Vec<u8> {
		let mut out = Vec::with_capacity(8 + self.wire.len());
		out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
		out.extend_from_slice(&self.wire);
		out
	}
}

/// Build and encrypt a channel post from `sender`.
pub fn pack(
	channel: &str,
	sender: &Identity,
	content: &[u8],
	title: &[u8],
	name: &PostName,
) -> Result<PackedPost, String> {
	pack_at(channel, sender, content, title, name, None)
}

fn pack_at(
	channel: &str,
	sender: &Identity,
	content: &[u8],
	title: &[u8],
	name: &PostName,
	timestamp: Option<f64>,
) -> Result<PackedPost, String> {
	if channel.is_empty() {
		return Err("channel name is empty".into());
	}
	let name_value = match name {
		// A caller may hand an uncleaned name; what goes out is always cleaned.
		NameField::Name(raw) => Some(
			NameField::Name(display_name::clean(raw.as_bytes()).ok_or("channel display name cleans to nothing")?)
				.to_value()
				.expect("a name has a value"),
		),
		other => other.to_value(),
	};

	let sender_pub = sender.get_public_key().map_err(|e| format!("sender identity has no public key: {e}"))?;
	if sender_pub.len() != 64 {
		return Err(format!("sender identity public key wrong length: expected 64, got {}", sender_pub.len()));
	}

	let mut channel_dest = channel_destination(channel).map_err(|e| format!("channel destination: {e}"))?;
	let sender_dest = Destination::new_outbound(
		Some(sender.clone()),
		DestinationType::Single,
		LXMF_APP_NAME.to_string(),
		vec![LXMF_DELIVERY_ASPECT.to_string()],
	)
	.map_err(|e| format!("sender destination: {e}"))?;

	let mut msg = LXMessage::new(
		Some(channel_dest.clone()),
		Some(sender_dest),
		Some(content.to_vec()),
		Some(title.to_vec()),
		None, // fields = empty map, exactly as before names existed
		Some(LXMessage::PROPAGATED),
		None,
		None,
		None,  // stamp_cost: PoW is at the RFed wrapper, not LXMF
		false, // include_ticket
	)
	.map_err(|e| format!("LXMessage::new: {e}"))?;
	if let Some(value) = name_value {
		msg.set_field(FIELD_DISPLAY_NAME, value);
	}
	msg.timestamp = timestamp;
	msg.pack(false).map_err(|e| format!("LXMessage::pack: {e}"))?;

	let packed = msg.packed.as_ref().ok_or("LXMessage missing packed buffer after pack")?;
	if packed.len() < HASH_LEN {
		return Err("packed buffer too short".into());
	}
	// packed = lxmf_dest(16) | source(16) | signature(64) | payload. The
	// destination is dropped (the receiver derives it from the channel name)
	// and the prelude goes in front.
	let lxmf_tail = &packed[HASH_LEN..];
	let mut plaintext = Vec::with_capacity(PRELUDE_LEN + lxmf_tail.len());
	plaintext.extend_from_slice(PRELUDE_MAGIC);
	plaintext.extend_from_slice(&sender_pub);
	plaintext.extend_from_slice(lxmf_tail);
	let encrypted = channel_dest.encrypt(&plaintext).map_err(|e| format!("channel encrypt: {e}"))?;

	let id_hash = channel_id_hash(channel)?;
	let mut wire = Vec::with_capacity(HASH_LEN + encrypted.len());
	wire.extend_from_slice(&id_hash);
	wire.extend_from_slice(&encrypted);
	Ok(PackedPost { timestamp_ms: (msg.timestamp.unwrap_or(0.0) * 1000.0) as u64, wire })
}

/// An unpacked post.
#[derive(Debug, Clone, PartialEq)]
pub struct UnpackedPost {
	pub source_hash: Vec<u8>,
	pub timestamp_ms: u64,
	pub signature_validated: bool,
	/// 0 ok, 1 source unknown, 2 signature invalid (other LXMF reasons pass through).
	pub unverified_reason: u8,
	pub title: Vec<u8>,
	pub content: Vec<u8>,
	/// The post's Channel Display Name (DISPLAY_NAMES.md §5.2): reported only
	/// when the key binding and the signature both passed; `Absent` otherwise.
	pub display_name: NameField,
}

impl UnpackedPost {
	/// The FFI/JNI output. The first part is the layout the bridges have
	/// always returned; the name trailer is appended at the end so decoders
	/// that ignore trailing bytes keep working.
	///
	/// ```text
	/// offset      size  field
	/// 0           16    source_hash
	/// 16          8     timestamp_ms       u64 BE
	/// 24          1     signature_validated  1 ok, 0 not
	/// 25          1     unverified_reason  0 ok, 1 source unknown, 2 signature invalid
	/// 26          2     title_len          u16 BE
	/// 28          4     content_len        u32 BE
	/// 32          t     title
	/// 32+t        c     content
	/// 32+t+c      1     name_state         0 absent, 1 clear, 2 name
	/// 33+t+c      2     name_len           u16 BE
	/// 35+t+c      n     name               cleaned UTF-8
	/// ```
	pub fn to_bridge_bytes(&self) -> Result<Vec<u8>, String> {
		if self.title.len() > u16::MAX as usize {
			return Err("title too large".into());
		}
		if self.content.len() > u32::MAX as usize {
			return Err("content too large".into());
		}
		let trailer = self.display_name.to_trailer();
		let mut out = Vec::with_capacity(32 + self.title.len() + self.content.len() + trailer.len());
		out.extend_from_slice(&self.source_hash);
		out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
		out.push(self.signature_validated as u8);
		out.push(self.unverified_reason);
		out.extend_from_slice(&(self.title.len() as u16).to_be_bytes());
		out.extend_from_slice(&(self.content.len() as u32).to_be_bytes());
		out.extend_from_slice(&self.title);
		out.extend_from_slice(&self.content);
		out.extend_from_slice(&trailer);
		Ok(out)
	}
}

/// Decrypt and verify a post received from RFed (`data` is the wire payload
/// `channel_id_hash(16) | EC_encrypted(...)`).
///
/// Rejects a post whose prelude key does not produce its claimed source
/// hash, before any key is remembered (DISPLAY_NAMES.md §2.3). A post that
/// passes has its sender key remembered under the source hash, so the LXMF
/// signature is checked against it.
pub fn unpack(channel: &str, data: &[u8]) -> Result<UnpackedPost, String> {
	if channel.is_empty() {
		return Err("channel name is empty".into());
	}
	if data.len() < HASH_LEN + 32 {
		return Err("lxmf_data too short".into());
	}
	let mut id = channel_identity(channel).map_err(|e| format!("channel identity: {e}"))?;
	let decrypted = id.decrypt(&data[HASH_LEN..]).map_err(|e| format!("channel decrypt: {e}"))?;

	// The prelude is mandatory: every Retichat client sends it.
	if decrypted.len() < PRELUDE_LEN || &decrypted[..4] != PRELUDE_MAGIC {
		return Err("channel: missing SOURCE-IDENTITY PRELUDE — sender on incompatible build or payload malformed".into());
	}
	let sender_pub = &decrypted[4..PRELUDE_LEN];
	let lxmf_tail = &decrypted[PRELUDE_LEN..];
	if lxmf_tail.len() < HASH_LEN {
		return Err("channel: LXMF tail after prelude too short".into());
	}
	let claimed_source = &lxmf_tail[..HASH_LEN];

	// §2.3 key binding, BEFORE remembering anything.
	let bound = lxmf_delivery_hash_for_public_key(sender_pub)
		.map_err(|e| format!("channel: prelude key is not a valid public key: {e}"))?;
	if bound[..] != claimed_source[..] {
		return Err(format!(
			"channel: prelude key does not produce the claimed source {} — post rejected (key binding, DISPLAY_NAMES.md §2.3)",
			reticulum_rust::hexrep(claimed_source, false)
		));
	}
	Identity::remember_destination(claimed_source, sender_pub, None)
		.map_err(|e| format!("channel: remember_destination failed: {e}"))?;

	// Rebuild the canonical LXMF bytes over the channel's lxmf.delivery hash,
	// which is what the sender signed (the wire prefix is the identity hash).
	let lxmf_dest = channel_destination(channel).map_err(|e| format!("channel destination: {e}"))?.hash;
	if lxmf_dest.len() != HASH_LEN {
		return Err("lxmf dest hash wrong length".into());
	}
	let mut full = Vec::with_capacity(HASH_LEN + lxmf_tail.len());
	full.extend_from_slice(&lxmf_dest);
	full.extend_from_slice(lxmf_tail);
	let msg = LXMessage::unpack_from_bytes(&full, Some(LXMessage::PROPAGATED)).map_err(|e| format!("LXMessage::unpack: {e}"))?;

	if msg.source_hash.len() != HASH_LEN {
		return Err("source_hash wrong length".into());
	}
	let unverified_reason = match msg.unverified_reason {
		Some(LXMessage::SOURCE_UNKNOWN) => 1,
		Some(LXMessage::SIGNATURE_INVALID) => 2,
		Some(other) => other,
		None => 0,
	};
	// §5.2: a post's 0xD1 counts only once the key binding (above) and the
	// signature have passed.
	let display_name = if msg.signature_validated {
		display_name::decode_field(&msg.fields)
	} else {
		NameField::Absent
	};
	Ok(UnpackedPost {
		source_hash: msg.source_hash.clone(),
		timestamp_ms: (msg.timestamp.unwrap_or(0.0) * 1000.0) as u64,
		signature_validated: msg.signature_validated,
		unverified_reason,
		title: msg.title.clone(),
		content: msg.content.clone(),
		display_name,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	const CHANNEL: &str = "public.display-name-tests";

	fn decrypt_post(channel: &str, wire: &[u8]) -> Vec<u8> {
		channel_identity(channel).unwrap().decrypt(&wire[HASH_LEN..]).unwrap()
	}

	fn encrypt_post(channel: &str, plaintext: &[u8]) -> Vec<u8> {
		let mut out = channel_id_hash(channel).unwrap();
		out.extend_from_slice(&channel_destination(channel).unwrap().encrypt(plaintext).unwrap());
		out
	}

	fn delivery_hash(identity: &Identity) -> Vec<u8> {
		lxmf_delivery_hash_for_public_key(&identity.get_public_key().unwrap()).unwrap()
	}

	/// The wire bytes without a name are exactly the pre-name format: the
	/// routing label, then (decrypted) RTID | sender key | source | signature
	/// | [F64 timestamp, bin title, bin content, {}].
	#[test]
	fn a_post_without_a_name_keeps_the_existing_wire_shape() {
		let sender = Identity::new(true);
		let ts = 1_790_000_000.25_f64;
		let post = pack_at(CHANNEL, &sender, b"hello", b"t", &NameField::Absent, Some(ts)).unwrap();
		assert_eq!(post.timestamp_ms, 1_790_000_000_250);
		assert_eq!(&post.wire[..HASH_LEN], &channel_id_hash(CHANNEL).unwrap()[..]);
		let bridge = post.to_bridge_bytes();
		assert_eq!(&bridge[..8], &1_790_000_000_250u64.to_be_bytes());
		assert_eq!(&bridge[8..], &post.wire[..]);

		let plaintext = decrypt_post(CHANNEL, &post.wire);
		assert_eq!(&plaintext[..4], b"RTID");
		assert_eq!(&plaintext[4..68], &sender.get_public_key().unwrap()[..]);
		assert_eq!(&plaintext[68..84], &delivery_hash(&sender)[..]);
		let mut payload = vec![0x94, 0xcb];
		payload.extend_from_slice(&ts.to_be_bytes());
		payload.extend_from_slice(&[0xc4, 0x01, b't', 0xc4, 0x05]);
		payload.extend_from_slice(b"hello");
		payload.push(0x80);
		assert_eq!(&plaintext[84 + 64..], &payload[..], "payload bytes changed");
		assert_eq!(plaintext.len(), 84 + 64 + payload.len());
	}

	#[test]
	fn a_named_post_carries_0xd1_as_bin() {
		let sender = Identity::new(true);
		let ts = 1_790_000_000.5_f64;
		let post = pack_at(CHANNEL, &sender, b"hi", b"", &NameField::Name("  Bob ".into()), Some(ts)).unwrap();
		let plaintext = decrypt_post(CHANNEL, &post.wire);
		assert!(plaintext.ends_with(&[0x81, 0xcc, 0xd1, 0xc4, 0x03, b'B', b'o', b'b']), "fields = {{0xD1: bin \"Bob\"}}");
		let clear = pack_at(CHANNEL, &sender, b"hi", b"", &NameField::Clear, Some(ts)).unwrap();
		assert!(decrypt_post(CHANNEL, &clear.wire).ends_with(&[0x81, 0xcc, 0xd1, 0xc4, 0x00]));
	}

	#[test]
	fn names_round_trip() {
		let sender = Identity::new(true);
		for name in [NameField::Absent, NameField::Clear, NameField::Name("Bob \u{1F44B}".into())] {
			let post = pack(CHANNEL, &sender, b"body", b"title", &name).unwrap();
			let got = unpack(CHANNEL, &post.wire).unwrap();
			assert_eq!(got.source_hash, delivery_hash(&sender));
			assert!(got.signature_validated);
			assert_eq!(got.unverified_reason, 0);
			assert_eq!(got.title, b"title");
			assert_eq!(got.content, b"body");
			assert_eq!(got.timestamp_ms, post.timestamp_ms);
			assert_eq!(got.display_name, name);
		}
	}

	#[test]
	fn bridge_output_appends_the_name_after_the_old_layout() {
		let sender = Identity::new(true);
		let post = pack(CHANNEL, &sender, b"body", b"ti", &NameField::Name("Bob".into())).unwrap();
		let out = unpack(CHANNEL, &post.wire).unwrap().to_bridge_bytes().unwrap();
		assert_eq!(&out[..16], &delivery_hash(&sender)[..]);
		assert_eq!(&out[16..24], &post.timestamp_ms.to_be_bytes());
		assert_eq!(out[24], 1);
		assert_eq!(out[25], 0);
		assert_eq!(&out[26..28], &[0, 2]);
		assert_eq!(&out[28..32], &[0, 0, 0, 4]);
		assert_eq!(&out[32..34], b"ti");
		assert_eq!(&out[34..38], b"body");
		assert_eq!(&out[38..], &[2, 0, 3, b'B', b'o', b'b']);

		let plain = pack(CHANNEL, &sender, b"body", b"ti", &NameField::Absent).unwrap();
		let out = unpack(CHANNEL, &plain.wire).unwrap().to_bridge_bytes().unwrap();
		assert_eq!(&out[38..], &[0, 0, 0], "absent: state 0, length 0");
	}

	/// §2.3: a post whose prelude key does not produce the claimed source is
	/// rejected, and no key is remembered — the victim's stored key survives.
	#[test]
	fn a_mismatched_key_is_rejected_and_nothing_is_remembered() {
		let attacker = Identity::new(true);
		let victim = Identity::new(true);
		let victim_hash = delivery_hash(&victim);
		let post = pack(CHANNEL, &attacker, b"I am the victim", b"", &NameField::Name("Victim".into())).unwrap();
		let mut plaintext = decrypt_post(CHANNEL, &post.wire);
		plaintext[68..84].copy_from_slice(&victim_hash);
		let forged = encrypt_post(CHANNEL, &plaintext);

		assert_eq!(Identity::recall_public_key(&victim_hash), None);
		let err = unpack(CHANNEL, &forged).expect_err("must be rejected");
		assert!(err.contains("key binding"), "{err}");
		assert_eq!(Identity::recall_public_key(&victim_hash), None, "nothing remembered");

		// A contact whose key is already known keeps it.
		Identity::remember_destination(&victim_hash, &victim.get_public_key().unwrap(), None).unwrap();
		assert!(unpack(CHANNEL, &forged).is_err());
		assert_eq!(Identity::recall_public_key(&victim_hash), Some(victim.get_public_key().unwrap()));
	}

	/// With the victim's real key in the prelude the binding passes, but the
	/// signature (made by someone else) does not: the name is not reported.
	#[test]
	fn a_post_with_an_invalid_signature_reports_no_name() {
		let attacker = Identity::new(true);
		let victim = Identity::new(true);
		let victim_hash = delivery_hash(&victim);
		let post = pack(CHANNEL, &attacker, b"forged", b"", &NameField::Name("Victim".into())).unwrap();
		let mut plaintext = decrypt_post(CHANNEL, &post.wire);
		plaintext[4..68].copy_from_slice(&victim.get_public_key().unwrap());
		plaintext[68..84].copy_from_slice(&victim_hash);
		let got = unpack(CHANNEL, &encrypt_post(CHANNEL, &plaintext)).unwrap();
		assert!(!got.signature_validated);
		assert_eq!(got.unverified_reason, 2);
		assert_eq!(got.display_name, NameField::Absent);
	}

	#[test]
	fn a_post_without_the_prelude_is_rejected() {
		let sender = Identity::new(true);
		let post = pack(CHANNEL, &sender, b"x", b"", &NameField::Absent).unwrap();
		let plaintext = decrypt_post(CHANNEL, &post.wire);
		assert!(unpack(CHANNEL, &encrypt_post(CHANNEL, &plaintext[PRELUDE_LEN..])).is_err());
	}

	#[test]
	fn post_name_states() {
		assert_eq!(post_name_from_state(0, b"ignored").unwrap(), NameField::Absent);
		assert_eq!(post_name_from_state(1, b"").unwrap(), NameField::Clear);
		assert_eq!(post_name_from_state(2, b" Bob\t").unwrap(), NameField::Name("Bob".into()));
		assert!(post_name_from_state(2, "\u{200B}".as_bytes()).is_err());
		assert!(post_name_from_state(2, b"\xff").is_err());
		assert!(post_name_from_state(3, b"").is_err());
		assert!(pack(CHANNEL, &Identity::new(true), b"x", b"", &NameField::Name("\u{200B}".into())).is_err());
	}

	/// The same key derivation the bridges used (and RFed's ChannelKeypair).
	#[test]
	fn channel_keys_are_sha256_of_the_name_twice() {
		let prv = channel_private_key_bytes("public.general");
		let seed: [u8; 32] = Sha256::digest(b"public.general").into();
		assert_eq!(&prv[..32], &seed);
		assert_eq!(&prv[32..], &seed);
	}
}
