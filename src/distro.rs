//! Distro client primitives.
//!
//! Everything a client needs to speak RFed's distro protocol that is *wire
//! format* rather than orchestration: the signed request payloads, the
//! pre-signed announce, and unwrapping a delivered blob.
//!
//! This lives here, once, because both native bridges (`retichat-ffi` for iOS
//! and `retichat-jni` for Android) depend on `lxmf_rust`, and because format
//! code is precisely the class that must not be reimplemented per platform —
//! a second copy of a wire format drifts silently and is only discovered when
//! two implementations stop talking to each other.
//!
//! Orchestration — link management, retries, persistence, UI — stays in the
//! platform layer, mirroring how `RfedChannelClient` already works.
//!
//! Payload shapes are pinned by `rfed`'s `verify_signed_payload` and
//! `parse_distro_announce_payload`; see RFed SPEC §17.5 and §17.9. The
//! sent-message sync marker read by `unwrap_blob` is RFed SPEC §17.11. The
//! distro sync proof (`seal_for_sync`, `sealed_upload`,
//! `decode_sync_extension`, `verify_sync_claim`) is RFed SPEC §17.13.

use std::collections::HashMap;
use std::io::Cursor;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rmpv::decode::{read_value, read_value_ref};
use rmpv::encode::write_value;
use rmpv::Value;

use reticulum_rust::destination::{Destination, DestinationType, Direction};
use reticulum_rust::identity::{full_hash, truncated_hash, Identity};

use crate::display_name::{self, NameField};
use crate::lx_message::LXMessage;

/// Size of an LXMF signature and of an identity public key half, in bytes.
const PUBKEY_LEN: usize = 64;
/// `srcHash(16) || signature(64)` precedes the msgpack payload in an LXMF message.
const LXMF_HEADER_LEN: usize = 16 + 64;
/// Truncated destination hash length.
const DEST_HASH_LEN: usize = 16;

/// A distro message after decryption.
#[derive(Debug, Clone, PartialEq)]
pub struct DistroMessage {
    /// `lxmf.delivery` hash of whoever sent it.
    pub source_hash: Vec<u8>,
    /// LXMF timestamp, seconds since epoch as a float. With `source_hash` this
    /// is the identity a client should deduplicate on — the same message
    /// arrives more than once (live fan-out, deferred PULL, and a re-fan
    /// whenever a node re-ingests it), and the framings differ, so the bytes
    /// are not a usable key.
    pub timestamp: f64,
    pub title: String,
    pub content: String,
    /// True when the message carries no content and no attachment
    /// (FIELD_FILE_ATTACHMENTS, FIELD_IMAGE, FIELD_AUDIO) but does carry a
    /// ticket field, i.e. it is a delivery notification rather than
    /// something to display. Storing these produces empty message bubbles.
    pub is_delivery_notification: bool,
    /// FIELD_TICKET (0x0C), when present.
    pub ticket: Option<String>,
    /// A distro private key being transferred to this device (RFed SPEC
    /// §17.9): FIELD_CUSTOM_DATA of a message whose FIELD_CUSTOM_TYPE is
    /// `DISTRO_TRANSFER_TYPE`. Present only on an identity-transfer message.
    pub distro_transfer_key: Option<String>,
    /// RFed SPEC §17.11 sent-message sync: the recipient R of the message a
    /// sibling device sent as the distro — FIELD_CUSTOM_DATA of a message whose
    /// FIELD_CUSTOM_TYPE is `DISTRO_SENT_TYPE`, lowercased. `None` unless the
    /// value is exactly 32 hex characters, so a client never files a copy into
    /// a conversation with a malformed address.
    pub sent_to: Option<String>,
    /// RFed SPEC §17.11: FIELD_CUSTOM_META of the same copy, lowercased — the
    /// sending device's own `lxmf.delivery` address, which lets the sender
    /// recognise and drop its own echo. `Some` whenever the custom type is
    /// `DISTRO_SENT_TYPE` (empty when 0xFD is absent), so `sent_by.is_some()`
    /// is how a client tells "sync copy with a bad 0xFC — drop and log" apart
    /// from an ordinary message, whose `sent_to` is also `None`.
    pub sent_by: Option<String>,
    /// DISPLAY_NAMES.md §2.1 / §5.2: what the name entry (key 0 of field
    /// 0xD1) says about the source.
    /// Whether the client accepts it depends on the signature fields below.
    pub display_name: NameField,
    /// LXMF signature check against the source's known key (§5.2): true only
    /// when the key is known and the signature verifies.
    pub signature_validated: bool,
    /// `None` when validated; otherwise `LXMessage::SOURCE_UNKNOWN` (no key
    /// for the source yet) or `LXMessage::SIGNATURE_INVALID`.
    pub unverified_reason: Option<u8>,
    /// The message's LXMF fields map (payload element 3) as msgpack, the
    /// bytes exactly as the sender packed them: attachments
    /// (FIELD_FILE_ATTACHMENTS 0x05, FIELD_IMAGE 0x06, FIELD_AUDIO 0x07) and
    /// every other field, for the apps' own field decoders — the same input
    /// they take for a direct message. `None` when the payload has no fields
    /// map. An empty map is `Some(vec![0x80])`.
    pub fields: Option<Vec<u8>>,
}

impl DistroMessage {
    /// The JSON both native bridges return from their distro unwrap
    /// (`retichat_distro_unwrap`, `nativeDistroUnwrap`): one definition, so the
    /// keys cannot drift between iOS and Android.
    ///
    /// Keys: `source_hash` (hex), `timestamp`, `title`, `content`,
    /// `is_delivery_notification`, `ticket`, `distro_transfer_key`, `sent_to`,
    /// `sent_by`, `display_name_state` (0 absent, 1 clear, 2 name),
    /// `display_name` (null unless 2), `signature_validated`,
    /// `unverified_reason` (0 ok, 1 source unknown, 2 signature invalid),
    /// `fields`: the LXMF fields map as msgpack (`DistroMessage::fields`,
    /// the bytes as the sender packed them), base64 with the standard
    /// alphabet and `=` padding (RFC 4648 §4) — what iOS
    /// `Data(base64Encoded:)` and Android `Base64.decode(_, DEFAULT)` read —
    /// or null when the payload has no fields map. The decoded bytes go
    /// straight to the apps' field decoders, as for a direct message.
    pub fn to_json(&self) -> String {
        let opt = |v: &Option<String>| v.as_deref().map(json_string).unwrap_or_else(|| "null".into());
        format!(
            concat!(
                r#"{{"source_hash":"{}","timestamp":{},"title":{},"content":{},"#,
                r#""is_delivery_notification":{},"ticket":{},"distro_transfer_key":{},"#,
                r#""sent_to":{},"sent_by":{},"#,
                r#""display_name_state":{},"display_name":{},"signature_validated":{},"unverified_reason":{},"#,
                r#""fields":{}}}"#
            ),
            self.source_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            self.timestamp,
            json_string(&self.title),
            json_string(&self.content),
            self.is_delivery_notification,
            opt(&self.ticket),
            opt(&self.distro_transfer_key),
            opt(&self.sent_to),
            opt(&self.sent_by),
            self.display_name.state_byte(),
            self.display_name.name().map(json_string).unwrap_or_else(|| "null".into()),
            self.signature_validated,
            self.unverified_reason.unwrap_or(0),
            // Base64 needs no JSON escaping.
            self.fields.as_deref().map(|f| format!("\"{}\"", STANDARD.encode(f))).unwrap_or_else(|| "null".into()),
        )
    }
}

/// A JSON string literal (the escaping both bridges used before this moved here).
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

const FIELD_TICKET: u64 = 0x0C;
const FIELD_FILE_ATTACHMENTS: u64 = crate::lxmf::FIELD_FILE_ATTACHMENTS as u64;
const FIELD_IMAGE: u64 = crate::lxmf::FIELD_IMAGE as u64;
const FIELD_AUDIO: u64 = crate::lxmf::FIELD_AUDIO as u64;
/// LXMF/LXMF.py FIELD_CUSTOM_TYPE / FIELD_CUSTOM_DATA: upstream's pair for
/// application payloads — a format identifier and the payload. Until
/// 2026-09-24 the transfer used field 0x0D, which LXMF 1.1.1 defines as
/// FIELD_EVENT.
pub const FIELD_CUSTOM_TYPE: u64 = 0xFB;
pub const FIELD_CUSTOM_DATA: u64 = 0xFC;
/// LXMF/LXMF.py FIELD_CUSTOM_META: upstream's metadata slot beside the pair
/// above. The sent-message sync copy (RFed SPEC §17.11) carries the sending
/// device's address here.
pub const FIELD_CUSTOM_META: u64 = 0xFD;
/// The FIELD_CUSTOM_TYPE value of a distro identity transfer (RFed SPEC §17.9).
pub const DISTRO_TRANSFER_TYPE: &str = "rfed.distro.transfer";
/// The FIELD_CUSTOM_TYPE value of a sent-message sync copy (RFed SPEC §17.11):
/// a device that sent a message as the distro copies it to the distro itself
/// so every sibling device shows it as sent.
pub const DISTRO_SENT_TYPE: &str = "rfed.distro.sent";

fn encode(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = write_value(&mut buf, value);
    buf
}

/// `lxmf.delivery` destination hash for an identity.
pub fn delivery_hash(identity: &Identity) -> Result<Vec<u8>, String> {
    let hash = identity.hash.as_ref().ok_or("identity has no hash")?;
    Ok(Destination::hash(Some(hash), "lxmf", &["delivery"]))
}

/// Payload for `/rfed/distro/register` and `/rfed/distro/unregister`.
///
/// `msgpack [ bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey) ]`
///
/// The signature is made with the DISTRO key over the device's public key: that
/// is what proves the caller owns the distro and may enrol a device under it.
pub fn register_payload(device: &Identity, distro: &Identity) -> Result<Vec<u8>, String> {
    let device_pubkey = device.get_public_key()?;
    let distro_pubkey = distro.get_public_key()?;
    if device_pubkey.len() != PUBKEY_LEN || distro_pubkey.len() != PUBKEY_LEN {
        return Err("public keys must be 64 bytes".into());
    }
    let sig = distro.sign(&device_pubkey);

    Ok(encode(&Value::Array(vec![
        Value::Binary(device_pubkey),
        Value::Binary(distro_pubkey),
        Value::Binary(sig),
    ])))
}

/// Payload for `/rfed/distro/list`.
///
/// `msgpack [ bin(16) distro_identity_hash, bin(64) distro_pubkey, bin(64) sig(distro_identity_hash) ]`
pub fn list_payload(distro: &Identity) -> Result<Vec<u8>, String> {
    let distro_pubkey = distro.get_public_key()?;
    let identity_hash = distro.hash.clone().ok_or("distro identity has no hash")?;
    let sig = distro.sign(&identity_hash);

    Ok(encode(&Value::Array(vec![
        Value::Binary(identity_hash),
        Value::Binary(distro_pubkey),
        Value::Binary(sig),
    ])))
}

/// The app_data of a distro address's announce (RFed SPEC §17.10,
/// DISPLAY_NAMES.md §2.2): `[announce_name, nil, [SF_RFED_DISTRO]]`.
///
/// `announce_name` is the raw Announce Display Name; it is cleaned with the
/// announce rules (§3) and carried as bin, or nil when there is none (the
/// default: anonymous to other apps). No stamp cost and no compression claim.
/// `SF_RFED_DISTRO` in the functionality list is how every sender learns,
/// from the announce it needs anyway, that no device answers a direct link
/// to this address.
pub fn distro_announce_app_data(announce_name: Option<&[u8]>) -> Vec<u8> {
    let name = announce_name
        .and_then(display_name::clean_announce)
        .map(|n| Value::Binary(n.into_bytes()))
        .unwrap_or(Value::Nil);
    encode(&Value::Array(vec![
        name,
        Value::Nil,
        Value::Array(vec![Value::Integer(crate::lxmf::SF_RFED_DISTRO.into())]),
    ]))
}

/// `msgpack [ bin value, bin(64) distro_pubkey, bin(64) sig(value) ]`
/// where `value = flags(1) || announce_data` and bit 0 of `flags` signals a
/// ratchet.
///
/// RFed cannot mint this itself: it only ever learns the distro *public* key,
/// so it cannot sign an announce for the distro address. Without one, nobody
/// can resolve a path to the distro and the address is unreachable. The device
/// holding the private key signs it here and hands it over for rebroadcast.
///
/// The destination is built OUT-bound on purpose. An IN destination would make
/// this device claim inbound delivery for the distro address, which is exactly
/// what must not happen — delivery arrives fanned out on `rfed.delivery`.
///
/// `announce_name` is the raw Announce Display Name (see
/// `distro_announce_app_data`); `None` announces no name.
pub fn announce_payload(distro: &Identity, announce_name: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let app_data = distro_announce_app_data(announce_name);
    let mut destination = Destination::new_outbound(
        Some(distro.clone()),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )?;
    // announce() refuses anything but IN/SINGLE; flip the direction on the
    // local object only, after construction, so nothing is registered as an
    // inbound destination for the distro.
    destination.direction = Direction::IN;

    let packet = destination
        .announce(Some(&app_data), false, None, None, false)?
        .ok_or("announce did not produce a packet")?;
    let announce_data = packet.data.clone();

    let has_ratchet = destination.ratchets.as_ref().map_or(false, |r| !r.is_empty());
    let mut value = Vec::with_capacity(1 + announce_data.len());
    value.push(if has_ratchet { 0x01 } else { 0x00 });
    value.extend_from_slice(&announce_data);

    let distro_pubkey = distro.get_public_key()?;
    let sig = distro.sign(&value);

    Ok(encode(&Value::Array(vec![
        Value::Binary(value),
        Value::Binary(distro_pubkey),
        Value::Binary(sig),
    ])))
}

// ---------------------------------------------------------------------------
// RFed SPEC §17.13: the distro sync proof.
//
// A device's own uploads to its distro D (the §17.11 sent copy and the §17.12
// membership message) are sync, and RFed delivers them without a wake when
// the upload proves, with D's key, that it is one. The proof is a third
// element of the client's `lxmf.propagation` upload:
//
//     [ timebase f64, [ lxmf_data, ... ], { "rfed.distro.sync": [ claim, ... ] } ]
//     claim = [ bin(16) id, bin(64) distro_pubkey, bin(64) sig ]
//
// One implementation serves the sending device (seal_for_sync, sealed_upload)
// and RFed (decode_sync_extension, verify_sync_claim), so the two cannot
// drift. Golden vector: tests/distro_sync_vectors.json.
// ---------------------------------------------------------------------------

/// The key of the sync proof in the third element of the upload.
pub const DISTRO_SYNC_KEY: &str = "rfed.distro.sync";
/// The domain tag the signed bytes begin with: the same 16 ASCII bytes.
pub const DISTRO_SYNC_TAG: &[u8; 16] = b"rfed.distro.sync";
/// The version byte that follows the tag in the signed bytes.
pub const DISTRO_SYNC_VERSION: u8 = 0x01;
/// `tag(16) | version(1) | D_hash(16) | transient_id(32)`.
pub const DISTRO_SYNC_SIGNED_LEN: usize = 65;
/// A claim's `id`: `transient_id[0..16]`, RFed's `distro_message_id`.
pub const DISTRO_SYNC_ID_LEN: usize = 16;
/// `transient_id = SHA-256(sealed)`.
const TRANSIENT_ID_LEN: usize = 32;
/// The PN stamp that follows the sealed message in `lxmf_data`.
const STAMP_LEN: usize = crate::lx_stamper::STAMP_SIZE;

/// The bytes D signs for a sync proof (SPEC §17.13):
/// `"rfed.distro.sync" | 0x01 | D_hash | transient_id`, 65 bytes.
///
/// `transient_id = SHA-256(sealed)` commits to the destination and the
/// ciphertext, so a signature covers one exact sealed message. No other D
/// signature is 65 bytes that begin with this tag: the register and list
/// signatures cover 64 and 16 bytes, the announce value begins with a flags
/// byte, an RNS announce or LXMF signature begins with a destination hash,
/// and a packet proof covers 32 bytes.
pub fn sync_signed_bytes(d_hash: &[u8; DEST_HASH_LEN], transient_id: &[u8; TRANSIENT_ID_LEN]) -> [u8; DISTRO_SYNC_SIGNED_LEN] {
    let mut out = [0u8; DISTRO_SYNC_SIGNED_LEN];
    out[..16].copy_from_slice(DISTRO_SYNC_TAG);
    out[16] = DISTRO_SYNC_VERSION;
    out[17..17 + DEST_HASH_LEN].copy_from_slice(d_hash);
    out[17 + DEST_HASH_LEN..].copy_from_slice(transient_id);
    out
}

/// `transient_id = SHA-256(sealed)`: what the PN stamp is mined over, and
/// what a sync signature covers.
pub fn sync_transient_id(sealed: &[u8]) -> [u8; TRANSIENT_ID_LEN] {
    let mut out = [0u8; TRANSIENT_ID_LEN];
    out.copy_from_slice(&full_hash(sealed));
    out
}

/// A message sealed once, when it is owed (SPEC §17.13 "On the sending
/// device"). The device stores both with the owed entry, and every upload of
/// the entry carries these same bytes; only the stamp and the timebase are
/// made again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// `D_hash(16) | D.encrypt(packed[16..])`: LXMF's `lxmf_data` before the
    /// stamp, the bytes RFed stores.
    pub sealed: Vec<u8>,
    /// D's Ed25519 signature over `sync_signed_bytes(D_hash, SHA-256(sealed))`.
    pub sig: [u8; 64],
}

/// Seal a packed LXMF message for distro sync: encrypt it to D once and sign
/// the result with D's key (DISTRO-SYNC-PROOF-DESIGN.md §5.1).
///
/// `packed` is the message as `LXMessage::pack` leaves it, addressed to and
/// signed by D: `D_hash | src | signature | payload`. Fails, with nothing
/// made, when:
/// - `distro` has no private key (`Identity::sign` would panic on it);
/// - `packed` is too short to be an LXMF message, or is not addressed to D;
/// - the encryption fails, or the signature does not validate.
///
/// The caller then owes the entry without `sealed`, logs the failure as an
/// error, and builds it the legacy way.
pub fn seal_for_sync(distro: &Identity, packed: &[u8]) -> Result<Sealed, String> {
    if distro.get_private_key().is_err() {
        return Err("the distro identity has no private key: a sync proof needs D's signature".into());
    }
    if packed.len() <= DEST_HASH_LEN + LXMF_HEADER_LEN {
        return Err(format!(
            "a packed LXMF message is longer than {} bytes, this is {}",
            DEST_HASH_LEN + LXMF_HEADER_LEN,
            packed.len()
        ));
    }
    let d_hash: [u8; DEST_HASH_LEN] = delivery_hash(distro)?
        .try_into()
        .map_err(|_| "the distro's lxmf.delivery hash is not 16 bytes".to_string())?;
    if packed[..DEST_HASH_LEN] != d_hash {
        return Err("the packed message is not addressed to the distro".into());
    }

    // Encrypted once: every upload of this entry carries these bytes.
    let encrypted = distro.encrypt(&packed[DEST_HASH_LEN..])?;
    let mut sealed = Vec::with_capacity(DEST_HASH_LEN + encrypted.len());
    sealed.extend_from_slice(&d_hash);
    sealed.extend_from_slice(&encrypted);

    let signed = sync_signed_bytes(&d_hash, &sync_transient_id(&sealed));
    let sig = distro.sign(&signed);
    if !distro.validate(&sig, &signed) {
        return Err("the sync signature does not validate with the distro's own key".into());
    }
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| "the sync signature is not 64 bytes".to_string())?;
    Ok(Sealed { sealed, sig })
}

/// One claim of the sync proof: `[bin(16) id, bin(64) distro_pubkey, bin(64) sig]`.
/// It names no device: it marks one sealed message as D's own sync and
/// nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncClaim {
    /// `transient_id[0..16]` of the message the claim is for.
    pub id: [u8; DISTRO_SYNC_ID_LEN],
    /// D's public key: X25519(32) | Ed25519(32).
    pub distro_pubkey: [u8; 64],
    /// D's signature over `sync_signed_bytes(D_hash, transient_id)`.
    pub sig: [u8; 64],
}

impl SyncClaim {
    /// The claim for a sealed message, from what the device stored with the
    /// entry: `sealed`, D's public key and the sync signature.
    pub fn for_sealed(sealed: &[u8], distro_pubkey: &[u8], sig: &[u8]) -> Result<SyncClaim, String> {
        let distro_pubkey: [u8; 64] = distro_pubkey
            .try_into()
            .map_err(|_| format!("a distro public key is 64 bytes, this is {}", distro_pubkey.len()))?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| format!("a sync signature is 64 bytes, this is {}", sig.len()))?;
        let mut id = [0u8; DISTRO_SYNC_ID_LEN];
        id.copy_from_slice(&sync_transient_id(sealed)[..DISTRO_SYNC_ID_LEN]);
        Ok(SyncClaim { id, distro_pubkey, sig })
    }

    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Binary(self.id.to_vec()),
            Value::Binary(self.distro_pubkey.to_vec()),
            Value::Binary(self.sig.to_vec()),
        ])
    }

    /// Exactly `[bin16, bin64, bin64]` (reader rule 4), or `None`.
    fn from_value(value: &Value) -> Option<SyncClaim> {
        let Value::Array(items) = value else { return None };
        let [Value::Binary(id), Value::Binary(distro_pubkey), Value::Binary(sig)] = items.as_slice() else {
            return None;
        };
        Some(SyncClaim {
            id: id.as_slice().try_into().ok()?,
            distro_pubkey: distro_pubkey.as_slice().try_into().ok()?,
            sig: sig.as_slice().try_into().ok()?,
        })
    }
}

/// LXMF's two-element propagation upload, `msgpack [timebase f64, [bin lxmf_data]]`,
/// as `LXMessage` packs `propagation_packed` (LXMessage.py). Byte for byte
/// what the native bridges wrote by hand before this (retichat-jni and
/// retichat-ffi `distro_outbox::propagation_payload`): every value native
/// msgpack (CHECK_THESE_THINGS_FIRST §11).
pub fn propagation_payload(timebase: f64, lxmf_data: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::F64(timebase),
        Value::Array(vec![Value::Binary(lxmf_data.to_vec())]),
    ]))
}

/// The upload of one sealed message to `lxmf.propagation` (SPEC §17.13):
/// `lxmf_data = sealed | stamp`, where the stamp is the PN stamp mined over
/// `SHA-256(sealed)` at the node's cost.
///
/// With a claim, `[timebase, [lxmf_data], {"rfed.distro.sync": [claim]}]`,
/// built with rmpv so every value is native msgpack: bin for bytes, str for
/// the key, arrays and a map for the structure, nothing pre-encoded and
/// wrapped in bin. Without one, today's two-element envelope,
/// `propagation_payload`, byte for byte. The caller passes a claim only to
/// the `lxmf.propagation` destination of the RFed it registered D with:
/// LXMF ignores a Resource whose envelope is not exactly two elements
/// (DISTRO-SYNC-PROOF-DESIGN.md §5.4).
///
/// Fails when the stamp is not 32 bytes, or when the claim is not one RFed
/// would accept for this message (`verify_sync_claim`): a claim for another
/// message, a key that is not the destination's, or a bad signature.
pub fn sealed_upload(sealed: &[u8], stamp: &[u8], claim: Option<&SyncClaim>, timebase: f64) -> Result<Vec<u8>, String> {
    if sealed.len() <= DEST_HASH_LEN {
        return Err(format!("a sealed message is longer than {DEST_HASH_LEN} bytes, this is {}", sealed.len()));
    }
    if stamp.len() != STAMP_LEN {
        return Err(format!("a propagation stamp is {STAMP_LEN} bytes, this is {}", stamp.len()));
    }
    let mut lxmf_data = Vec::with_capacity(sealed.len() + stamp.len());
    lxmf_data.extend_from_slice(sealed);
    lxmf_data.extend_from_slice(stamp);

    let Some(claim) = claim else {
        return Ok(propagation_payload(timebase, &lxmf_data));
    };
    verify_sync_claim(claim, &sync_transient_id(sealed), sealed)
        .map_err(|reason| format!("the sync claim is not this message's: {reason}"))?;
    Ok(encode(&Value::Array(vec![
        Value::F64(timebase),
        Value::Array(vec![Value::Binary(lxmf_data)]),
        Value::Map(vec![(
            Value::String(DISTRO_SYNC_KEY.into()),
            Value::Array(vec![claim.to_value()]),
        )]),
    ])))
}

/// The claims of one upload, as RFed reads them (`decode_sync_extension`).
/// Counts only: nothing here is a string, so nothing a sender writes reaches
/// a log line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncClaims {
    /// Well-formed claims with an `id` no other claim shares, at most one per
    /// message of the upload.
    pub by_id: HashMap<[u8; DISTRO_SYNC_ID_LEN], SyncClaim>,
    /// Claims that are not exactly `[bin16, bin64, bin64]`.
    pub malformed: usize,
    /// Well-formed claims dropped because another claim has the same `id`
    /// (all of them, not all but one).
    pub duplicate: usize,
    /// 1 when the extension was ignored as a whole, else 0. RFed adds its own
    /// (a peer's batch that carries one).
    pub ignored: usize,
}

/// Read the third element of a client's `lxmf.propagation` upload with the
/// reader rules of DISTRO-SYNC-PROOF-DESIGN.md §4.1. `extension` is `data[2]`;
/// `n_messages` is the number of messages in `data[1]` (rule 1, the caller's).
///
/// 2. `extension` counts only as a map, and only its str key
///    `"rfed.distro.sync"` is read; other keys are ignored. A map that has
///    the key twice is ambiguous and is ignored as a whole.
/// 3. The claims value is ignored as a whole when it is not an array, is
///    empty, or has more elements than `n_messages`: then no claim is looked
///    at, so the work is bounded by the message count.
/// 4. A claim that is not exactly `[bin16, bin64, bin64]` is ignored and
///    counted malformed. Claims that share an `id` are all ignored and
///    counted duplicate.
/// 5. Nothing is logged here; the counts are for RFed's one summary line per
///    batch.
///
/// Every claim is counted once: `by_id.len() + malformed + duplicate` is the
/// number of claims unless the extension was ignored as a whole.
pub fn decode_sync_extension(extension: &Value, n_messages: usize) -> SyncClaims {
    let mut out = SyncClaims::default();
    let ignored = |mut out: SyncClaims| {
        out.ignored = 1;
        out
    };

    let Value::Map(entries) = extension else { return ignored(out) };
    let mut values = entries
        .iter()
        .filter(|(k, _)| matches!(k, Value::String(s) if s.as_bytes() == DISTRO_SYNC_KEY.as_bytes()))
        .map(|(_, v)| v);
    let (Some(claims), None) = (values.next(), values.next()) else { return ignored(out) };
    let Value::Array(claims) = claims else { return ignored(out) };
    if claims.is_empty() || claims.len() > n_messages {
        return ignored(out);
    }

    let mut shared: std::collections::HashSet<[u8; DISTRO_SYNC_ID_LEN]> = Default::default();
    for value in claims {
        let Some(claim) = SyncClaim::from_value(value) else {
            out.malformed += 1;
            continue;
        };
        if shared.contains(&claim.id) {
            out.duplicate += 1;
        } else if out.by_id.remove(&claim.id).is_some() {
            out.duplicate += 2;
            shared.insert(claim.id);
        } else {
            out.by_id.insert(claim.id, claim);
        }
    }
    out
}

/// RFed's check of one claim against the message it names (SPEC §17.13 "At
/// RFed"), run only for a message whose PN stamp is valid and whose
/// destination is a distro registered there.
///
/// `transient_id` and `lxmf_data` are what `lx_stamper::validate_pn_stamp`
/// returns for the message: `SHA-256(sealed)` and the stamp-free `sealed`.
/// The claim is accepted when:
/// - `id == transient_id[0..16]`;
/// - the `lxmf.delivery` hash of `distro_pubkey` is `lxmf_data[0..16]`, the
///   message's destination;
/// - `sig` is valid for `distro_pubkey` over
///   `sync_signed_bytes(lxmf_data[0..16], transient_id)`.
///
/// The refusal reason is a fixed string, for RFed's verdict line.
pub fn verify_sync_claim(claim: &SyncClaim, transient_id: &[u8], lxmf_data: &[u8]) -> Result<(), &'static str> {
    let transient_id: &[u8; TRANSIENT_ID_LEN] = transient_id
        .try_into()
        .map_err(|_| "transient id is not 32 bytes")?;
    let d_hash: &[u8; DEST_HASH_LEN] = lxmf_data
        .get(..DEST_HASH_LEN)
        .and_then(|d| d.try_into().ok())
        .ok_or("message shorter than a destination hash")?;
    if claim.id[..] != transient_id[..DISTRO_SYNC_ID_LEN] {
        return Err("id is not the message's");
    }
    // The identity hash is the truncated hash of the public key (as
    // `Identity` computes it), so a key that is not the destination's is
    // refused before any curve work.
    let identity_hash = truncated_hash(&claim.distro_pubkey);
    if Destination::hash(Some(&identity_hash), "lxmf", &["delivery"])[..] != d_hash[..] {
        return Err("distro key is not the message's destination");
    }
    let distro = Identity::from_public_key(&claim.distro_pubkey).map_err(|_| "distro key unusable")?;
    if !distro.validate(&claim.sig, &sync_signed_bytes(d_hash, transient_id)) {
        return Err("signature invalid");
    }
    Ok(())
}

/// Decrypt and parse a distro blob delivered on `rfed.delivery` or returned by
/// `/rfed/pull`.
///
/// `blob` is the LXMF propagation message: `dest_hash(16) || EC_encrypted(rest)`,
/// where the plaintext is `src_hash(16) || signature(64) || msgpack payload`.
///
/// Returns `Ok(None)` when the blob is addressed to a different distro — a node
/// may legitimately hand over blobs for an address this device does not hold.
/// Returns `Err` for a §17.11 sent-copy that claims the distro as its source
/// but is not signed by the distro key.
pub fn unwrap_blob(distro: &mut Identity, blob: &[u8]) -> Result<Option<DistroMessage>, String> {
    if blob.len() < DEST_HASH_LEN + LXMF_HEADER_LEN {
        return Err(format!("blob too short: {} bytes", blob.len()));
    }

    let expected = delivery_hash(distro)?;
    if blob[..DEST_HASH_LEN] != expected[..] {
        return Ok(None);
    }

    let plaintext = distro
        .decrypt(&blob[DEST_HASH_LEN..])
        .map_err(|e| format!("distro decrypt failed: {e}"))?;
    if plaintext.len() < LXMF_HEADER_LEN {
        return Err("decrypted blob shorter than the LXMF header".into());
    }

    let source_hash = plaintext[..DEST_HASH_LEN].to_vec();
    let payload = &plaintext[LXMF_HEADER_LEN..];

    let mut cur = Cursor::new(payload);
    let parsed = read_value(&mut cur).map_err(|e| format!("msgpack decode: {e}"))?;
    let arr = match parsed {
        Value::Array(a) if a.len() >= 3 => a,
        other => return Err(format!("expected an LXMF payload array, got {other:?}")),
    };

    let timestamp = arr[0].as_f64().unwrap_or(0.0);
    let title = value_to_string(&arr[1]);
    let content = value_to_string(&arr[2]);

    let (ticket, distro_transfer_key, (sent_to, sent_by)) = match arr.get(3) {
        Some(Value::Map(entries)) => {
            let ticket = entries
                .iter()
                .find(|(k, _)| k.as_u64() == Some(FIELD_TICKET))
                .map(|(_, v)| value_to_string(v));
            (ticket, transfer_key_from_fields(entries), sent_marker_from_fields(entries))
        }
        _ => (None, None, (None, None)),
    };
    let display_name = arr.get(3).map(display_name::decode_field).unwrap_or(NameField::Absent);
    let signature = &plaintext[DEST_HASH_LEN..LXMF_HEADER_LEN];

    // RFed SPEC §17.11 receive rule 2: a sync copy is filed as the user's
    // OWN sent message, so "source = D" must be proven by D's signature, not
    // taken from the plaintext — D's public key is announced, so anyone can
    // encrypt a message to D that claims source D. Rejecting it here, once,
    // covers both native clients (Android classifySentCopy and iOS
    // sentCopyDisposition only compare the claimed source); Retichat-js
    // _handleDistroBlob makes the same check and drops the copy. A marker
    // from any other source is left to the clients' "not our distro" check,
    // receive rule 1.
    if sent_by.is_some() && source_hash[..] == expected[..] {
        if !lxmf_signature_valid(distro, &expected, &source_hash, payload, &arr, signature) {
            return Err("§17.11 sent-copy claims the distro as source but fails the distro signature — dropped".into());
        }
    }

    // DISPLAY_NAMES.md §5.2: every message reports its signature, so the
    // client can decide whether to accept its 0xD1 — validated, source
    // unknown (no key for the source yet) or invalid. The distro's own
    // address is checked against the distro key this device holds.
    let signer = if source_hash[..] == expected[..] {
        Some(distro.clone())
    } else {
        Identity::recall(&source_hash)
    };
    let (signature_validated, unverified_reason) = match signer {
        Some(signer) if lxmf_signature_valid(&signer, &expected, &source_hash, payload, &arr, signature) => (true, None),
        Some(_) => (false, Some(LXMessage::SIGNATURE_INVALID)),
        None => (false, Some(LXMessage::SOURCE_UNKNOWN)),
    };

    // A ticket with no content is a delivery notification, which the apps
    // drop — unless the message carries an attachment: a photo sent without
    // a caption by a sender that includes a ticket is a message to show.
    let carries_attachment = matches!(arr.get(3), Some(Value::Map(entries)) if entries.iter().any(|(k, _)| {
        matches!(k.as_u64(), Some(FIELD_FILE_ATTACHMENTS | FIELD_IMAGE | FIELD_AUDIO))
    }));
    let is_delivery_notification = ticket.is_some() && content.is_empty() && !carries_attachment;
    let fields = fields_map_bytes(payload).map(<[u8]>::to_vec);

    Ok(Some(DistroMessage {
        source_hash,
        timestamp,
        title,
        content,
        is_delivery_notification,
        ticket,
        distro_transfer_key,
        sent_to,
        sent_by,
        display_name,
        signature_validated,
        unverified_reason,
        fields,
    }))
}

/// The fields map of an LXMF payload (element 3 of the payload array), as the
/// slice of `payload` the sender packed, or `None` when element 3 is absent
/// or not a map. Handing on the sender's bytes rather than re-encoding the
/// decoded map means the apps decode exactly what was sent (CHECK_THESE_
/// THINGS_FIRST §11: the map stays a native msgpack map, never wrapped in
/// bin). `read_value_ref` borrows strings and binaries from `payload`, so
/// finding the map's bounds does not copy the attachments in it.
fn fields_map_bytes(payload: &[u8]) -> Option<&[u8]> {
    let mut rd = payload;
    if rmp::decode::read_array_len(&mut rd).ok()? < 4 {
        return None;
    }
    for _ in 0..3 {
        read_value_ref(&mut rd).ok()?;
    }
    let start = payload.len() - rd.len();
    match read_value_ref(&mut rd).ok()? {
        rmpv::ValueRef::Map(_) => Some(&payload[start..payload.len() - rd.len()]),
        _ => None,
    }
}

/// RFed SPEC §17.9: the transferred distro key, when the message's
/// FIELD_CUSTOM_TYPE is `DISTRO_TRANSFER_TYPE`; the key travels in
/// FIELD_CUSTOM_DATA. Any other custom type, or the pre-2026-09-24 field
/// 0x0D, is not a transfer.
fn transfer_key_from_fields(entries: &[(Value, Value)]) -> Option<String> {
    let mut custom_type = None;
    let mut custom_data = None;
    for (k, v) in entries {
        match k.as_u64() {
            Some(FIELD_CUSTOM_TYPE) => custom_type = Some(value_to_string(v)),
            Some(FIELD_CUSTOM_DATA) => custom_data = Some(value_to_string(v)),
            _ => {}
        }
    }
    if custom_type.as_deref() == Some(DISTRO_TRANSFER_TYPE) { custom_data } else { None }
}

/// RFed SPEC §17.11: `(sent_to, sent_by)` of a sent-message sync copy, read
/// from the custom triple only when FIELD_CUSTOM_TYPE is `DISTRO_SENT_TYPE`.
/// `sent_to` (0xFC) must be exactly 32 hex characters after lowercasing or it
/// is `None`; `sent_by` (0xFD) is lowercased and is `Some` whenever the type
/// matches, so the marker's presence survives a malformed 0xFC and the client
/// can drop the copy with a log line instead of showing it as an ordinary
/// message from the distro.
fn sent_marker_from_fields(entries: &[(Value, Value)]) -> (Option<String>, Option<String>) {
    let mut custom_type = None;
    let mut custom_data = None;
    let mut custom_meta = None;
    for (k, v) in entries {
        match k.as_u64() {
            Some(FIELD_CUSTOM_TYPE) => custom_type = Some(value_to_string(v)),
            Some(FIELD_CUSTOM_DATA) => custom_data = Some(value_to_string(v)),
            Some(FIELD_CUSTOM_META) => custom_meta = Some(value_to_string(v)),
            _ => {}
        }
    }
    if custom_type.as_deref() != Some(DISTRO_SENT_TYPE) {
        return (None, None);
    }
    let sent_to = custom_data
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s.len() == DEST_HASH_LEN * 2 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let sent_by = Some(custom_meta.unwrap_or_default().to_ascii_lowercase());
    (sent_to, sent_by)
}

/// LXMF's signature check, as LXMF/LXMF.py `LXMessage.unpack_from_bytes`
/// does it: the signed part is `dest || src || packed_payload ||
/// full_hash(dest || src || packed_payload)`, where a payload carrying a stamp
/// (a 5th element) is re-packed without it and any other payload is hashed
/// as received.
fn lxmf_signature_valid(
    signer: &Identity,
    dest: &[u8],
    src: &[u8],
    packed_payload: &[u8],
    items: &[Value],
    signature: &[u8],
) -> bool {
    let restamped;
    let packed = if items.len() > 4 {
        restamped = encode(&Value::Array(items[..4].to_vec()));
        &restamped[..]
    } else {
        packed_payload
    };
    let mut hashed_part = Vec::with_capacity(dest.len() + src.len() + packed.len());
    hashed_part.extend_from_slice(dest);
    hashed_part.extend_from_slice(src);
    hashed_part.extend_from_slice(packed);
    let mut signed_part = hashed_part.clone();
    signed_part.extend_from_slice(&full_hash(&hashed_part));
    signer.validate(signature, &signed_part)
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::Binary(b) => String::from_utf8_lossy(b).into_owned(),
        Value::String(s) => s.as_str().unwrap_or_default().to_string(),
        Value::Nil => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity::new(true)
    }

    /// RFed SPEC §17.10 / DISPLAY_NAMES.md §2.2: the pre-signed announce is
    /// `[announce_name | nil, nil, [0xD0]]`.
    #[test]
    fn announce_app_data_carries_the_flag_and_the_announce_name() {
        use crate::lxmf::{distro_from_app_data, compression_support_from_app_data, stamp_cost_from_app_data};
        use crate::display_name::announce_name_from_app_data;
        let flag = Value::Array(vec![Value::Integer(crate::lxmf::SF_RFED_DISTRO.into())]);

        let bare = distro_announce_app_data(None);
        assert_eq!(bare, encode(&Value::Array(vec![Value::Nil, Value::Nil, flag.clone()])));
        assert!(distro_from_app_data(Some(&bare)));
        assert_eq!(compression_support_from_app_data(Some(&bare)), Some(false), "no compression claim");
        assert_eq!(announce_name_from_app_data(Some(&bare)), None);

        let named = distro_announce_app_data(Some(" Alice\u{202e} ".as_bytes()));
        assert_eq!(named, encode(&Value::Array(vec![Value::Binary(b"Alice".to_vec()), Value::Nil, flag.clone()])),
            "cleaned, as bin");
        assert!(distro_from_app_data(Some(&named)));
        assert_eq!(stamp_cost_from_app_data(Some(&named)), None);
        assert_eq!(announce_name_from_app_data(Some(&named)).as_deref(), Some("Alice"));

        for anonymous in [&b"Anonymous Peer"[..], b"", b"\x00", b"\xff"] {
            assert_eq!(distro_announce_app_data(Some(anonymous)), bare, "{anonymous:?} announces nil");
        }
    }

    #[test]
    fn announce_payload_carries_the_name() {
        let distro = identity();
        let payload = announce_payload(&distro, Some(b"Alice")).expect("build");
        let (value, _) = verify_like_rfed(&payload).expect("rfed would accept this");
        let app_data = encode(&Value::Array(vec![
            Value::Binary(b"Alice".to_vec()),
            Value::Nil,
            Value::Array(vec![Value::Integer(crate::lxmf::SF_RFED_DISTRO.into())]),
        ]));
        assert!(value.ends_with(&app_data), "the announce data ends with the app_data");
    }

    /// RFed SPEC §17.9: a transfer is FIELD_CUSTOM_TYPE == DISTRO_TRANSFER_TYPE
    /// with the key in FIELD_CUSTOM_DATA; a custom message of another type
    /// is not one, and field 0x0D is ignored.
    #[test]
    fn transfer_key_is_read_from_the_custom_pair_only() {
        let key_hex = "ab".repeat(64);
        let mut fields = vec![
            (Value::Integer(FIELD_CUSTOM_TYPE.into()), Value::String(DISTRO_TRANSFER_TYPE.into())),
            (Value::Integer(FIELD_CUSTOM_DATA.into()), Value::String(key_hex.clone().into())),
        ];
        assert_eq!(transfer_key_from_fields(&fields).as_deref(), Some(key_hex.as_str()));
        fields[0].1 = Value::String("something.else".into());
        assert_eq!(transfer_key_from_fields(&fields), None);
        let legacy = vec![(Value::Integer(0x0D.into()), Value::String(key_hex.clone().into()))];
        assert_eq!(transfer_key_from_fields(&legacy), None);
    }

    /// RFed SPEC §17.11: a sync copy is FIELD_CUSTOM_TYPE == DISTRO_SENT_TYPE
    /// with R in FIELD_CUSTOM_DATA and the sending device in FIELD_CUSTOM_META.
    #[test]
    fn sent_marker_with_valid_recipient_and_sender() {
        let fields = vec![
            (Value::Integer(FIELD_CUSTOM_TYPE.into()), Value::String(DISTRO_SENT_TYPE.into())),
            (Value::Integer(FIELD_CUSTOM_DATA.into()), Value::String("AB".repeat(16).into())),
            (Value::Integer(FIELD_CUSTOM_META.into()), Value::String("CD".repeat(16).into())),
        ];
        let (to, by) = sent_marker_from_fields(&fields);
        assert_eq!(to.as_deref(), Some("ab".repeat(16).as_str()), "lowercased");
        assert_eq!(by.as_deref(), Some("cd".repeat(16).as_str()), "lowercased");
        assert_eq!(transfer_key_from_fields(&fields), None, "a sync copy is not a transfer");
    }

    /// RFed SPEC §17.11: a malformed 0xFC yields no recipient, but sent_by
    /// stays Some so the client still sees the marker and drops the copy.
    #[test]
    fn sent_marker_with_bad_recipient_has_no_sent_to() {
        for bad in ["ab".repeat(15), "ab".repeat(17), "zz".repeat(16), String::new()] {
            let fields = vec![
                (Value::Integer(FIELD_CUSTOM_TYPE.into()), Value::String(DISTRO_SENT_TYPE.into())),
                (Value::Integer(FIELD_CUSTOM_DATA.into()), Value::String(bad.clone().into())),
                (Value::Integer(FIELD_CUSTOM_META.into()), Value::String("cd".repeat(16).into())),
            ];
            let (to, by) = sent_marker_from_fields(&fields);
            assert_eq!(to, None, "0xFC {bad:?} must be rejected");
            assert_eq!(by.as_deref(), Some("cd".repeat(16).as_str()));
        }
        let no_data = vec![(Value::Integer(FIELD_CUSTOM_TYPE.into()), Value::String(DISTRO_SENT_TYPE.into()))];
        assert_eq!(sent_marker_from_fields(&no_data), (None, Some(String::new())));
    }

    /// RFed SPEC §17.9 / §17.11: a transfer's 0xFC is a key, never a recipient.
    #[test]
    fn transfer_type_does_not_set_sent_to() {
        let fields = vec![
            (Value::Integer(FIELD_CUSTOM_TYPE.into()), Value::String(DISTRO_TRANSFER_TYPE.into())),
            (Value::Integer(FIELD_CUSTOM_DATA.into()), Value::String("ab".repeat(16).into())),
            (Value::Integer(FIELD_CUSTOM_META.into()), Value::String("cd".repeat(16).into())),
        ];
        assert_eq!(sent_marker_from_fields(&fields), (None, None));
    }

    #[test]
    fn no_fields_means_no_sent_marker() {
        assert_eq!(sent_marker_from_fields(&[]), (None, None));
    }

    /// Mirrors rfed's verify_signed_payload: decode the triple, check the
    /// lengths, and validate the signature over payload[0] with payload[1].
    fn verify_like_rfed(payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut cur = Cursor::new(payload);
        let top = read_value(&mut cur).map_err(|e| e.to_string())?;
        let arr = match top {
            Value::Array(a) if a.len() == 3 => a,
            other => return Err(format!("expected fixarray-3, got {other:?}")),
        };
        let value = match &arr[0] {
            Value::Binary(b) => b.clone(),
            other => return Err(format!("payload[0] not bin: {other:?}")),
        };
        let pubkey = match &arr[1] {
            Value::Binary(b) => b.clone(),
            _ => return Err("payload[1] not bin".into()),
        };
        let sig = match &arr[2] {
            Value::Binary(b) => b.clone(),
            _ => return Err("payload[2] not bin".into()),
        };
        if pubkey.len() != 64 { return Err(format!("pubkey len {}", pubkey.len())); }
        if sig.len() != 64 { return Err(format!("sig len {}", sig.len())); }

        let id = Identity::from_public_key(&pubkey).map_err(|e| e.to_string())?;
        if !id.validate(&sig, &value) {
            return Err("signature verification failed".into());
        }
        Ok((value, pubkey))
    }

    #[test]
    fn register_payload_verifies_the_way_rfed_verifies_it() {
        let device = identity();
        let distro = identity();
        let payload = register_payload(&device, &distro).expect("build");

        let (value, pubkey) = verify_like_rfed(&payload).expect("rfed would accept this");
        assert_eq!(value, device.get_public_key().unwrap(),
            "payload[0] must be the DEVICE public key");
        assert_eq!(pubkey, distro.get_public_key().unwrap(),
            "payload[1] must be the DISTRO public key — it is what signs");
    }

    #[test]
    fn list_payload_verifies_the_way_rfed_verifies_it() {
        let distro = identity();
        let payload = list_payload(&distro).expect("build");

        let (value, pubkey) = verify_like_rfed(&payload).expect("rfed would accept this");
        assert_eq!(value, distro.hash.clone().unwrap(), "payload[0] is the distro identity hash");
        assert_eq!(value.len(), 16);
        assert_eq!(pubkey, distro.get_public_key().unwrap());
    }

    #[test]
    fn a_payload_signed_by_the_wrong_key_is_rejected() {
        // Signing with the device key instead of the distro key would let
        // anyone enrol themselves under someone else's distro.
        let device = identity();
        let distro = identity();
        let device_pubkey = device.get_public_key().unwrap();
        let forged = encode(&Value::Array(vec![
            Value::Binary(device_pubkey),
            Value::Binary(distro.get_public_key().unwrap()),
            Value::Binary(device.sign(&device.get_public_key().unwrap())),
        ]));
        assert!(verify_like_rfed(&forged).is_err(), "rfed must reject a mis-signed payload");
    }

    #[test]
    fn announce_payload_carries_a_flag_byte_then_announce_data() {
        let distro = identity();
        let payload = announce_payload(&distro, None).expect("build");

        let (value, pubkey) = verify_like_rfed(&payload).expect("rfed would accept this");
        assert_eq!(pubkey, distro.get_public_key().unwrap());
        assert!(!value.is_empty(), "value is flags(1) || announce_data");
        assert_eq!(value[0] & 0x01, 0, "a fresh identity has no ratchet");
        assert!(value.len() > 1 + 64, "announce data must follow the flag byte");
    }

    #[test]
    fn delivery_hash_is_the_lxmf_delivery_destination() {
        let distro = identity();
        let hash = delivery_hash(&distro).unwrap();
        assert_eq!(hash.len(), 16);
        assert_eq!(
            hash,
            Destination::hash(Some(&distro.hash.clone().unwrap()), "lxmf", &["delivery"]),
            "senders address this hash; the identity hash routes nowhere",
        );
    }

    /// A propagated LXMF blob to `distro`, as a sender builds it: `dest ||
    /// encrypt(src || sig || payload)`, signed by `signer` over LXMF's signed
    /// part. `stamp` adds a 5th payload element, which LXMF excludes from the
    /// signature.
    fn lxmf_blob(distro: &Identity, src: &[u8], signer: &Identity, fields: Vec<(Value, Value)>, stamp: bool) -> Vec<u8> {
        lxmf_blob_with_content(distro, src, signer, b"hello R", fields, stamp)
    }

    fn lxmf_blob_with_content(
        distro: &Identity,
        src: &[u8],
        signer: &Identity,
        content: &[u8],
        fields: Vec<(Value, Value)>,
        stamp: bool,
    ) -> Vec<u8> {
        let dest = delivery_hash(distro).unwrap();
        let mut items = vec![
            Value::F64(1_790_000_000.5),
            Value::Binary(Vec::new()),
            Value::Binary(content.to_vec()),
            Value::Map(fields),
        ];
        let mut hashed_part = [dest.clone(), src.to_vec(), encode(&Value::Array(items.clone()))].concat();
        let hash = full_hash(&hashed_part);
        hashed_part.extend_from_slice(&hash);
        let sig = signer.sign(&hashed_part);
        if stamp {
            items.push(Value::Binary(vec![7u8; 32]));
        }
        let plaintext = [src.to_vec(), sig, encode(&Value::Array(items))].concat();
        [dest, distro.encrypt(&plaintext).unwrap()].concat()
    }

    /// A propagated LXMF blob whose payload the test packed by hand, so it
    /// can be packed in ways rmpv would not (a non-minimal header, no fields
    /// map). Unstamped: LXMF signs the payload as received.
    fn lxmf_blob_packed(distro: &Identity, src: &[u8], signer: &Identity, packed_payload: &[u8]) -> Vec<u8> {
        let dest = delivery_hash(distro).unwrap();
        let mut hashed_part = [dest.clone(), src.to_vec(), packed_payload.to_vec()].concat();
        let hash = full_hash(&hashed_part);
        hashed_part.extend_from_slice(&hash);
        let sig = signer.sign(&hashed_part);
        let plaintext = [src.to_vec(), sig, packed_payload.to_vec()].concat();
        [dest, distro.encrypt(&plaintext).unwrap()].concat()
    }

    /// The first three payload elements (timestamp, title, content), packed
    /// after an array header of `len` elements.
    fn packed_head(len: u8, content: &[u8]) -> Vec<u8> {
        [
            vec![0x90 | len],
            encode(&Value::F64(1_790_000_000.5)),
            encode(&Value::Binary(Vec::new())),
            encode(&Value::Binary(content.to_vec())),
        ]
        .concat()
    }

    /// What an app reads from the unwrap JSON's `fields`: base64 (standard
    /// alphabet, padded) → msgpack → one value. `None` for null. The key
    /// must be present either way.
    fn json_fields(json: &str) -> Option<Value> {
        let parsed: serde_json::Value = serde_json::from_str(json).expect("the unwrap JSON parses");
        match parsed.get("fields").expect("the fields key is always present") {
            serde_json::Value::Null => None,
            serde_json::Value::String(b64) => {
                let bytes = STANDARD.decode(b64).expect("standard padded base64");
                let mut cur = Cursor::new(&bytes[..]);
                let value = read_value(&mut cur).expect("msgpack");
                assert_eq!(cur.position() as usize, bytes.len(), "exactly one msgpack value, nothing after it");
                Some(value)
            }
            other => panic!("fields must be a string or null, got {other:?}"),
        }
    }

    /// FIELD_FILE_ATTACHMENTS `[[filename, bytes]]` and FIELD_IMAGE
    /// `[format, bytes]`, as LXMF/LXMF.py senders pack them.
    fn attachment_fields() -> Vec<(Value, Value)> {
        vec![
            (
                Value::from(crate::lxmf::FIELD_FILE_ATTACHMENTS),
                Value::Array(vec![Value::Array(vec![
                    Value::String("notes.txt".into()),
                    Value::Binary(b"file bytes\n".to_vec()),
                ])]),
            ),
            (
                Value::from(crate::lxmf::FIELD_IMAGE),
                Value::Array(vec![
                    Value::String("webp".into()),
                    Value::Binary((0..=255u8).cycle().take(3000).collect()),
                ]),
            ),
        ]
    }

    /// The 2026-09-29 bug: a photo sent from the Pixel to the iPad's distro
    /// address arrived as its caption only, because the unwrap dropped the
    /// fields. The fields map must reach the JSON both bridges return, every
    /// entry intact, stamped or not.
    #[test]
    fn unwrap_hands_the_attachments_to_the_apps() {
        let mut distro = identity();
        let sender = identity();
        let s = delivery_hash(&sender).unwrap();
        for stamp in [false, true] {
            let blob = lxmf_blob(&distro, &s, &sender, attachment_fields(), stamp);
            let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
            assert_eq!(
                msg.fields.as_deref(),
                Some(&encode(&Value::Map(attachment_fields()))[..]),
                "the fields map as the sender packed it (stamp {stamp})"
            );
            assert_eq!(json_fields(&msg.to_json()), Some(Value::Map(attachment_fields())), "stamp {stamp}");
            assert_eq!(msg.content, "hello R", "the caption as before");
            assert!(!msg.is_delivery_notification);
        }
    }

    /// The bytes handed on are the sender's, not a re-encoding of what was
    /// decoded: a map16 header on a one-entry map and a str8 format name
    /// survive, where rmpv would write a fixmap and a fixstr.
    #[test]
    fn unwrap_hands_on_the_fields_bytes_the_sender_packed() {
        let mut distro = identity();
        let sender = identity();
        let s = delivery_hash(&sender).unwrap();
        let mut fields_raw = vec![0xde, 0x00, 0x01, 0x06, 0x92, 0xd9, 0x04];
        fields_raw.extend_from_slice(b"webp");
        fields_raw.extend_from_slice(&[0xc4, 0x03, 1, 2, 3]);
        let decoded = Value::Map(vec![(
            Value::from(crate::lxmf::FIELD_IMAGE),
            Value::Array(vec![Value::String("webp".into()), Value::Binary(vec![1, 2, 3])]),
        )]);
        assert_ne!(encode(&decoded), fields_raw, "the test needs bytes rmpv would not produce");

        let payload = [packed_head(4, b""), fields_raw.clone()].concat();
        let blob = lxmf_blob_packed(&distro, &s, &sender, &payload);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert_eq!(msg.fields.as_deref(), Some(&fields_raw[..]));
        assert_eq!(json_fields(&msg.to_json()), Some(decoded));
    }

    /// A message without attachments hands on whatever fields map it has —
    /// the 0xD1 name alone, or an empty map — and a payload without a map in
    /// element 3 gives null.
    #[test]
    fn unwrap_without_attachments_hands_on_the_map_it_has() {
        let mut distro = identity();
        let sender = identity();
        let s = delivery_hash(&sender).unwrap();

        let named = name_fields(Value::Binary(b"Bob".to_vec()));
        let blob = lxmf_blob(&distro, &s, &sender, named.clone(), false);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert_eq!(msg.fields.as_deref(), Some(&encode(&Value::Map(named.clone()))[..]));
        assert_eq!(json_fields(&msg.to_json()), Some(Value::Map(named)));
        assert_eq!(msg.content, "hello R");

        let blob = lxmf_blob(&distro, &s, &sender, Vec::new(), false);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert_eq!(msg.fields.as_deref(), Some(&[0x80u8][..]), "an empty map is a map");
        assert!(msg.to_json().ends_with(r#","fields":"gA=="}"#));

        let three = packed_head(3, b"no map");
        let blob = lxmf_blob_packed(&distro, &s, &sender, &three);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert_eq!((msg.content.as_str(), msg.fields.as_deref()), ("no map", None));
        assert_eq!(json_fields(&msg.to_json()), None);

        let nil = [packed_head(4, b"nil map"), vec![0xc0]].concat();
        let blob = lxmf_blob_packed(&distro, &s, &sender, &nil);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert_eq!((msg.content.as_str(), msg.fields.as_deref()), ("nil map", None));
        assert!(msg.to_json().ends_with(r#","fields":null}"#));
    }

    /// A delivery notification (a ticket and no content) is still flagged as
    /// one, and its fields carry the ticket.
    #[test]
    fn a_delivery_notification_hands_on_its_ticket_field() {
        let mut distro = identity();
        let sender = identity();
        let s = delivery_hash(&sender).unwrap();
        let ticket = vec![(
            Value::from(crate::lxmf::FIELD_TICKET),
            Value::Array(vec![Value::F64(1_792_000_000.0), Value::Binary(vec![9u8; 16])]),
        )];
        let blob = lxmf_blob_with_content(&distro, &s, &sender, b"", ticket.clone(), false);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert!(msg.is_delivery_notification);
        assert!(msg.ticket.is_some());
        assert_eq!(json_fields(&msg.to_json()), Some(Value::Map(ticket)));
    }

    /// The apps drop delivery notifications, so a captionless attachment from
    /// a sender that includes a ticket (LXMF `include_ticket`) must not be
    /// taken for one — for a file, an image or an audio message alike.
    #[test]
    fn a_captionless_attachment_with_a_ticket_is_a_message() {
        let mut distro = identity();
        let sender = identity();
        let s = delivery_hash(&sender).unwrap();
        let ticket = (
            Value::from(crate::lxmf::FIELD_TICKET),
            Value::Array(vec![Value::F64(1_792_000_000.0), Value::Binary(vec![9u8; 16])]),
        );
        let audio = (
            Value::from(crate::lxmf::FIELD_AUDIO),
            Value::Array(vec![Value::Integer(0x10.into()), Value::Binary(vec![5u8; 64])]),
        );
        for attachment in attachment_fields().into_iter().chain([audio]) {
            let fields = vec![ticket.clone(), attachment.clone()];
            let blob = lxmf_blob_with_content(&distro, &s, &sender, b"", fields.clone(), false);
            let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
            assert!(!msg.is_delivery_notification, "field {:?} is something to show", attachment.0);
            assert!(msg.ticket.is_some());
            assert_eq!(json_fields(&msg.to_json()), Some(Value::Map(fields)));
        }
    }

    fn sent_copy_fields() -> Vec<(Value, Value)> {
        vec![
            (Value::Integer(FIELD_CUSTOM_TYPE.into()), Value::String(DISTRO_SENT_TYPE.into())),
            (Value::Integer(FIELD_CUSTOM_DATA.into()), Value::String("ab".repeat(16).into())),
            (Value::Integer(FIELD_CUSTOM_META.into()), Value::String("cd".repeat(16).into())),
        ]
    }

    /// RFed SPEC §17.11: a copy signed by the distro key unwraps with its
    /// marker, stamped or not.
    #[test]
    fn a_distro_signed_sent_copy_is_accepted() {
        let mut distro = identity();
        let d = delivery_hash(&distro).unwrap();
        for stamp in [false, true] {
            let blob = lxmf_blob(&distro, &d, &distro, sent_copy_fields(), stamp);
            let msg = unwrap_blob(&mut distro, &blob).expect("genuine copy").expect("addressed to us");
            assert_eq!(msg.source_hash, d);
            assert_eq!(msg.sent_to.as_deref(), Some("ab".repeat(16).as_str()));
            assert_eq!(msg.sent_by.as_deref(), Some("cd".repeat(16).as_str()));
            assert_eq!(msg.content, "hello R");
        }
    }

    /// RFed SPEC §17.11 receive rule 2: anyone can encrypt to D's announced
    /// key and claim source D; without D's signature the copy must not reach
    /// a client that would file it as the user's own sent message.
    #[test]
    fn a_sent_copy_claiming_the_distro_without_its_signature_is_rejected() {
        let mut distro = identity();
        let d = delivery_hash(&distro).unwrap();
        let forger = identity();
        let blob = lxmf_blob(&distro, &d, &forger, sent_copy_fields(), false);
        let err = unwrap_blob(&mut distro, &blob).expect_err("forged copy must be rejected");
        assert!(err.contains("signature"), "{err}");
    }

    /// Only the marker triggers the check (a D-sourced message without it
    /// keeps today's behaviour), and a marker from another source is left to
    /// the clients' "not our distro" check (receive rule 1), which needs
    /// sent_by to see it.
    #[test]
    fn the_signature_check_applies_only_to_sent_copies_claiming_the_distro() {
        let mut distro = identity();
        let d = delivery_hash(&distro).unwrap();
        let other = identity();
        let plain = lxmf_blob(&distro, &d, &other, Vec::new(), false);
        let msg = unwrap_blob(&mut distro, &plain).unwrap().unwrap();
        assert_eq!((msg.sent_to, msg.sent_by), (None, None));

        let o = delivery_hash(&other).unwrap();
        let foreign = lxmf_blob(&distro, &o, &other, sent_copy_fields(), false);
        let msg = unwrap_blob(&mut distro, &foreign).unwrap().unwrap();
        assert_eq!(msg.source_hash, o);
        assert!(msg.sent_by.is_some(), "the client must still see the marker to ignore it");
    }

    fn name_fields(value: Value) -> Vec<(Value, Value)> {
        // {0xD1: {0: value}} (DISPLAY_NAMES.md §2.1).
        vec![(Value::from(crate::lxmf::FIELD_RETICHAT), Value::Map(vec![(Value::from(0), value)]))]
    }

    /// DISPLAY_NAMES.md §5.2: an ordinary message reports its 0xD1 and its
    /// signature: validated when the source's key is known and matches.
    #[test]
    fn unwrap_reports_the_name_and_a_validated_signature() {
        let mut distro = identity();
        let sender = identity();
        let s = delivery_hash(&sender).unwrap();
        Identity::remember_destination(&s, &sender.get_public_key().unwrap(), None).unwrap();
        for stamp in [false, true] {
            let blob = lxmf_blob(&distro, &s, &sender, name_fields(Value::Binary(b" Bob ".to_vec())), stamp);
            let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
            assert_eq!(msg.display_name, NameField::Name("Bob".into()));
            assert!(msg.signature_validated);
            assert_eq!(msg.unverified_reason, None);
        }
        let clear = lxmf_blob(&distro, &s, &sender, name_fields(Value::String("".into())), false);
        assert_eq!(unwrap_blob(&mut distro, &clear).unwrap().unwrap().display_name, NameField::Clear);
        let none = lxmf_blob(&distro, &s, &sender, Vec::new(), false);
        assert_eq!(unwrap_blob(&mut distro, &none).unwrap().unwrap().display_name, NameField::Absent);
    }

    #[test]
    fn unwrap_reports_an_invalid_signature() {
        let mut distro = identity();
        let sender = identity();
        let forger = identity();
        let s = delivery_hash(&sender).unwrap();
        Identity::remember_destination(&s, &sender.get_public_key().unwrap(), None).unwrap();
        let blob = lxmf_blob(&distro, &s, &forger, name_fields(Value::Binary(b"Bob".to_vec())), false);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert_eq!(msg.display_name, NameField::Name("Bob".into()), "decoded; the client ignores it");
        assert!(!msg.signature_validated);
        assert_eq!(msg.unverified_reason, Some(LXMessage::SIGNATURE_INVALID));
    }

    #[test]
    fn unwrap_reports_an_unknown_source() {
        let mut distro = identity();
        let stranger = identity();
        let s = delivery_hash(&stranger).unwrap();
        let blob = lxmf_blob(&distro, &s, &stranger, name_fields(Value::Binary(b"Bob".to_vec())), false);
        let msg = unwrap_blob(&mut distro, &blob).unwrap().unwrap();
        assert!(!msg.signature_validated);
        assert_eq!(msg.unverified_reason, Some(LXMessage::SOURCE_UNKNOWN));
        assert_eq!(msg.display_name, NameField::Name("Bob".into()));
    }

    /// The distro's own address is checked against the distro key held here.
    #[test]
    fn unwrap_validates_a_message_from_the_distro_itself() {
        let mut distro = identity();
        let d = delivery_hash(&distro).unwrap();
        let signed = lxmf_blob(&distro, &d, &distro.clone(), Vec::new(), false);
        let msg = unwrap_blob(&mut distro, &signed).unwrap().unwrap();
        assert!(msg.signature_validated);
        let forged = lxmf_blob(&distro, &d, &identity(), Vec::new(), false);
        let msg = unwrap_blob(&mut distro, &forged).unwrap().unwrap();
        assert_eq!(msg.unverified_reason, Some(LXMessage::SIGNATURE_INVALID));
    }

    #[test]
    fn unwrap_json_carries_the_name_and_signature_keys() {
        let msg = DistroMessage {
            source_hash: vec![0xab; 16],
            timestamp: 1.5,
            title: String::new(),
            content: "hi\n".into(),
            is_delivery_notification: false,
            ticket: None,
            distro_transfer_key: None,
            sent_to: Some("cd".repeat(16)),
            sent_by: None,
            display_name: NameField::Name("Bob \"B\"".into()),
            signature_validated: false,
            unverified_reason: Some(LXMessage::SOURCE_UNKNOWN),
            fields: None,
        };
        assert_eq!(
            msg.to_json(),
            format!(
                concat!(
                    r#"{{"source_hash":"{}","timestamp":1.5,"title":"","content":"hi\n","#,
                    r#""is_delivery_notification":false,"ticket":null,"distro_transfer_key":null,"#,
                    r#""sent_to":"{}","sent_by":null,"#,
                    r#""display_name_state":2,"display_name":"Bob \"B\"","signature_validated":false,"unverified_reason":1,"#,
                    r#""fields":null}}"#
                ),
                "ab".repeat(16),
                "cd".repeat(16)
            )
        );
        let validated = DistroMessage { display_name: NameField::Clear, signature_validated: true, unverified_reason: None, ..msg };
        assert!(validated.to_json().ends_with(r#""display_name_state":1,"display_name":null,"signature_validated":true,"unverified_reason":0,"fields":null}"#));
        // {0x06: ["png", bin fb ff]} = 81 06 92 a3 70 6e 67 c4 02 fb ff, whose
        // base64 has a '+', a '/' and a '='.
        let with_fields = DistroMessage {
            fields: Some(vec![0x81, 0x06, 0x92, 0xa3, b'p', b'n', b'g', 0xc4, 0x02, 0xfb, 0xff]),
            ..validated
        };
        assert!(with_fields.to_json().ends_with(r#""unverified_reason":0,"fields":"gQaSo3BuZ8QC+/8="}"#),
            "standard alphabet (+ and / not - and _), padded: {}", with_fields.to_json());
    }

    #[test]
    fn a_blob_for_another_distro_is_not_an_error() {
        let mut mine = identity();
        let theirs = identity();
        let mut blob = delivery_hash(&theirs).unwrap();
        blob.extend_from_slice(&[0u8; LXMF_HEADER_LEN + 16]);
        assert_eq!(unwrap_blob(&mut mine, &blob).unwrap(), None);
    }

    #[test]
    fn short_blobs_are_rejected() {
        let mut distro = identity();
        assert!(unwrap_blob(&mut distro, &[0u8; 8]).is_err());
    }
}

/// RFed SPEC §17.13, the distro sync proof (DISTRO-SYNC-PROOF-DESIGN.md
/// §13.1 "LXMF-rust"). The golden vector, made with the Python reference, is
/// checked by tests/distro_sync_vectors.rs.
#[cfg(test)]
mod sync_proof_tests {
    use super::*;
    use std::collections::HashSet;

    const STAMP: [u8; 32] = [7u8; 32];

    fn identity() -> Identity {
        Identity::new(true)
    }

    fn d_hash(distro: &Identity) -> [u8; 16] {
        delivery_hash(distro).unwrap().try_into().unwrap()
    }

    /// An LXMF message `signer` packs to `to`'s `lxmf.delivery`, as
    /// `LXMessage::pack` leaves it: dest | src | signature | payload. With
    /// `signer` = `to` = D it is a §17.11 sent copy.
    fn packed_by(signer: &Identity, to: &Identity, content: &[u8]) -> Vec<u8> {
        let dest = delivery_hash(to).unwrap();
        let src = delivery_hash(signer).unwrap();
        let payload = encode(&Value::Array(vec![
            Value::F64(1_790_000_000.5),
            Value::Binary(Vec::new()),
            Value::Binary(content.to_vec()),
            Value::Map(vec![
                (Value::Integer(FIELD_CUSTOM_TYPE.into()), Value::String(DISTRO_SENT_TYPE.into())),
                (Value::Integer(FIELD_CUSTOM_DATA.into()), Value::String("ab".repeat(16).into())),
                (Value::Integer(FIELD_CUSTOM_META.into()), Value::String("cd".repeat(16).into())),
            ]),
        ]));
        let mut hashed_part = [dest.clone(), src.clone(), payload.clone()].concat();
        let hash = full_hash(&hashed_part);
        hashed_part.extend_from_slice(&hash);
        let sig = signer.sign(&hashed_part);
        [dest, src, sig, payload].concat()
    }

    fn packed(distro: &Identity) -> Vec<u8> {
        packed_by(distro, distro, b"hello R")
    }

    fn claim_for(distro: &Identity, sealed: &Sealed) -> SyncClaim {
        SyncClaim::for_sealed(&sealed.sealed, &distro.get_public_key().unwrap(), &sealed.sig).unwrap()
    }

    fn sealed_message() -> (Identity, Sealed, [u8; 32]) {
        let distro = identity();
        let sealed = seal_for_sync(&distro, &packed(&distro)).expect("seal");
        let transient_id = sync_transient_id(&sealed.sealed);
        (distro, sealed, transient_id)
    }

    fn decode_upload(bytes: &[u8]) -> Vec<Value> {
        match read_value(&mut Cursor::new(bytes)).expect("msgpack") {
            Value::Array(items) => items,
            other => panic!("the upload is not an array: {other:?}"),
        }
    }

    // ---- the signed bytes ----

    #[test]
    fn the_signed_bytes_are_tag_version_destination_and_transient_id() {
        let d = [0x11u8; 16];
        let t = [0x22u8; 32];
        let signed = sync_signed_bytes(&d, &t);
        assert_eq!(signed.len(), 65);
        assert_eq!(
            signed[..16].iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "726665642e64697374726f2e73796e63",
            "the 16 ASCII bytes of \"rfed.distro.sync\""
        );
        assert_eq!(signed[16], 0x01, "version");
        assert_eq!(signed[17..33], d, "D_hash");
        assert_eq!(signed[33..], t, "transient_id");
        assert_eq!(DISTRO_SYNC_KEY.as_bytes(), DISTRO_SYNC_TAG, "the map key and the tag are the same text");
    }

    // ---- seal_for_sync ----

    #[test]
    fn seal_for_sync_encrypts_to_the_distro_once_and_signs_the_sealed_bytes() {
        let mut distro = identity();
        let packed = packed(&distro);
        let sealed = seal_for_sync(&distro, &packed).expect("seal");

        assert_eq!(sealed.sealed[..16], d_hash(&distro), "sealed[0..16] is D_hash");
        assert_eq!(distro.decrypt(&sealed.sealed[16..]).unwrap(), packed[16..], "D.encrypt(packed[16..])");

        let message = unwrap_blob(&mut distro, &sealed.sealed).unwrap().expect("a blob for this distro");
        assert!(message.signature_validated, "unwrap_blob validates the copy D signed");
        assert_eq!(message.content, "hello R");
        assert_eq!(message.sent_to.as_deref(), Some("ab".repeat(16).as_str()));

        let transient_id = sync_transient_id(&sealed.sealed);
        assert_eq!(transient_id.to_vec(), full_hash(&sealed.sealed), "transient_id = SHA-256(sealed)");
        let public = Identity::from_public_key(&distro.get_public_key().unwrap()).unwrap();
        assert!(
            public.validate(&sealed.sig, &sync_signed_bytes(&d_hash(&distro), &transient_id)),
            "the sig validates with D's public key alone"
        );
        assert_eq!(verify_sync_claim(&claim_for(&distro, &sealed), &transient_id, &sealed.sealed), Ok(()));
    }

    #[test]
    fn seal_for_sync_refuses_a_public_only_identity_without_panicking() {
        let distro = identity();
        let public = Identity::from_public_key(&distro.get_public_key().unwrap()).unwrap();
        let err = seal_for_sync(&public, &packed(&distro)).unwrap_err();
        assert!(err.contains("no private key"), "{err}");
    }

    #[test]
    fn seal_for_sync_refuses_a_message_not_addressed_to_the_distro() {
        let distro = identity();
        let other = identity();

        let to_other = packed_by(&distro, &other, b"hello");
        let err = seal_for_sync(&distro, &to_other).unwrap_err();
        assert!(err.contains("not addressed to the distro"), "{err}");

        let err = seal_for_sync(&other, &packed(&distro)).unwrap_err();
        assert!(err.contains("not addressed to the distro"), "a wrong D: {err}");

        let packed = packed(&distro);
        assert!(seal_for_sync(&distro, &packed[..DEST_HASH_LEN + LXMF_HEADER_LEN]).is_err(), "no payload");
        assert!(seal_for_sync(&distro, &[]).is_err());
    }

    #[test]
    fn every_upload_of_one_sealed_entry_carries_the_same_message() {
        // Each seal encrypts afresh, so the device seals once, when the entry
        // is owed, and stores the result: then two uploads differ only in the
        // stamp and the timebase, and RFed holds the second as the first.
        let distro = identity();
        let packed = packed(&distro);
        let a = seal_for_sync(&distro, &packed).unwrap();
        let b = seal_for_sync(&distro, &packed).unwrap();
        assert_ne!(a.sealed, b.sealed, "the encryption is random");

        let claim = claim_for(&distro, &a);
        for (stamp, timebase) in [([1u8; 32], 1.0), ([2u8; 32], 2.0)] {
            let items = decode_upload(&sealed_upload(&a.sealed, &stamp, Some(&claim), timebase).unwrap());
            assert_eq!(items[0], Value::F64(timebase));
            assert_eq!(items[1], Value::Array(vec![Value::Binary([a.sealed.clone(), stamp.to_vec()].concat())]));
            let claims = decode_sync_extension(&items[2], 1);
            assert_eq!(claims.by_id.get(&claim.id), Some(&claim));
            assert_eq!(claim.id[..], sync_transient_id(&a.sealed)[..16]);
        }
    }

    // ---- sealed_upload and the two-element envelope ----

    #[test]
    fn sealed_upload_with_a_claim_is_three_native_msgpack_elements() {
        let (distro, sealed, _) = sealed_message();
        let claim = claim_for(&distro, &sealed);
        let bytes = sealed_upload(&sealed.sealed, &STAMP, Some(&claim), 1_790_000_001.25).unwrap();
        assert_eq!(bytes[0], 0x93, "fixarray(3)");

        // The extension is the last 170 bytes (one claim is 151): a fixmap(1)
        // with the fixstr(16) key and a fixarray(1) of one fixarray(3) of bin,
        // nothing wrapped in bin.
        let mut extension = vec![0x81, 0xb0];
        extension.extend_from_slice(b"rfed.distro.sync");
        extension.extend_from_slice(&[0x91, 0x93, 0xc4, 0x10]);
        extension.extend_from_slice(&claim.id);
        extension.extend_from_slice(&[0xc4, 0x40]);
        extension.extend_from_slice(&claim.distro_pubkey);
        extension.extend_from_slice(&[0xc4, 0x40]);
        extension.extend_from_slice(&claim.sig);
        assert_eq!(extension.len(), 170);
        assert_eq!(encode(&claim.to_value()).len(), 151);
        assert_eq!(bytes[bytes.len() - 170..], extension[..]);

        // Before it, today's envelope under a fixarray(3) header.
        let legacy = sealed_upload(&sealed.sealed, &STAMP, None, 1_790_000_001.25).unwrap();
        assert_eq!(legacy[0], 0x92);
        assert_eq!(bytes[1..bytes.len() - 170], legacy[1..]);

        let items = decode_upload(&bytes);
        assert_eq!(items.len(), 3);
        assert!(matches!(&items[1], Value::Array(m) if m.len() == 1 && matches!(m[0], Value::Binary(_))));
        assert!(matches!(items[2], Value::Map(_)), "data[2] is a native map, never bin");
        let claims = decode_sync_extension(&items[2], 1);
        assert_eq!(claims.by_id.get(&claim.id), Some(&claim));
        assert_eq!((claims.malformed, claims.duplicate, claims.ignored), (0, 0, 0));
    }

    /// The native bridges' hand-written builder as it stood (retichat-jni and
    /// retichat-ffi `distro_outbox::propagation_payload`), the reference the
    /// rmpv builder must match byte for byte.
    fn bridges_propagation_payload(timestamp: f64, lxmf_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(lxmf_data.len() + 16);
        out.push(0x92);
        out.push(0xcb);
        out.extend_from_slice(&timestamp.to_bits().to_be_bytes());
        out.push(0x91);
        let len = lxmf_data.len();
        if len <= 0xff {
            out.extend_from_slice(&[0xc4, len as u8]);
        } else if len <= 0xffff {
            out.push(0xc5);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0xc6);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
        out.extend_from_slice(lxmf_data);
        out
    }

    #[test]
    fn the_two_element_envelope_is_byte_for_byte_the_bridges_one() {
        for len in [0usize, 1, 31, 255, 256, 431, 65_535, 65_536, 70_000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            for timebase in [0.0, 1_790_000_001.25, -1.5, f64::MAX, f64::MIN_POSITIVE] {
                assert_eq!(
                    propagation_payload(timebase, &data),
                    bridges_propagation_payload(timebase, &data),
                    "{len} bytes, timebase {timebase}"
                );
            }
        }
        let (_, sealed, _) = sealed_message();
        assert_eq!(
            sealed_upload(&sealed.sealed, &STAMP, None, 5.0).unwrap(),
            bridges_propagation_payload(5.0, &[sealed.sealed.clone(), STAMP.to_vec()].concat()),
            "without a claim, sealed_upload is today's envelope over sealed | stamp"
        );
    }

    #[test]
    fn sealed_upload_refuses_a_claim_rfed_would_refuse_and_a_bad_stamp() {
        let (distro, a, _) = sealed_message();
        let b = seal_for_sync(&distro, &packed(&distro)).unwrap();
        let good = claim_for(&distro, &a);

        let err = sealed_upload(&a.sealed, &STAMP, Some(&claim_for(&distro, &b)), 1.0).unwrap_err();
        assert!(err.contains("id is not the message's"), "another sealing's claim: {err}");

        let other = identity();
        let wrong_key = SyncClaim { distro_pubkey: other.get_public_key().unwrap().try_into().unwrap(), ..good.clone() };
        assert!(sealed_upload(&a.sealed, &STAMP, Some(&wrong_key), 1.0).is_err());

        let wrong_sig = SyncClaim { sig: b.sig, ..good.clone() };
        assert!(sealed_upload(&a.sealed, &STAMP, Some(&wrong_sig), 1.0).is_err());

        for stamp in [&[0u8; 31][..], &[0u8; 33][..], &[][..]] {
            assert!(sealed_upload(&a.sealed, stamp, None, 1.0).is_err(), "{} byte stamp", stamp.len());
            assert!(sealed_upload(&a.sealed, stamp, Some(&good), 1.0).is_err(), "{} byte stamp", stamp.len());
        }
        assert!(sealed_upload(&a.sealed[..16], &STAMP, None, 1.0).is_err(), "no ciphertext");
        assert!(sealed_upload(&a.sealed, &STAMP, Some(&good), 1.0).is_ok());
    }

    // ---- verify_sync_claim ----

    #[test]
    fn verify_sync_claim_accepts_only_d_signing_this_message() {
        let (distro, sealed, transient_id) = sealed_message();
        let good = claim_for(&distro, &sealed);
        let verify = |claim: &SyncClaim| verify_sync_claim(claim, &transient_id, &sealed.sealed);
        assert_eq!(verify(&good), Ok(()));

        let d = d_hash(&distro);
        let signed = sync_signed_bytes(&d, &transient_id);
        let sig = |s: Vec<u8>| -> [u8; 64] { s.try_into().unwrap() };

        // Another identity's key, signing correctly with its own key.
        let other = identity();
        let other_key = SyncClaim {
            distro_pubkey: other.get_public_key().unwrap().try_into().unwrap(),
            sig: sig(other.sign(&signed)),
            ..good.clone()
        };
        assert_eq!(verify(&other_key), Err("distro key is not the message's destination"));

        // D's signature over another transient id.
        let over_other = SyncClaim { sig: sig(distro.sign(&sync_signed_bytes(&d, &[0x5a; 32]))), ..good.clone() };
        assert_eq!(verify(&over_other), Err("signature invalid"));

        // D's signature without the tag, without the version, or another version.
        let no_tag = signed[16..].to_vec();
        let no_version = [&signed[..16], &signed[17..]].concat();
        let mut version_2 = signed;
        version_2[16] = 0x02;
        for (name, bytes) in [("no tag", no_tag), ("no version", no_version), ("version 2", version_2.to_vec())] {
            let claim = SyncClaim { sig: sig(distro.sign(&bytes)), ..good.clone() };
            assert_eq!(verify(&claim), Err("signature invalid"), "{name}");
        }

        // A device key's signature over the right bytes, naming D's key.
        let device = identity();
        assert_eq!(verify(&SyncClaim { sig: sig(device.sign(&signed)), ..good.clone() }), Err("signature invalid"));

        // D's register signature (over a device's public key) and list
        // signature (over D's identity hash).
        let register = sig(distro.sign(&device.get_public_key().unwrap()));
        assert_eq!(verify(&SyncClaim { sig: register, ..good.clone() }), Err("signature invalid"));
        let list = sig(distro.sign(distro.hash.as_ref().unwrap()));
        assert_eq!(verify(&SyncClaim { sig: list, ..good.clone() }), Err("signature invalid"));

        // An id that is not transient_id[0..16].
        let mut id = good.id;
        id[15] ^= 1;
        assert_eq!(verify(&SyncClaim { id, ..good.clone() }), Err("id is not the message's"));

        // The good claim against another sealing of the same packed message.
        let again = seal_for_sync(&distro, &packed(&distro)).unwrap();
        assert_eq!(
            verify_sync_claim(&good, &sync_transient_id(&again.sealed), &again.sealed),
            Err("id is not the message's")
        );

        // A key that is no key.
        assert!(verify(&SyncClaim { distro_pubkey: [0xff; 64], ..good.clone() }).is_err());

        // Inputs of the wrong length.
        assert_eq!(verify_sync_claim(&good, &transient_id[..31], &sealed.sealed), Err("transient id is not 32 bytes"));
        assert_eq!(
            verify_sync_claim(&good, &transient_id, &sealed.sealed[..15]),
            Err("message shorter than a destination hash")
        );
    }

    #[test]
    fn fields_of_63_or_65_bytes_never_become_a_claim() {
        // A claim's fields are fixed-size, so verify_sync_claim never sees one
        // of the wrong length: the reader counts it malformed, and the
        // sending side refuses to build it.
        let (distro, sealed, _) = sealed_message();
        let key = distro.get_public_key().unwrap();
        for n in [63usize, 65] {
            let key_n = if n == 63 { key[..63].to_vec() } else { [key.clone(), vec![0]].concat() };
            assert!(SyncClaim::for_sealed(&sealed.sealed, &key_n, &sealed.sig).is_err(), "{n} byte key");
            let sig_n = if n == 63 { sealed.sig[..63].to_vec() } else { [sealed.sig.to_vec(), vec![0]].concat() };
            assert!(SyncClaim::for_sealed(&sealed.sealed, &key, &sig_n).is_err(), "{n} byte sig");

            let bin = |len: usize| Value::Binary(vec![1u8; len]);
            let claims = Value::Array(vec![
                Value::Array(vec![bin(16), bin(n), bin(64)]),
                Value::Array(vec![bin(16), bin(64), bin(n)]),
            ]);
            let got = decode_sync_extension(&extension(claims), 2);
            assert_eq!((got.by_id.len(), got.malformed), (0, 2), "{n} byte fields");
        }
    }

    // ---- decode_sync_extension ----

    fn extension(claims: Value) -> Value {
        Value::Map(vec![(Value::String(DISTRO_SYNC_KEY.into()), claims)])
    }

    fn claim_value(id: u8) -> Value {
        Value::Array(vec![
            Value::Binary(vec![id; 16]),
            Value::Binary(vec![1u8; 64]),
            Value::Binary(vec![2u8; 64]),
        ])
    }

    fn claim_with(id: u8) -> SyncClaim {
        SyncClaim { id: [id; 16], distro_pubkey: [1u8; 64], sig: [2u8; 64] }
    }

    fn ignored_whole() -> SyncClaims {
        SyncClaims { ignored: 1, ..Default::default() }
    }

    #[test]
    fn an_extension_that_is_not_a_map_with_the_key_once_is_ignored_as_a_whole() {
        let one = Value::Array(vec![claim_value(1)]);
        let key = Value::String(DISTRO_SYNC_KEY.into());
        let cases = [
            ("nil", Value::Nil),
            ("an array", one.clone()),
            ("the map pre-encoded and wrapped in bin", Value::Binary(encode(&extension(one.clone())))),
            ("a str", Value::String(DISTRO_SYNC_KEY.into())),
            ("an integer", Value::Integer(1.into())),
            ("an empty map", Value::Map(Vec::new())),
            ("a map without the key", Value::Map(vec![(Value::String("rfed.distro.other".into()), one.clone())])),
            ("the key as bin", Value::Map(vec![(Value::Binary(DISTRO_SYNC_TAG.to_vec()), one.clone())])),
            ("the key twice", Value::Map(vec![(key.clone(), one.clone()), (key.clone(), one.clone())])),
        ];
        for (name, value) in cases {
            assert_eq!(decode_sync_extension(&value, 4), ignored_whole(), "{name}");
        }
    }

    #[test]
    fn claims_that_are_not_an_array_of_one_to_n_are_ignored_as_a_whole() {
        let cases = [
            ("a map", Value::Map(vec![(Value::Integer(0.into()), claim_value(1))]), 3),
            ("bin", Value::Binary(encode(&Value::Array(vec![claim_value(1)]))), 3),
            ("nil", Value::Nil, 3),
            ("an empty array", Value::Array(Vec::new()), 3),
            ("more claims than messages", Value::Array(vec![claim_value(1), claim_value(2)]), 1),
            ("a claim and no messages", Value::Array(vec![claim_value(1)]), 0),
        ];
        for (name, claims, n) in cases {
            assert_eq!(decode_sync_extension(&extension(claims), n), ignored_whole(), "{name}");
        }
        // A claim not wrapped in the claims array is an array of three
        // elements, none of them a claim.
        let bare = decode_sync_extension(&extension(claim_value(1)), 3);
        assert_eq!((bare.by_id.len(), bare.malformed, bare.duplicate, bare.ignored), (0, 3, 0, 0));
    }

    #[test]
    fn claims_are_bounded_by_the_message_count() {
        let claims = |m: u8| Value::Array((0..m).map(claim_value).collect());

        let at_n = decode_sync_extension(&extension(claims(5)), 5);
        assert_eq!(at_n.by_id.len(), 5, "M = N is read");
        assert_eq!((at_n.malformed, at_n.duplicate, at_n.ignored), (0, 0, 0));
        assert_eq!(decode_sync_extension(&extension(claims(4)), 5).by_id.len(), 4, "M < N is read");
        assert_eq!(decode_sync_extension(&extension(claims(6)), 5), ignored_whole(), "M = N + 1 is not");

        // 10^5 junk claims for one message: no claim is looked at, one count.
        let junk = Value::Array(vec![Value::Nil; 100_000]);
        assert_eq!(decode_sync_extension(&extension(junk.clone()), 1), ignored_whole());
        // Against as many messages, each is counted and none returned.
        let got = decode_sync_extension(&extension(junk), 100_000);
        assert_eq!((got.by_id.len(), got.malformed, got.duplicate, got.ignored), (0, 100_000, 0, 0));
    }

    #[test]
    fn malformed_claims_are_counted_and_skipped() {
        let bin = |n: usize| Value::Binary(vec![3u8; n]);
        let malformed = vec![
            Value::Nil,
            Value::Binary(encode(&claim_value(8))),
            Value::Array(Vec::new()),
            Value::Array(vec![bin(16), bin(64)]),
            Value::Array(vec![bin(16), bin(64), bin(64), bin(64)]),
            Value::Array(vec![bin(15), bin(64), bin(64)]),
            Value::Array(vec![bin(17), bin(64), bin(64)]),
            Value::Array(vec![bin(16), bin(63), bin(64)]),
            Value::Array(vec![bin(16), bin(65), bin(64)]),
            Value::Array(vec![bin(16), bin(64), bin(63)]),
            Value::Array(vec![bin(16), bin(64), bin(65)]),
            Value::Array(vec![Value::String("0123456789abcdef".into()), bin(64), bin(64)]),
            Value::Array(vec![bin(16), Value::Array(vec![Value::Integer(1.into()); 64]), bin(64)]),
            Value::Array(vec![bin(16), bin(64), Value::Nil]),
            Value::Map(vec![(bin(16), bin(64))]),
        ];
        let mut claims = malformed.clone();
        claims.insert(3, claim_value(9));
        let n = claims.len();
        let got = decode_sync_extension(&extension(Value::Array(claims)), n);
        assert_eq!(got.malformed, malformed.len());
        assert_eq!((got.duplicate, got.ignored), (0, 0));
        assert_eq!(got.by_id.len(), 1);
        assert_eq!(got.by_id[&[9u8; 16]], claim_with(9));
    }

    #[test]
    fn claims_that_share_an_id_are_all_dropped() {
        let mut other_key = claim_with(2);
        other_key.distro_pubkey = [5u8; 64];
        let claims = vec![
            claim_value(1),
            claim_value(2),
            claim_value(1),
            claim_value(3),
            other_key.to_value(),
            claim_value(2),
            // A malformed claim with id 3 is not a claim, so it shares nothing.
            Value::Array(vec![Value::Binary(vec![3u8; 16]), Value::Binary(vec![1u8; 63]), Value::Binary(vec![2u8; 64])]),
        ];
        let n = claims.len();
        let got = decode_sync_extension(&extension(Value::Array(claims)), n);
        assert_eq!(got.by_id.keys().copied().collect::<HashSet<_>>(), HashSet::from([[3u8; 16]]));
        assert_eq!(got.duplicate, 5, "both of id 1 and all three of id 2");
        assert_eq!(got.malformed, 1);
        assert_eq!(got.ignored, 0);
        assert_eq!(got.by_id.len() + got.malformed + got.duplicate, n, "every claim is counted once");
    }

    #[test]
    fn other_keys_and_their_order_do_not_matter() {
        let value = Value::Map(vec![
            (Value::String("rfed.other".into()), Value::Nil),
            (Value::Integer(1.into()), Value::Array(vec![claim_value(6)])),
            (Value::String(DISTRO_SYNC_KEY.into()), Value::Array(vec![claim_value(4)])),
            (Value::Binary(b"rfed.distro.sync".to_vec()), Value::Array(vec![claim_value(5)])),
        ]);
        let got = decode_sync_extension(&value, 1);
        assert_eq!(got.by_id.len(), 1);
        assert_eq!(got.by_id[&[4u8; 16]], claim_with(4));
        assert_eq!((got.malformed, got.duplicate, got.ignored), (0, 0, 0));
    }

    #[test]
    fn the_reader_returns_claims_and_counts_and_no_strings() {
        // Pins the shapes: no field carries text a sender wrote, so nothing a
        // sender puts in the extension can reach a log line.
        let SyncClaims { by_id, malformed, duplicate, ignored } = decode_sync_extension(&Value::Nil, 1);
        let _: (HashMap<[u8; 16], SyncClaim>, usize, usize, usize) = (by_id, malformed, duplicate, ignored);
        let SyncClaim { id, distro_pubkey, sig } = claim_with(1);
        let _: ([u8; 16], [u8; 64], [u8; 64]) = (id, distro_pubkey, sig);
    }

    // ---- RFed's path, end to end ----

    #[test]
    fn rfed_reads_a_proven_upload_and_refuses_a_strangers_claim() {
        // As RFed will: decode the batch, take data[2] as the extension,
        // validate the stamp, then look the claim up by transient_id[0..16].
        let rfed_verdict = |upload: &[u8]| -> Result<(), &'static str> {
            let items = decode_upload(upload);
            let Value::Array(messages) = &items[1] else { panic!("data[1]") };
            let claims = decode_sync_extension(&items[2], messages.len());
            let Value::Binary(lxmf_data) = &messages[0] else { panic!("bin") };
            let (transient_id, lxm_data, _, _) =
                crate::lx_stamper::validate_pn_stamp(lxmf_data, 0).expect("stamp valid at cost 0");
            let id: [u8; 16] = transient_id[..16].try_into().unwrap();
            let claim = claims.by_id.get(&id).ok_or("no claim")?;
            verify_sync_claim(claim, &transient_id, &lxm_data)
        };

        let (distro, sealed, _) = sealed_message();
        let own = sealed_upload(&sealed.sealed, &STAMP, Some(&claim_for(&distro, &sealed)), 1.0).unwrap();
        assert_eq!(rfed_verdict(&own), Ok(()));

        // A stranger's message to D, with a claim the stranger signed: it
        // cannot be built with sealed_upload, so it is written by hand.
        let stranger = identity();
        let packed = packed_by(&stranger, &distro, b"from a stranger");
        let mut theirs = d_hash(&distro).to_vec();
        theirs.extend_from_slice(&distro.encrypt(&packed[16..]).unwrap());
        let transient_id = sync_transient_id(&theirs);
        let forged = SyncClaim {
            id: transient_id[..16].try_into().unwrap(),
            distro_pubkey: stranger.get_public_key().unwrap().try_into().unwrap(),
            sig: stranger.sign(&sync_signed_bytes(&d_hash(&stranger), &transient_id)).try_into().unwrap(),
        };
        let upload = encode(&Value::Array(vec![
            Value::F64(1.0),
            Value::Array(vec![Value::Binary([theirs.clone(), STAMP.to_vec()].concat())]),
            extension(Value::Array(vec![forged.to_value()])),
        ]));
        assert_eq!(rfed_verdict(&upload), Err("distro key is not the message's destination"));
        assert!(sealed_upload(&theirs, &STAMP, Some(&forged), 1.0).is_err());
    }
}
