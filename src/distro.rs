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
//! sent-message sync marker read by `unwrap_blob` is RFed SPEC §17.11.

use std::io::Cursor;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rmpv::decode::{read_value, read_value_ref};
use rmpv::encode::write_value;
use rmpv::Value;

use reticulum_rust::destination::{Destination, DestinationType, Direction};
use reticulum_rust::identity::{full_hash, Identity};

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
    /// True when the message carries no content but does carry a ticket field,
    /// i.e. it is a delivery notification rather than something to display.
    /// Storing these produces empty message bubbles.
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

    let is_delivery_notification = ticket.is_some() && content.is_empty();
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
