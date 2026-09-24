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
//! `parse_distro_announce_payload`; see RFed SPEC §17.5 and §17.9.

use std::io::Cursor;

use rmpv::decode::read_value;
use rmpv::encode::write_value;
use rmpv::Value;

use reticulum_rust::destination::{Destination, DestinationType, Direction};
use reticulum_rust::identity::Identity;

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
}

const FIELD_TICKET: u64 = 0x0C;
/// LXMF/LXMF.py FIELD_CUSTOM_TYPE / FIELD_CUSTOM_DATA: upstream's pair for
/// application payloads — a format identifier and the payload. Until
/// 2026-09-24 the transfer used field 0x0D, which LXMF 1.1.1 defines as
/// FIELD_EVENT.
pub const FIELD_CUSTOM_TYPE: u64 = 0xFB;
pub const FIELD_CUSTOM_DATA: u64 = 0xFC;
/// The FIELD_CUSTOM_TYPE value of a distro identity transfer (RFed SPEC §17.9).
pub const DISTRO_TRANSFER_TYPE: &str = "rfed.distro.transfer";

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

/// Payload for `/rfed/distro/announce`.
///
/// The app_data of a distro address's announce (RFed SPEC §17.10): the LXMF
/// 0.5.0+ list `[display_name, stamp_cost, supported_functionality]` with
/// `SF_RFED_DISTRO` in the functionality list, which is how every sender
/// learns, once and from the announce it needs anyway, that no device answers
/// a direct link to this address. With no caller data this is
/// `[nil, nil, [SF_RFED_DISTRO]]`: no name (names travel inside encrypted
/// messages), no stamp cost, no compression claim. Caller data in the list
/// format keeps its name and cost and gains the flag; anything else is
/// replaced, since a raw-format announce cannot carry it.
pub fn distro_announce_app_data(app_data: Option<&[u8]>) -> Vec<u8> {
    let flag = Value::Integer(crate::lxmf::SF_RFED_DISTRO.into());
    let mut items: Vec<Value> = match app_data.filter(|d| !d.is_empty()) {
        Some(data) => match read_value(&mut Cursor::new(data)) {
            Ok(Value::Array(items)) => items,
            _ => Vec::new(),
        },
        None => Vec::new(),
    };
    while items.len() < 3 {
        items.push(Value::Nil);
    }
    let flags = match items.get(2) {
        Some(Value::Array(existing)) => {
            let mut flags = existing.clone();
            if !flags.iter().any(|f| f.as_i64() == Some(crate::lxmf::SF_RFED_DISTRO)) {
                flags.push(flag);
            }
            flags
        }
        _ => vec![flag],
    };
    items[2] = Value::Array(flags);
    items.truncate(3);
    encode(&Value::Array(items))
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
pub fn announce_payload(distro: &Identity, app_data: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let app_data = distro_announce_app_data(app_data);
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

    let (ticket, distro_transfer_key) = match arr.get(3) {
        Some(Value::Map(entries)) => {
            let ticket = entries
                .iter()
                .find(|(k, _)| k.as_u64() == Some(FIELD_TICKET))
                .map(|(_, v)| value_to_string(v));
            (ticket, transfer_key_from_fields(entries))
        }
        _ => (None, None),
    };

    let is_delivery_notification = ticket.is_some() && content.is_empty();

    Ok(Some(DistroMessage {
        source_hash,
        timestamp,
        title,
        content,
        is_delivery_notification,
        ticket,
        distro_transfer_key,
    }))
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

    /// RFed SPEC §17.10: the pre-signed announce always carries the distro
    /// flag, whatever the caller supplied.
    #[test]
    fn announce_app_data_always_carries_the_distro_flag() {
        use crate::lxmf::{distro_from_app_data, compression_support_from_app_data, display_name_from_app_data, SF_COMPRESSION};
        let bare = distro_announce_app_data(None);
        assert!(distro_from_app_data(Some(&bare)));
        assert_eq!(compression_support_from_app_data(Some(&bare)), Some(false), "no compression claim");
        assert_eq!(display_name_from_app_data(Some(&bare)), None);

        let named = encode(&Value::Array(vec![
            Value::Binary(b"Alice".to_vec()),
            Value::Integer(8.into()),
            Value::Array(vec![Value::Integer(SF_COMPRESSION.into())]),
        ]));
        let merged = distro_announce_app_data(Some(&named));
        assert!(distro_from_app_data(Some(&merged)));
        assert_eq!(compression_support_from_app_data(Some(&merged)), Some(true), "existing flags kept");
        assert_eq!(display_name_from_app_data(Some(&merged)).as_deref(), Some("Alice"));
        assert_eq!(distro_announce_app_data(Some(&merged)), merged, "adding the flag twice changes nothing");

        let raw = distro_announce_app_data(Some(b"Alice"));
        assert!(distro_from_app_data(Some(&raw)), "the raw format is replaced");
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
