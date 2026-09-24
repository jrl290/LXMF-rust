use std::io::Cursor;

use rmpv::Value;

pub const APP_NAME: &str = "lxmf";

pub const FIELD_EMBEDDED_LXMS: u8 = 0x01;
pub const FIELD_TELEMETRY: u8 = 0x02;
pub const FIELD_TELEMETRY_STREAM: u8 = 0x03;
pub const FIELD_ICON_APPEARANCE: u8 = 0x04;
pub const FIELD_FILE_ATTACHMENTS: u8 = 0x05;
pub const FIELD_IMAGE: u8 = 0x06;
pub const FIELD_AUDIO: u8 = 0x07;
pub const FIELD_THREAD: u8 = 0x08;
pub const FIELD_COMMANDS: u8 = 0x09;
pub const FIELD_RESULTS: u8 = 0x0A;
pub const FIELD_GROUP: u8 = 0x0B;
pub const FIELD_TICKET: u8 = 0x0C;
pub const FIELD_EVENT: u8 = 0x0D;
pub const FIELD_RNR_REFS: u8 = 0x0E;
pub const FIELD_RENDERER: u8 = 0x0F;
pub const FIELD_SENDER_NAME: u8 = 0x10;   // sender display name (UTF-8 bytes) — per-message, not broadcast

pub const FIELD_CUSTOM_TYPE: u8 = 0xFB;
pub const FIELD_CUSTOM_DATA: u8 = 0xFC;
pub const FIELD_CUSTOM_META: u8 = 0xFD;
pub const FIELD_NON_SPECIFIC: u8 = 0xFE;
pub const FIELD_DEBUG: u8 = 0xFF;

pub const AM_CODEC2_450PWB: u8 = 0x01;
pub const AM_CODEC2_450: u8 = 0x02;
pub const AM_CODEC2_700C: u8 = 0x03;
pub const AM_CODEC2_1200: u8 = 0x04;
pub const AM_CODEC2_1300: u8 = 0x05;
pub const AM_CODEC2_1400: u8 = 0x06;
pub const AM_CODEC2_1600: u8 = 0x07;
pub const AM_CODEC2_2400: u8 = 0x08;
pub const AM_CODEC2_3200: u8 = 0x09;

pub const AM_OPUS_OGG: u8 = 0x10;
pub const AM_OPUS_LBW: u8 = 0x11;
pub const AM_OPUS_MBW: u8 = 0x12;
pub const AM_OPUS_PTT: u8 = 0x13;
pub const AM_OPUS_RT_HDX: u8 = 0x14;
pub const AM_OPUS_RT_FDX: u8 = 0x15;
pub const AM_OPUS_STANDARD: u8 = 0x16;
pub const AM_OPUS_HQ: u8 = 0x17;
pub const AM_OPUS_BROADCAST: u8 = 0x18;
pub const AM_OPUS_LOSSLESS: u8 = 0x19;

pub const AM_CUSTOM: u8 = 0xFF;

pub const RENDERER_PLAIN: u8 = 0x00;
pub const RENDERER_MICRON: u8 = 0x01;
pub const RENDERER_MARKDOWN: u8 = 0x02;
pub const RENDERER_BBCODE: u8 = 0x03;

pub const PN_META_VERSION: u8 = 0x00;
pub const PN_META_NAME: u8 = 0x01;
pub const PN_META_SYNC_STRATUM: u8 = 0x02;
pub const PN_META_SYNC_THROTTLE: u8 = 0x03;
pub const PN_META_AUTH_BAND: u8 = 0x04;
pub const PN_META_UTIL_PRESSURE: u8 = 0x05;
pub const PN_META_CUSTOM: u8 = 0xFF;

pub fn display_name_from_app_data(app_data: Option<&[u8]>) -> Option<String> {
	let data = app_data?;
	if data.is_empty() {
		return None;
	}

	if is_msgpack_list(data) {
		if let Some(Value::Array(items)) = decode_msgpack_value(data) {
			if let Some(name_value) = items.get(0) {
				return value_to_utf8(name_value);
			}
		}
		None
	} else {
		String::from_utf8(data.to_vec()).ok()
	}
}

/// LXMF/LXMF.py `SF_COMPRESSION`: the supported-functionality flag for bz2
/// compressed Resources, carried as the third element of a 0.5.0+ announce.
pub const SF_COMPRESSION: i64 = 0x00;

/// RFed SPEC §17.10: the supported-functionality value a distro address puts
/// in its pre-signed `lxmf.delivery` announce. No device answers a direct
/// link to such an address; a sender that has seen this goes straight to the
/// propagation node. The list has no custom range, so the value sits far
/// above the ones upstream counts up from zero (0x00 so far) and outside the
/// one-byte range it would fill first.
pub const SF_RFED_DISTRO: i64 = 0xD0;

/// RFed SPEC §17.10: whether `app_data` is a distro address's announce —
/// a 0.5.0+ list whose third element is a list containing `SF_RFED_DISTRO`.
/// Anything else (no app_data, the original raw format, a short list, a
/// non-list third element) is not.
pub fn distro_from_app_data(app_data: Option<&[u8]>) -> bool {
	let data = match app_data {
		Some(d) if !d.is_empty() => d,
		_ => return false,
	};
	if !is_msgpack_list(data) {
		return false;
	}
	match decode_msgpack_value(data) {
		Some(Value::Array(items)) => match items.get(2) {
			Some(Value::Array(flags)) => flags.iter().any(|f| value_to_i64(f) == Some(SF_RFED_DISTRO)),
			_ => false,
		},
		_ => false,
	}
}

/// Whether `destination_hash` is a distro address, from its last announce.
/// Unknown destinations are not: a sender learns it once, from the announce
/// it needs anyway to encrypt to the address.
pub fn peer_is_distro(destination_hash: &[u8]) -> bool {
	let app_data = reticulum_rust::identity::Identity::recall_app_data(destination_hash);
	distro_from_app_data(app_data.as_deref())
}

/// LXMF/LXMF.py `compression_support_from_app_data()`: `None` for no
/// app_data; `true` for the original (non-msgpack) format or a list with
/// fewer than three elements or a non-list third element; otherwise whether
/// `SF_COMPRESSION` is in the third element. A sender compresses a Resource
/// only when this is not `Some(false)`.
pub fn compression_support_from_app_data(app_data: Option<&[u8]>) -> Option<bool> {
	let data = app_data?;
	if data.is_empty() {
		return None;
	}
	if is_msgpack_list(data) {
		if let Some(Value::Array(items)) = decode_msgpack_value(data) {
			return Some(match items.get(2) {
				Some(Value::Array(flags)) => flags.iter().any(|f| value_to_i64(f) == Some(SF_COMPRESSION)),
				_ => true,
			});
		}
		Some(true)
	} else {
		Some(true)
	}
}

/// Whether a Resource to `destination_hash` may be compressed: the peer's
/// last announce decides (LXMF/LXMessage.py determine_compression_support();
/// no announce means compression is assumed).
pub fn peer_accepts_compression(destination_hash: &[u8]) -> bool {
	let app_data = reticulum_rust::identity::Identity::recall_app_data(destination_hash);
	compression_support_from_app_data(app_data.as_deref()).unwrap_or(true)
}

pub fn stamp_cost_from_app_data(app_data: Option<&[u8]>) -> Option<i64> {
	let data = app_data?;
	if data.is_empty() {
		return None;
	}

	if is_msgpack_list(data) {
		if let Some(Value::Array(items)) = decode_msgpack_value(data) {
			return items.get(1).and_then(value_to_i64);
		}
		None
	} else {
		None
	}
}

/// Extract the sender's display name from LXMF message fields.
/// This is the preferred source — per-message, not broadcast.
/// Use this instead of `display_name_from_app_data` for privacy-preserving
/// name resolution.
pub fn sender_name_from_fields(fields: &Value) -> Option<String> {
	match fields {
		Value::Map(entries) => {
			for (key, value) in entries.iter() {
				if value_key_matches(key, FIELD_SENDER_NAME) {
					return value_to_utf8(value);
				}
			}
			None
		}
		_ => None,
	}
}

pub fn pn_name_from_app_data(app_data: Option<&[u8]>) -> Option<String> {
	let data = app_data?;
	if !pn_announce_data_is_valid(data) {
		return None;
	}

	let items = match decode_msgpack_value(data) {
		Some(Value::Array(items)) => items,
		_ => return None,
	};

	let metadata = match items.get(6) {
		Some(Value::Map(entries)) => entries,
		_ => return None,
	};

	for (key, value) in metadata.iter() {
		if value_key_matches(key, PN_META_NAME) {
			return value_to_utf8(value);
		}
	}

	None
}

pub fn pn_stamp_cost_from_app_data(app_data: Option<&[u8]>) -> Option<i64> {
	let data = app_data?;
	if !pn_announce_data_is_valid(data) {
		return None;
	}

	let items = match decode_msgpack_value(data) {
		Some(Value::Array(items)) => items,
		_ => return None,
	};

	let stamp_costs = match items.get(5) {
		Some(Value::Array(values)) => values,
		_ => return None,
	};

	stamp_costs.get(0).and_then(value_to_i64)
}

pub fn pn_announce_data_is_valid(data: &[u8]) -> bool {
	if data.is_empty() {
		return false;
	}

	let items = match decode_msgpack_value(data) {
		Some(Value::Array(items)) => items,
		_ => return false,
	};

	if items.len() < 7 {
		return false;
	}

	// items[1]: node timebase — must be an integer timestamp
	if value_to_i64(items.get(1).unwrap_or(&Value::Nil)).is_none() {
		return false;
	}

	// items[2]: propagation node state flag — must be boolean
	match items.get(2) {
		Some(Value::Boolean(_)) => {}
		_ => return false,
	}

	// items[3] and items[4]: per-transfer and per-sync limits.
	// Python LXMF sends these as float, int, or None depending on configuration.
	// We accept any numeric type or nil — we only need to confirm presence.
	match items.get(3) {
		Some(Value::Integer(_)) | Some(Value::F32(_)) | Some(Value::F64(_)) | Some(Value::Nil) | None => {}
		_ => return false,
	}
	match items.get(4) {
		Some(Value::Integer(_)) | Some(Value::F32(_)) | Some(Value::F64(_)) | Some(Value::Nil) | None => {}
		_ => return false,
	}

	// items[5]: stamp cost array. Only items[0] (the required stamp cost) needs to
	// be a valid integer. items[1] (flexibility) and items[2] (peering cost) may
	// be nil when the prop node hasn't configured them.
	let stamp_costs = match items.get(5) {
		Some(Value::Array(values)) => values,
		_ => return false,
	};

	if stamp_costs.is_empty() {
		return false;
	}

	if value_to_i64(&stamp_costs[0]).is_none() {
		return false;
	}

	matches!(items.get(6), Some(Value::Map(_)))
}

fn is_msgpack_list(data: &[u8]) -> bool {
	matches!(data.first(), Some(0x90..=0x9f) | Some(0xdc))
}

fn decode_msgpack_value(data: &[u8]) -> Option<Value> {
	let mut cursor = Cursor::new(data);
	rmpv::decode::read_value(&mut cursor).ok()
}

fn value_to_utf8(value: &Value) -> Option<String> {
	match value {
		Value::String(string) => string.as_str().map(|s| s.to_string()),
		Value::Binary(bytes) => String::from_utf8(bytes.clone()).ok(),
		_ => None,
	}
}

fn value_to_i64(value: &Value) -> Option<i64> {
	match value {
		Value::Integer(int) => int.as_i64().or_else(|| int.as_u64().map(|v| v as i64)),
		_ => None,
	}
}

fn value_key_matches(value: &Value, target: u8) -> bool {
	match value {
		Value::Integer(int) => int.as_u64().map(|v| v == target as u64).unwrap_or(false),
		_ => false,
	}
}

#[cfg(test)]
mod distro_flag_tests {
	use super::{distro_from_app_data, SF_COMPRESSION, SF_RFED_DISTRO};
	use rmpv::Value;

	fn pack(v: Value) -> Vec<u8> {
		let mut buf = Vec::new();
		rmpv::encode::write_value(&mut buf, &v).unwrap();
		buf
	}

	/// RFed SPEC §17.10: only the flag in the third element marks a distro.
	#[test]
	fn only_the_flag_marks_a_distro() {
		let distro = pack(Value::Array(vec![Value::Nil, Value::Nil, Value::Array(vec![Value::Integer(SF_RFED_DISTRO.into())])]));
		assert!(distro_from_app_data(Some(&distro)));
		let both = pack(Value::Array(vec![Value::Nil, Value::Nil, Value::Array(vec![Value::Integer(SF_COMPRESSION.into()), Value::Integer(SF_RFED_DISTRO.into())])]));
		assert!(distro_from_app_data(Some(&both)), "the flag may sit next to compression");
		let plain = pack(Value::Array(vec![Value::Nil, Value::Nil, Value::Array(vec![Value::Integer(SF_COMPRESSION.into())])]));
		assert!(!distro_from_app_data(Some(&plain)));
		let empty = pack(Value::Array(vec![Value::Nil, Value::Nil, Value::Array(vec![])]));
		assert!(!distro_from_app_data(Some(&empty)));
		let short = pack(Value::Array(vec![Value::Nil, Value::Nil]));
		assert!(!distro_from_app_data(Some(&short)));
		let not_a_list = pack(Value::Array(vec![Value::Nil, Value::Nil, Value::Integer(SF_RFED_DISTRO.into())]));
		assert!(!distro_from_app_data(Some(&not_a_list)));
		assert!(!distro_from_app_data(Some(b"Alice")), "original raw format");
		assert!(!distro_from_app_data(Some(b"")));
		assert!(!distro_from_app_data(None));
		// The reference reads compression from the same list and ignores the flag.
		assert_eq!(super::compression_support_from_app_data(Some(&distro)), Some(false));
		assert_eq!(super::compression_support_from_app_data(Some(&both)), Some(true));
	}
}

#[cfg(test)]
mod compression_support_tests {
	use super::compression_support_from_app_data;
	use rmpv::Value;

	fn pack(v: Value) -> Vec<u8> {
		let mut buf = Vec::new();
		rmpv::encode::write_value(&mut buf, &v).unwrap();
		buf
	}

	/// LXMF/LXMF.py compression_support_from_app_data(), case by case.
	#[test]
	fn matches_the_reference() {
		assert_eq!(compression_support_from_app_data(None), None);
		assert_eq!(compression_support_from_app_data(Some(b"")), None);
		assert_eq!(compression_support_from_app_data(Some(b"Alice")), Some(true), "original format");
		assert_eq!(compression_support_from_app_data(Some(&pack(Value::Array(vec![Value::Nil, Value::Nil])))), Some(true), "fewer than three elements");
		assert_eq!(compression_support_from_app_data(Some(&pack(Value::Array(vec![Value::Nil, Value::Nil, Value::Integer(7.into())])))), Some(true), "third element not a list");
		assert_eq!(compression_support_from_app_data(Some(&pack(Value::Array(vec![Value::Nil, Value::Nil, Value::Array(vec![])])))), Some(false), "empty list: no SF_COMPRESSION");
		assert_eq!(compression_support_from_app_data(Some(&pack(Value::Array(vec![Value::Nil, Value::Integer(8.into()), Value::Array(vec![Value::Integer(0.into())])])))), Some(true), "SF_COMPRESSION present");
	}
}
