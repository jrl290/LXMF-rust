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
