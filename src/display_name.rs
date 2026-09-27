//! Display names: cleaning, the name entry (key 0 of the Retichat field
//! `0xD1`), and the name digest.
//!
//! The contract is `DISPLAY_NAMES.md` in this crate. This module is the one
//! Rust implementation of its section 3; Swift and Kotlin call it through the
//! FFI/JNI and Retichat-js mirrors it. The shared test vectors are
//! `tests/display_name_vectors.json`.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::retichat_field::{self, RF_DISPLAY_NAME};

/// DISPLAY_NAMES.md §3 rule 5: names are cut to this many Unicode scalars.
pub const MAX_SCALARS: usize = 64;

/// The most UTF-8 bytes a cleaned name can take: 64 scalars of 4 bytes.
pub const MAX_NAME_BYTES: usize = MAX_SCALARS * 4;

/// DISPLAY_NAMES.md §4.1: a name confirmed delivered is sent again after this.
pub const NAME_REFRESH_SECS: i64 = 30 * 24 * 60 * 60;

/// DISPLAY_NAMES.md §4.2: a channel post carries the name again after this.
/// The channel rule is applied by the clients; the constant lives here so
/// they read one value.
pub const CHANNEL_NAME_REFRESH_SECS: i64 = 24 * 60 * 60;

/// MeshChatX's and Columba's placeholder; an announce carrying it is anonymous.
pub const ANONYMOUS_PEER: &str = "Anonymous Peer";

/// Length of a name digest (§4.1): the first 16 bytes of SHA-256.
pub const DIGEST_LEN: usize = 16;

/// Unicode `White_Space` (PropList.txt). Rule 2 turns each into U+0020.
fn is_white_space(c: char) -> bool {
	matches!(
		c,
		'\u{0009}'..='\u{000D}'
			| '\u{0020}'
			| '\u{0085}'
			| '\u{00A0}'
			| '\u{1680}'
			| '\u{2000}'..='\u{200A}'
			| '\u{2028}'
			| '\u{2029}'
			| '\u{202F}'
			| '\u{205F}'
			| '\u{3000}'
	)
}

/// Rule 3: characters removed outright. U+200C and U+200D are kept.
fn is_removed(c: char) -> bool {
	matches!(
		c,
		'\u{0000}'..='\u{001F}'
			| '\u{007F}'
			| '\u{0080}'..='\u{009F}'
			| '\u{202A}'..='\u{202E}'
			| '\u{2066}'..='\u{2069}'
			| '\u{200B}'
			| '\u{200E}'
			| '\u{200F}'
			| '\u{2060}'
			| '\u{FEFF}'
	)
}

/// DISPLAY_NAMES.md §3: raw bytes to a display name, or `None`.
///
/// 1. invalid UTF-8 is `None`;
/// 2. every `White_Space` character becomes U+0020 (so U+0085 becomes a
///    space before rule 3 could remove it as a C1 control);
/// 3. C0/C1 controls, DEL, bidi embeddings/overrides/isolates, U+200B,
///    U+200E, U+200F, U+2060 and U+FEFF are removed;
/// 4. runs of spaces collapse to one, both ends are trimmed;
/// 5. the result is cut to 64 scalars, then trailing U+0020 and U+200D are
///    stripped (repeatedly: a cut can leave "…x\u{200D}" or "… \u{200D}");
/// 6. empty is `None`.
pub fn clean(raw: &[u8]) -> Option<String> {
	let text = std::str::from_utf8(raw).ok()?;
	let mut out: Vec<char> = Vec::with_capacity(text.len().min(4 * MAX_SCALARS));
	// `true` at the start so leading spaces are trimmed as they arrive.
	let mut after_space = true;
	for c in text.chars() {
		let c = if is_white_space(c) { ' ' } else { c };
		if is_removed(c) {
			continue;
		}
		if c == ' ' {
			if after_space {
				continue;
			}
			after_space = true;
		} else {
			after_space = false;
		}
		out.push(c);
	}
	out.truncate(MAX_SCALARS);
	while matches!(out.last(), Some(' ') | Some('\u{200D}')) {
		out.pop();
	}
	if out.is_empty() {
		None
	} else {
		Some(out.into_iter().collect())
	}
}

/// §3, announce names only: [`clean`], and the "Anonymous Peer" placeholder
/// (ASCII case-insensitive) is `None`.
pub fn clean_announce(raw: &[u8]) -> Option<String> {
	clean(raw).filter(|name| !name.eq_ignore_ascii_case(ANONYMOUS_PEER))
}

/// §4.1: the first 16 bytes of SHA-256 over the cleaned name's UTF-8.
/// `None` (no name) hashes the empty string.
pub fn digest(name: Option<&str>) -> [u8; DIGEST_LEN] {
	let full = Sha256::digest(name.unwrap_or("").as_bytes());
	let mut out = [0u8; DIGEST_LEN];
	out.copy_from_slice(&full[..DIGEST_LEN]);
	out
}

/// The digest of "no name" (the empty string).
pub fn empty_digest() -> [u8; DIGEST_LEN] {
	digest(None)
}

/// What the name entry (key 0 of `0xD1`) says (§3, last table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameField {
	/// No `0xD1` map, no key 0 in it, a value that is not bin/str, or a
	/// non-empty value that cleans to nothing.
	Absent,
	/// A zero-length value: "I have no name now".
	Clear,
	/// A value that cleans to this name.
	Name(String),
}

impl NameField {
	/// The one-byte state used across the FFI/JNI: 0 absent, 1 clear, 2 name.
	pub fn state_byte(&self) -> u8 {
		match self {
			NameField::Absent => 0,
			NameField::Clear => 1,
			NameField::Name(_) => 2,
		}
	}

	pub fn name(&self) -> Option<&str> {
		match self {
			NameField::Name(name) => Some(name.as_str()),
			_ => None,
		}
	}

	/// `state u8 | name_len u16 BE | name bytes` — the trailer the channel
	/// unpack output and the fields decoder return across the FFI/JNI.
	pub fn to_trailer(&self) -> Vec<u8> {
		let name = self.name().unwrap_or("").as_bytes();
		// A cleaned name is at most 64 scalars (256 bytes); u16 always fits.
		let len = name.len().min(u16::MAX as usize);
		let mut out = Vec::with_capacity(3 + len);
		out.push(self.state_byte());
		out.extend_from_slice(&(len as u16).to_be_bytes());
		out.extend_from_slice(&name[..len]);
		out
	}

	/// The key-0 value that says this, if any: `Absent` puts no entry in the
	/// message, `Clear` an empty bin, `Name` the name as bin (§2.1).
	pub fn to_value(&self) -> Option<Value> {
		match self {
			NameField::Absent => None,
			NameField::Clear => Some(Value::Binary(Vec::new())),
			NameField::Name(name) => Some(Value::Binary(name.as_bytes().to_vec())),
		}
	}
}

/// Decode one name-entry value. Only bin and str count (§2.1).
pub fn decode_value(value: &Value) -> NameField {
	let raw: &[u8] = match value {
		Value::Binary(bytes) => bytes,
		Value::String(string) => string.as_bytes(),
		_ => return NameField::Absent,
	};
	if raw.is_empty() {
		return NameField::Clear;
	}
	match clean(raw) {
		Some(name) => NameField::Name(name),
		None => NameField::Absent,
	}
}

/// Decode the name from an LXMF fields map: key 0 of the Retichat field
/// `0xD1` (§2.1). Fields that are not a map, no `0xD1`, a `0xD1` that is not
/// a map (including the unshipped `{0xD1: bin}` form) or a map without an
/// integer key 0 are all `Absent`.
pub fn decode_field(fields: &Value) -> NameField {
	retichat_field::read_entry(fields, RF_DISPLAY_NAME).map(decode_value).unwrap_or(NameField::Absent)
}

/// Decode the name from msgpack-encoded fields (the `fields_raw` the FFI hands
/// the apps). Bytes that are not msgpack are `Absent`.
pub fn decode_fields_bytes(fields_raw: &[u8]) -> NameField {
	match rmpv::decode::read_value(&mut std::io::Cursor::new(fields_raw)) {
		Ok(value) => decode_field(&value),
		Err(_) => NameField::Absent,
	}
}

/// §2.2 / §5.1: the announce name in `lxmf.delivery` app_data — the first
/// element of the 0.5.0+ list, or the whole of the original raw format —
/// cleaned with the announce rules.
pub fn announce_name_from_app_data(app_data: Option<&[u8]>) -> Option<String> {
	let data = app_data.filter(|d| !d.is_empty())?;
	if matches!(data.first(), Some(0x90..=0x9f) | Some(0xdc) | Some(0xdd)) {
		match rmpv::decode::read_value(&mut std::io::Cursor::new(data)) {
			Ok(Value::Array(items)) => match items.first() {
				Some(Value::Binary(bytes)) => clean_announce(bytes),
				Some(Value::String(string)) => clean_announce(string.as_bytes()),
				_ => None,
			},
			_ => None,
		}
	} else {
		clean_announce(data)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pack(value: &Value) -> Vec<u8> {
		let mut buf = Vec::new();
		rmpv::encode::write_value(&mut buf, value).unwrap();
		buf
	}

	/// §2.1: `{0xD1: {0: bin}}`: the field number encoded `0xCC 0xD1`, a
	/// map (not bin-wrapped msgpack), key 0 as one byte, the name as bin —
	/// the way `retichat_field::set_entry` writes it.
	#[test]
	fn field_encodes_as_a_map_with_key_0_and_a_bin_value() {
		let mut fields = Value::Map(Vec::new());
		retichat_field::set_entry(&mut fields, RF_DISPLAY_NAME, NameField::Name("Alice".into()).to_value().unwrap());
		assert_eq!(pack(&fields), [&[0x81, 0xCC, 0xD1, 0x81, 0x00, 0xC4, 0x05][..], b"Alice"].concat());
		assert_eq!(decode_field(&fields), NameField::Name("Alice".into()));
		assert_eq!(pack(&NameField::Clear.to_value().unwrap()), vec![0xC4, 0x00]);
		assert_eq!(NameField::Absent.to_value(), None);
	}

	/// The unshipped `{0xD1: bin}` form, and any other non-map `0xD1`, says
	/// nothing (§2.1).
	#[test]
	fn a_non_map_field_is_absent() {
		for value in [Value::Binary(b"Alice".to_vec()), Value::String("Alice".into()), Value::Nil, Value::from(5)] {
			let fields = Value::Map(vec![(Value::from(0xD1), value.clone())]);
			assert_eq!(decode_field(&fields), NameField::Absent, "{value:?}");
		}
		let map = Value::Map(vec![(Value::from(0xD1), Value::Map(vec![(Value::from(0), Value::Binary(Vec::new()))]))]);
		assert_eq!(decode_field(&map), NameField::Clear);
	}

	#[test]
	fn trailer_layout() {
		assert_eq!(NameField::Absent.to_trailer(), vec![0, 0, 0]);
		assert_eq!(NameField::Clear.to_trailer(), vec![1, 0, 0]);
		assert_eq!(NameField::Name("Bo".into()).to_trailer(), vec![2, 0, 2, b'B', b'o']);
	}

	#[test]
	fn announce_name_reads_both_announce_formats() {
		let list = pack(&Value::Array(vec![Value::Binary(b" Alice ".to_vec()), Value::Nil]));
		assert_eq!(announce_name_from_app_data(Some(&list)).as_deref(), Some("Alice"));
		let placeholder = pack(&Value::Array(vec![Value::String("anonymous peer".into()), Value::Nil]));
		assert_eq!(announce_name_from_app_data(Some(&placeholder)), None);
		let nil = pack(&Value::Array(vec![Value::Nil, Value::Integer(8.into())]));
		assert_eq!(announce_name_from_app_data(Some(&nil)), None);
		assert_eq!(announce_name_from_app_data(Some(b"Raw\tName")).as_deref(), Some("Raw Name"));
		assert_eq!(announce_name_from_app_data(Some(b"")), None);
		assert_eq!(announce_name_from_app_data(None), None);
	}

	#[test]
	fn empty_digest_is_sha256_of_nothing() {
		assert_eq!(
			empty_digest().to_vec(),
			vec![0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24]
		);
	}
}
