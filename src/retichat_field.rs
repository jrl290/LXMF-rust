//! The Retichat field `0xD1` (DISPLAY_NAMES.md §2.1 and §10).
//!
//! Retichat owns one LXMF field number, [`FIELD_RETICHAT`]. Its value is a
//! msgpack map whose keys are small non-negative integers (one byte each on
//! the wire, `0..=127`); this module holds those keys and the helpers that
//! read and write them, once, for the router, the channel codec and the
//! FFI/JNI setters.
//!
//! - A `0xD1` that is not a map is ignored whole; unknown keys inside it are
//!   ignored. A message with no Retichat entries carries no `0xD1` at all.
//! - Keys are matched as integers of any msgpack width (a key `1` encoded as
//!   `0xCC 0x01` is key 1). Writers always emit the one-byte form, and keep
//!   the map in ascending key order so the bytes are deterministic.
//! - Key 0 is the display name, written only by the router
//!   (`name_ledger`) and `channel::pack`; decode it with
//!   `display_name::decode_field`.
//!
//! ## Group entries: the transition (§10)
//!
//! Groups used nine top-level fields `0xA0`–`0xA8`; they move to keys 1–9.
//! Readers take each group entry from the Retichat field when it is there
//! (with its type), otherwise from its old top-level field
//! ([`read_group_entry`]). Senders keep writing the old fields while
//! [`GROUP_ENTRIES_IN_RETICHAT_FIELD`] is false ([`set_group_entry`]); both
//! forms are implemented and tested, so the switch is this one constant.

use rmpv::Value;

pub use crate::lxmf::FIELD_RETICHAT;

/// §2.1: the LXMF source's display name. bin (receivers accept bin or str);
/// empty means "no name now". Router-owned: apps never set it.
pub const RF_DISPLAY_NAME: u8 = 0;
/// str: 32-hex group id (was `0xA0`).
pub const RF_GROUP_ID: u8 = 1;
/// str: comma-separated hex hashes of all members, invite only (was `0xA1`).
pub const RF_GROUP_MEMBERS: u8 = 2;
/// str: group name (was `0xA2`).
pub const RF_GROUP_NAME: u8 = 3;
/// str: `invite`, `accept`, `leave`, `relay_req`, `relay_done` (was `0xA3`).
pub const RF_GROUP_ACTION: u8 = 4;
/// str: original sender hex (was `0xA4`).
pub const RF_GROUP_SENDER: u8 = 5;
/// str: comma-separated hashes already delivered to (was `0xA5`).
pub const RF_GROUP_RELAY_SEEN: u8 = 6;
/// str: hash of the member being relayed for (was `0xA6`).
pub const RF_GROUP_RELAY_FOR: u8 = 7;
/// bool: relay-complete signal (was `0xA7`).
pub const RF_GROUP_RELAY_DONE: u8 = 8;
/// str: one `hash:base64-public-key` pair per invite chunk (was `0xA8`).
pub const RF_GROUP_MEMBER_KEYS: u8 = 9;

/// The largest key: keys are positive fixints, one byte on the wire (§2.1).
pub const RF_MAX_KEY: u8 = 127;

/// §10: where senders put group entries. `false` until the switch (around
/// 2026-10-26, with `DELIVERY_PACKET_PROOF = Required`): released apps read
/// only `0xA0`–`0xA8`. Swift's equivalent is `groupEntriesInRetichatField`.
pub const GROUP_ENTRIES_IN_RETICHAT_FIELD: bool = false;

/// The group keys, in order: `(key, old top-level field, type)`.
pub const GROUP_ENTRIES: [(u8, u8, EntryType); 9] = [
	(RF_GROUP_ID, 0xA0, EntryType::Str),
	(RF_GROUP_MEMBERS, 0xA1, EntryType::Str),
	(RF_GROUP_NAME, 0xA2, EntryType::Str),
	(RF_GROUP_ACTION, 0xA3, EntryType::Str),
	(RF_GROUP_SENDER, 0xA4, EntryType::Str),
	(RF_GROUP_RELAY_SEEN, 0xA5, EntryType::Str),
	(RF_GROUP_RELAY_FOR, 0xA6, EntryType::Str),
	(RF_GROUP_RELAY_DONE, 0xA7, EntryType::Bool),
	(RF_GROUP_MEMBER_KEYS, 0xA8, EntryType::Str),
];

/// The msgpack type a group entry has, in either form (§10: "each value
/// keeps exactly the type it had as a top-level field").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
	Str,
	Bool,
}

/// A decoded group entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupValue {
	Str(String),
	Bool(bool),
}

impl GroupValue {
	pub fn entry_type(&self) -> EntryType {
		match self {
			GroupValue::Str(_) => EntryType::Str,
			GroupValue::Bool(_) => EntryType::Bool,
		}
	}

	pub fn to_value(&self) -> Value {
		match self {
			GroupValue::Str(s) => Value::String(s.as_str().into()),
			GroupValue::Bool(b) => Value::Boolean(*b),
		}
	}

	/// `value` as this type, or `None` (a str must be valid UTF-8; bin is
	/// not a str).
	pub fn from_value(value: &Value, entry_type: EntryType) -> Option<GroupValue> {
		match (entry_type, value) {
			(EntryType::Str, Value::String(s)) => s.as_str().map(|s| GroupValue::Str(s.to_string())),
			(EntryType::Bool, Value::Boolean(b)) => Some(GroupValue::Bool(*b)),
			_ => None,
		}
	}
}

/// `(old top-level field, type)` of a group key 1..=9, else `None`.
pub fn group_entry(key: u8) -> Option<(u8, EntryType)> {
	GROUP_ENTRIES.iter().find(|(k, _, _)| *k == key).map(|(_, field, t)| (*field, *t))
}

/// The integer value of a map key of any msgpack width, if non-negative.
fn int_key(key: &Value) -> Option<u64> {
	match key {
		Value::Integer(int) => int.as_u64(),
		_ => None,
	}
}

/// Whether a map key is the integer `target` (any msgpack int width).
pub fn key_is(key: &Value, target: u8) -> bool {
	int_key(key) == Some(target as u64)
}

/// The value of the top-level field `field` in an LXMF fields map.
pub fn top_level(fields: &Value, field: u8) -> Option<&Value> {
	match fields {
		Value::Map(entries) => entries.iter().find(|(k, _)| key_is(k, field)).map(|(_, v)| v),
		_ => None,
	}
}

/// The Retichat field's map, when `fields` is a map holding a map at `0xD1`.
/// A non-map `0xD1` is ignored whole (§2.1): `None`.
pub fn retichat_map(fields: &Value) -> Option<&[(Value, Value)]> {
	match top_level(fields, FIELD_RETICHAT)? {
		Value::Map(entries) => Some(entries),
		_ => None,
	}
}

/// Entry `key` of the Retichat field, raw (no type check).
pub fn read_entry(fields: &Value, key: u8) -> Option<&Value> {
	retichat_map(fields)?.iter().find(|(k, _)| key_is(k, key)).map(|(_, v)| v)
}

/// §10 reader: group entry `key` (1..=9), typed, from the Retichat field when
/// it is there with its type, otherwise from its old top-level field.
/// `None` for a key that is not a group key, or when neither form holds a
/// value of the right type.
pub fn read_group_entry(fields: &Value, key: u8) -> Option<GroupValue> {
	let (legacy, entry_type) = group_entry(key)?;
	read_entry(fields, key)
		.and_then(|v| GroupValue::from_value(v, entry_type))
		.or_else(|| top_level(fields, legacy).and_then(|v| GroupValue::from_value(v, entry_type)))
}

/// Set top-level field `field`: replace the first entry with that integer key
/// (any width) in place, dropping any duplicates, or append. Does nothing
/// when `fields` is not a map (an `LXMessage`'s always is).
pub fn set_top_level(fields: &mut Value, field: u8, value: Value) {
	let Value::Map(entries) = fields else { return };
	match entries.iter().position(|(k, _)| key_is(k, field)) {
		Some(at) => {
			entries[at].1 = value;
			let mut index = 0;
			entries.retain(|(k, _)| {
				let keep = index <= at || !key_is(k, field);
				index += 1;
				keep
			});
		}
		None => entries.push((Value::from(field), value)),
	}
}

/// Remove every top-level entry whose key is the integer `field`.
pub fn remove_top_level(fields: &mut Value, field: u8) {
	if let Value::Map(entries) = fields {
		entries.retain(|(k, _)| !key_is(k, field));
	}
}

/// Set entry `key` of the Retichat field to `value`.
///
/// Creates `0xD1` (appended to the fields) when there is none, and replaces
/// a `0xD1` that is not a map (it carries nothing, §2.1). Inside the map,
/// other entries are kept; any entry with this key is replaced, and the new
/// one goes before the first larger integer key, so a map built by these
/// helpers is in ascending key order whatever order the entries were set in.
/// Does nothing when `fields` is not a map.
pub fn set_entry(fields: &mut Value, key: u8, value: Value) {
	let Value::Map(top) = fields else { return };
	let at = match top.iter().position(|(k, _)| key_is(k, FIELD_RETICHAT)) {
		Some(at) => {
			// One Retichat field: readers take the first.
			let mut index = 0;
			top.retain(|(k, _)| {
				let keep = index <= at || !key_is(k, FIELD_RETICHAT);
				index += 1;
				keep
			});
			if !matches!(top[at].1, Value::Map(_)) {
				top[at].1 = Value::Map(Vec::new());
			}
			at
		}
		None => {
			top.push((Value::from(FIELD_RETICHAT), Value::Map(Vec::new())));
			top.len() - 1
		}
	};
	let Value::Map(entries) = &mut top[at].1 else { unreachable!("made a map above") };
	entries.retain(|(k, _)| !key_is(k, key));
	let insert_at = entries
		.iter()
		.position(|(k, _)| int_key(k).map_or(false, |k| k > key as u64))
		.unwrap_or(entries.len());
	entries.insert(insert_at, (Value::from(key), value));
}

/// Remove entry `key` from the Retichat field. When the map is left empty,
/// or `0xD1` is not a map at all (it carries nothing, §2.1), `0xD1` is
/// dropped, so a message with no Retichat entries carries no `0xD1`.
pub fn remove_entry(fields: &mut Value, key: u8) {
	let Value::Map(top) = fields else { return };
	let mut drop_field = false;
	if let Some((_, value)) = top.iter_mut().find(|(k, _)| key_is(k, FIELD_RETICHAT)) {
		match value {
			Value::Map(entries) => {
				entries.retain(|(k, _)| !key_is(k, key));
				drop_field = entries.is_empty();
			}
			_ => drop_field = true,
		}
	}
	if drop_field {
		top.retain(|(k, _)| !key_is(k, FIELD_RETICHAT));
	}
}

/// §10 sender, in a chosen form: group entry `key` (1..=9) with `value`
/// written into the Retichat field (`in_retichat_field`) or its old
/// top-level field. The other form's entry for this key is removed, so a
/// message never carries two values for one entry.
pub fn set_group_entry_as(fields: &mut Value, key: u8, value: &GroupValue, in_retichat_field: bool) -> Result<(), String> {
	let (legacy, entry_type) = group_entry(key).ok_or_else(|| format!("{key} is not a group key (1..=9)"))?;
	if value.entry_type() != entry_type {
		return Err(format!("group key {key} holds {entry_type:?}, not {:?}", value.entry_type()));
	}
	if in_retichat_field {
		remove_top_level(fields, legacy);
		set_entry(fields, key, value.to_value());
	} else {
		remove_entry(fields, key);
		set_top_level(fields, legacy, value.to_value());
	}
	Ok(())
}

/// §10 sender: group entry `key` in the form [`GROUP_ENTRIES_IN_RETICHAT_FIELD`]
/// selects.
pub fn set_group_entry(fields: &mut Value, key: u8, value: &GroupValue) -> Result<(), String> {
	set_group_entry_as(fields, key, value, GROUP_ENTRIES_IN_RETICHAT_FIELD)
}

/// An app-settable key from a host integer (FFI/JNI): `1..=127`. Key 0 is
/// the display name, which only the router writes (§4.1); anything above
/// 127 would not be one byte on the wire. Nothing is truncated.
pub fn app_key(key: i64) -> Result<u8, String> {
	if key == RF_DISPLAY_NAME as i64 {
		return Err("Retichat field key 0 is the display name; only the router writes it".into());
	}
	if !(1..=RF_MAX_KEY as i64).contains(&key) {
		return Err(format!("Retichat field key {key} is outside 1..=127"));
	}
	Ok(key as u8)
}

/// An app entry for the FFI/JNI setters: the key checked by [`app_key`], and
/// a defined group key (1..=9) must get its own type.
pub fn check_app_entry(key: i64, entry_type: EntryType) -> Result<u8, String> {
	let key = app_key(key)?;
	if let Some((_, want)) = group_entry(key) {
		if want != entry_type {
			return Err(format!("Retichat field key {key} holds {want:?}, not {entry_type:?}"));
		}
	}
	Ok(key)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pack(value: &Value) -> Vec<u8> {
		let mut buf = Vec::new();
		rmpv::encode::write_value(&mut buf, value).unwrap();
		buf
	}

	fn unpack(bytes: &[u8]) -> Value {
		rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)).unwrap()
	}

	fn empty() -> Value {
		Value::Map(Vec::new())
	}

	#[test]
	fn keys_match_the_spec_table() {
		assert_eq!(FIELD_RETICHAT, 0xD1);
		let keys = [
			RF_DISPLAY_NAME, RF_GROUP_ID, RF_GROUP_MEMBERS, RF_GROUP_NAME, RF_GROUP_ACTION, RF_GROUP_SENDER,
			RF_GROUP_RELAY_SEEN, RF_GROUP_RELAY_FOR, RF_GROUP_RELAY_DONE, RF_GROUP_MEMBER_KEYS,
		];
		assert_eq!(keys, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
		for (i, (key, field, t)) in GROUP_ENTRIES.iter().enumerate() {
			assert_eq!(*key as usize, i + 1);
			assert_eq!(*field as usize, 0xA0 + i);
			assert_eq!(*t, if *key == RF_GROUP_RELAY_DONE { EntryType::Bool } else { EntryType::Str });
		}
		assert!(!GROUP_ENTRIES_IN_RETICHAT_FIELD, "the switch is around 2026-10-26, not before");
	}

	/// §2.1: `{0xD1: {key: value}}` with one-byte keys, never bin-wrapped.
	#[test]
	fn set_entry_creates_the_map() {
		let mut fields = empty();
		set_entry(&mut fields, 3, Value::String("g".into()));
		assert_eq!(pack(&fields), vec![0x81, 0xcc, 0xd1, 0x81, 0x03, 0xa1, b'g']);
	}

	#[test]
	fn set_entry_keeps_other_entries_in_ascending_order() {
		let mut a = empty();
		set_entry(&mut a, 5, Value::String("s".into()));
		set_entry(&mut a, 1, Value::String("i".into()));
		set_entry(&mut a, 0, Value::Binary(b"N".to_vec()));
		set_entry(&mut a, 3, Value::String("n".into()));
		let mut b = empty();
		for key in [3u8, 0, 5, 1] {
			let value = if key == 0 { Value::Binary(b"N".to_vec()) } else { Value::String(["", "i", "", "n", "", "s"][key as usize].into()) };
			set_entry(&mut b, key, value);
		}
		assert_eq!(pack(&a), pack(&b), "order does not depend on set order");
		assert_eq!(
			pack(&a),
			vec![0x81, 0xcc, 0xd1, 0x84, 0x00, 0xc4, 0x01, b'N', 0x01, 0xa1, b'i', 0x03, 0xa1, b'n', 0x05, 0xa1, b's']
		);
		// Replacing keeps the rest and the order.
		set_entry(&mut a, 3, Value::String("m".into()));
		assert_eq!(read_entry(&a, 3), Some(&Value::String("m".into())));
		assert_eq!(read_entry(&a, 1), Some(&Value::String("i".into())));
		assert_eq!(retichat_map(&a).unwrap().len(), 4);
	}

	#[test]
	fn set_entry_merges_into_a_received_map_with_wide_keys() {
		// {0xD1 (uint16): {1 (uint32): "g"}}, alongside another field.
		let mut fields = unpack(&[0x82, 0x0c, 0xc0, 0xcd, 0x00, 0xd1, 0x81, 0xce, 0, 0, 0, 1, 0xa1, b'g']);
		set_entry(&mut fields, 1, Value::String("h".into()));
		set_entry(&mut fields, 0, Value::Binary(Vec::new()));
		assert_eq!(read_entry(&fields, 1), Some(&Value::String("h".into())));
		let map = retichat_map(&fields).unwrap();
		assert_eq!(map.len(), 2, "the wide key 1 was replaced, not duplicated");
		assert!(key_is(&map[0].0, 0));
		let Value::Map(top) = &fields else { panic!() };
		assert_eq!(top.len(), 2);
	}

	#[test]
	fn set_entry_replaces_a_non_map_field() {
		let mut fields = unpack(&[0x81, 0xcc, 0xd1, 0xc4, 0x03, b'B', b'o', b'b']);
		assert_eq!(retichat_map(&fields), None, "the unshipped bin form is not a map");
		assert_eq!(read_entry(&fields, 0), None);
		set_entry(&mut fields, 2, Value::String("x".into()));
		assert_eq!(pack(&fields), vec![0x81, 0xcc, 0xd1, 0x81, 0x02, 0xa1, b'x']);
	}

	#[test]
	fn remove_entry_drops_an_empty_map_and_keeps_the_rest() {
		let mut fields = empty();
		set_top_level(&mut fields, 0x0c, Value::Nil);
		set_entry(&mut fields, 0, Value::Binary(b"A".to_vec()));
		set_entry(&mut fields, 4, Value::String("leave".into()));
		remove_entry(&mut fields, 0);
		assert_eq!(read_entry(&fields, 4), Some(&Value::String("leave".into())), "app entries survive");
		assert_eq!(read_entry(&fields, 0), None);
		remove_entry(&mut fields, 4);
		assert_eq!(pack(&fields), vec![0x81, 0x0c, 0xc0], "no empty 0xD1 left behind");
		remove_entry(&mut fields, 4);
		assert_eq!(pack(&fields), vec![0x81, 0x0c, 0xc0], "removing from nothing is a no-op");

		let mut non_map = unpack(&[0x81, 0xcc, 0xd1, 0xa1, b'x']);
		remove_entry(&mut non_map, 0);
		assert_eq!(pack(&non_map), vec![0x80], "a non-map 0xD1 carries nothing and is dropped");
	}

	#[test]
	fn set_top_level_matches_any_width_and_dedups() {
		// 0xA0 as uint16 and as uint8, then "" (a fixstr key, not an integer).
		let mut fields = unpack(&[0x83, 0xcd, 0x00, 0xa0, 0xa1, b'a', 0xcc, 0xa0, 0xa1, b'b', 0xa0, 0xa1, b'c']);
		set_top_level(&mut fields, 0xA0, Value::String("d".into()));
		assert_eq!(top_level(&fields, 0xA0), Some(&Value::String("d".into())));
		let Value::Map(top) = &fields else { panic!() };
		assert_eq!(top.len(), 2, "the duplicate 0xA0 is dropped, the str key kept");
		assert_eq!(top[1], (Value::String("".into()), Value::String("c".into())));
	}

	#[test]
	fn both_group_send_forms() {
		let id = GroupValue::Str("0123456789abcdef0123456789abcdef".into());
		let done = GroupValue::Bool(true);

		let mut legacy = empty();
		set_group_entry_as(&mut legacy, RF_GROUP_ID, &id, false).unwrap();
		set_group_entry_as(&mut legacy, RF_GROUP_RELAY_DONE, &done, false).unwrap();
		let mut want = vec![0x82, 0xcc, 0xa0, 0xd9, 0x20];
		want.extend_from_slice(b"0123456789abcdef0123456789abcdef");
		want.extend_from_slice(&[0xcc, 0xa7, 0xc3]);
		assert_eq!(pack(&legacy), want, "old form: top-level 0xA0 and 0xA7");

		let mut map = empty();
		set_group_entry_as(&mut map, RF_GROUP_RELAY_DONE, &done, true).unwrap();
		set_group_entry_as(&mut map, RF_GROUP_ID, &id, true).unwrap();
		let mut want = vec![0x81, 0xcc, 0xd1, 0x82, 0x01, 0xd9, 0x20];
		want.extend_from_slice(b"0123456789abcdef0123456789abcdef");
		want.extend_from_slice(&[0x08, 0xc3]);
		assert_eq!(pack(&map), want, "new form: {{0xD1: {{1: id, 8: true}}}}");

		for fields in [&legacy, &map] {
			assert_eq!(read_group_entry(fields, RF_GROUP_ID), Some(id.clone()));
			assert_eq!(read_group_entry(fields, RF_GROUP_RELAY_DONE), Some(done.clone()));
			assert_eq!(read_group_entry(fields, RF_GROUP_NAME), None);
		}

		// Switching form for one entry removes the other form's copy.
		set_group_entry_as(&mut legacy, RF_GROUP_ID, &id, true).unwrap();
		assert_eq!(top_level(&legacy, 0xA0), None);
		assert_eq!(read_entry(&legacy, RF_GROUP_ID), Some(&id.to_value()));
		set_group_entry_as(&mut map, RF_GROUP_ID, &id, false).unwrap();
		assert_eq!(read_entry(&map, RF_GROUP_ID), None);
		assert_eq!(read_entry(&map, RF_GROUP_RELAY_DONE), Some(&Value::Boolean(true)));

		// The default form is the constant's.
		let mut default = empty();
		set_group_entry(&mut default, RF_GROUP_NAME, &GroupValue::Str("n".into())).unwrap();
		assert_eq!(top_level(&default, 0xA2).is_some(), !GROUP_ENTRIES_IN_RETICHAT_FIELD);
		assert_eq!(read_entry(&default, RF_GROUP_NAME).is_some(), GROUP_ENTRIES_IN_RETICHAT_FIELD);

		assert!(set_group_entry_as(&mut empty(), RF_GROUP_RELAY_DONE, &id, true).is_err(), "wrong type");
		assert!(set_group_entry_as(&mut empty(), 0, &id, true).is_err(), "not a group key");
		assert!(set_group_entry_as(&mut empty(), 10, &id, false).is_err(), "not a group key");
	}

	#[test]
	fn the_map_wins_per_entry_and_only_with_its_type() {
		// 0xA0 "old", 0xA2 "oldname", {1: "new", 3: 7 (wrong type)}
		let fields = unpack(&[
			0x83, 0xcc, 0xa0, 0xa3, b'o', b'l', b'd', 0xcc, 0xa2, 0xa7, b'o', b'l', b'd', b'n', b'a', b'm', b'e',
			0xcc, 0xd1, 0x82, 0x01, 0xa3, b'n', b'e', b'w', 0x03, 0x07,
		]);
		assert_eq!(read_group_entry(&fields, RF_GROUP_ID), Some(GroupValue::Str("new".into())));
		assert_eq!(read_group_entry(&fields, RF_GROUP_NAME), Some(GroupValue::Str("oldname".into())));
		assert_eq!(read_group_entry(&fields, RF_GROUP_ACTION), None);
		assert_eq!(read_group_entry(&fields, 0), None, "key 0 is not a group entry");
	}

	#[test]
	fn app_keys() {
		assert!(app_key(0).is_err(), "router-owned");
		assert_eq!(app_key(1), Ok(1));
		assert_eq!(app_key(127), Ok(127));
		assert!(app_key(128).is_err());
		assert!(app_key(-1).is_err());
		assert!(app_key(256 + 1).is_err(), "never truncated to 1");
		assert_eq!(check_app_entry(8, EntryType::Bool), Ok(8));
		assert!(check_app_entry(8, EntryType::Str).is_err());
		assert!(check_app_entry(1, EntryType::Bool).is_err());
		assert_eq!(check_app_entry(10, EntryType::Bool), Ok(10), "undefined keys take either type");
		assert_eq!(check_app_entry(10, EntryType::Str), Ok(10));
	}
}
