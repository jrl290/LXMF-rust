//! Runs tests/retichat_field_vectors.json (DISPLAY_NAMES.md §2.1, §10)
//! against lxmf_rust::retichat_field and display_name::decode_fields_bytes.
//! Retichat-ios, Retichat-android and Retichat-js run the same file; the
//! display-name vectors are run by tests/display_name_vectors.rs.

use lxmf_rust::display_name::{decode_fields_bytes, NameField};
use lxmf_rust::retichat_field::{
	self, group_entry, read_group_entry, set_group_entry_as, EntryType, GroupValue, FIELD_RETICHAT, GROUP_ENTRIES,
};
use rmpv::Value;
use serde_json::Value as Json;

fn vectors() -> Json {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/retichat_field_vectors.json");
	serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse vectors")
}

fn hex(s: &str) -> Vec<u8> {
	assert!(s.len() % 2 == 0, "odd hex {s}");
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn to_hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read(bytes: &[u8]) -> Value {
	let mut cursor = std::io::Cursor::new(bytes);
	let value = rmpv::decode::read_value(&mut cursor).expect("msgpack");
	assert_eq!(cursor.position() as usize, bytes.len(), "one msgpack value, no trailing bytes");
	value
}

fn pack(value: &Value) -> Vec<u8> {
	let mut buf = Vec::new();
	rmpv::encode::write_value(&mut buf, value).unwrap();
	buf
}

/// `(key, json name, type)` of the group keys, from the file's table.
fn group_keys(v: &Json) -> Vec<(u8, String, EntryType)> {
	v["keys"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|k| k["key"].as_u64().unwrap() > 0)
		.map(|k| {
			let entry_type = match k["type"].as_str().unwrap() {
				"str" => EntryType::Str,
				"bool" => EntryType::Bool,
				other => panic!("group key type {other}"),
			};
			(k["key"].as_u64().unwrap() as u8, k["name"].as_str().unwrap().to_string(), entry_type)
		})
		.collect()
}

fn json_to_group(value: &Json) -> Option<GroupValue> {
	match value {
		Json::Null => None,
		Json::String(s) => Some(GroupValue::Str(s.clone())),
		Json::Bool(b) => Some(GroupValue::Bool(*b)),
		other => panic!("group value {other}"),
	}
}

/// The file's key table is the spec's §10 table and this crate's constants.
#[test]
fn key_table_matches_the_constants() {
	let v = vectors();
	let keys = v["keys"].as_array().unwrap();
	assert_eq!(keys.len(), 10);
	assert_eq!(keys[0]["key"], 0);
	assert_eq!(keys[0]["type"], "name");
	assert_eq!(keys[0]["legacy_field"], Json::Null);
	assert_eq!(FIELD_RETICHAT, 0xD1);
	let constants = [
		("RF_DISPLAY_NAME", retichat_field::RF_DISPLAY_NAME),
		("RF_GROUP_ID", retichat_field::RF_GROUP_ID),
		("RF_GROUP_MEMBERS", retichat_field::RF_GROUP_MEMBERS),
		("RF_GROUP_NAME", retichat_field::RF_GROUP_NAME),
		("RF_GROUP_ACTION", retichat_field::RF_GROUP_ACTION),
		("RF_GROUP_SENDER", retichat_field::RF_GROUP_SENDER),
		("RF_GROUP_RELAY_SEEN", retichat_field::RF_GROUP_RELAY_SEEN),
		("RF_GROUP_RELAY_FOR", retichat_field::RF_GROUP_RELAY_FOR),
		("RF_GROUP_RELAY_DONE", retichat_field::RF_GROUP_RELAY_DONE),
		("RF_GROUP_MEMBER_KEYS", retichat_field::RF_GROUP_MEMBER_KEYS),
	];
	for (entry, (constant, key)) in keys.iter().zip(constants) {
		assert_eq!(entry["constant"], constant);
		assert_eq!(entry["key"].as_u64().unwrap(), key as u64, "{constant}");
	}
	let table = group_keys(&v);
	assert_eq!(table.len(), GROUP_ENTRIES.len());
	for ((key, _, entry_type), json) in table.iter().zip(&keys[1..]) {
		let (legacy, t) = group_entry(*key).unwrap();
		assert_eq!(json["legacy_field"].as_u64().unwrap(), legacy as u64, "key {key}");
		assert_eq!(*entry_type, t, "key {key}");
	}
}

#[test]
fn decode_vectors() {
	let v = vectors();
	let table = group_keys(&v);
	let cases = v["decode"].as_array().unwrap();
	assert!(cases.len() >= 30);
	let mut failures = Vec::new();
	for case in cases {
		let name = case["name"].as_str().unwrap();
		let bytes = hex(case["fields_msgpack_hex"].as_str().unwrap());

		let got = decode_fields_bytes(&bytes);
		let want = match case["state"].as_str().unwrap() {
			"absent" => NameField::Absent,
			"clear" => NameField::Clear,
			"name" => NameField::Name(case["display_name"].as_str().unwrap().to_string()),
			other => panic!("unknown state {other}"),
		};
		if case["state"] != "name" {
			assert_eq!(case["display_name"], Json::Null, "{name}: display_name only for state name");
		}
		if got != want {
			failures.push(format!("{name}: name got {got:?}, want {want:?}"));
		}

		let fields = read(&bytes);
		let group = case["group"].as_object().expect("group object");
		assert_eq!(group.len(), table.len(), "{name}: every group entry is listed");
		for (key, json_name, _) in &table {
			let want = json_to_group(group.get(json_name).unwrap_or_else(|| panic!("{name}: no {json_name}")));
			let got = read_group_entry(&fields, *key);
			if got != want {
				failures.push(format!("{name}: {json_name} got {got:?}, want {want:?}"));
			}
		}
	}
	assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n"));
}

/// Both send forms, byte for byte (§10).
#[test]
fn encode_vectors() {
	let v = vectors();
	let cases = v["encode"].as_array().unwrap();
	assert!(!cases.is_empty());
	let mut failures = Vec::new();
	for case in cases {
		let name = case["name"].as_str().unwrap();
		for (in_retichat_field, expected) in [(false, "legacy_hex"), (true, "retichat_hex")] {
			let mut fields = read(&hex(case["start_hex"].as_str().unwrap()));
			for entry in case["entries"].as_array().unwrap() {
				let key = entry["key"].as_u64().unwrap() as u8;
				let value = json_to_group(&entry["value"]).expect("an encode value");
				set_group_entry_as(&mut fields, key, &value, in_retichat_field).unwrap();
			}
			let got = to_hex(&pack(&fields));
			let want = case[expected].as_str().unwrap();
			if got != want {
				failures.push(format!("{name} ({expected}): got {got}, want {want}"));
			}
			// What was written reads back.
			for entry in case["entries"].as_array().unwrap() {
				let key = entry["key"].as_u64().unwrap() as u8;
				let last = case["entries"].as_array().unwrap().iter().rev().find(|e| e["key"] == entry["key"]).unwrap();
				assert_eq!(read_group_entry(&fields, key), json_to_group(&last["value"]), "{name} ({expected}) key {key}");
			}
		}
	}
	assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n"));
}

/// A map key as the integer or bytes it means, whatever its msgpack width, so
/// `ff` and `d0 ff` (both -1) compare equal.
fn key_identity(key: &Value) -> String {
	match key {
		Value::Integer(i) => match (i.as_u64(), i.as_i64()) {
			(Some(u), _) => format!("int {u}"),
			(None, Some(n)) => format!("int {n}"),
			_ => unreachable!(),
		},
		Value::String(s) => format!("str {:?}", s.as_bytes()),
		Value::Binary(b) => format!("bin {b:?}"),
		other => format!("other {other:?}"),
	}
}

fn duplicate_keys(value: &Value, path: &str, found: &mut Vec<String>) {
	match value {
		Value::Map(entries) => {
			let mut seen = std::collections::HashSet::new();
			for (key, inner) in entries {
				let id = key_identity(key);
				if !seen.insert(id.clone()) {
					found.push(format!("{path}: duplicate key {id}"));
				}
				duplicate_keys(inner, &format!("{path}/{id}"), found);
			}
		}
		Value::Array(items) => items.iter().enumerate().for_each(|(i, item)| duplicate_keys(item, &format!("{path}[{i}]"), found)),
		_ => {}
	}
}

/// Group entry strings (old fields 0xA0-0xA8, map keys 1-9) with invalid UTF-8.
fn invalid_group_strings(fields: &Value, found: &mut Vec<String>) {
	let Value::Map(top) = fields else { return };
	for (key, value) in top {
		let Some(n) = key.as_u64() else { continue };
		if (0xA0..=0xA8).contains(&n) && matches!(value, Value::String(s) if !s.is_str()) {
			found.push(format!("old field {n:#x}: invalid UTF-8"));
		}
		if n == FIELD_RETICHAT as u64 {
			if let Value::Map(inner) = value {
				for (k, v) in inner {
					if matches!(k.as_u64(), Some(1..=9)) && matches!(v, Value::String(s) if !s.is_str()) {
						found.push(format!("0xd1 key {}: invalid UTF-8", k.as_u64().unwrap()));
					}
				}
			}
		}
	}
}

/// The notes promise every client can agree on every vector: no duplicate key
/// (at any width) anywhere, and no invalid UTF-8 in a group entry. Holds for
/// this file and for display_name_vectors.json's decode_field cases.
#[test]
fn no_vector_holds_a_duplicate_key_or_invalid_group_utf8() {
	let v = vectors();
	let note = v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("No vector holds a duplicate key"));
	assert!(note, "the notes still make the promise this test checks");

	let mut inputs: Vec<(String, String)> = Vec::new();
	for case in v["decode"].as_array().unwrap() {
		inputs.push((format!("decode / {}", case["name"]), case["fields_msgpack_hex"].as_str().unwrap().into()));
	}
	for case in v["encode"].as_array().unwrap() {
		for form in ["start_hex", "legacy_hex", "retichat_hex"] {
			inputs.push((format!("encode / {} / {form}", case["name"]), case[form].as_str().unwrap().into()));
		}
	}
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/display_name_vectors.json");
	let names: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
	for case in names["decode_field"].as_array().unwrap() {
		inputs.push((format!("display_name decode_field / {}", case["name"]), case["fields_msgpack_hex"].as_str().unwrap().into()));
	}

	let mut failures = Vec::new();
	for (name, hex_str) in &inputs {
		let value = read(&hex(hex_str));
		let mut found = Vec::new();
		duplicate_keys(&value, "", &mut found);
		invalid_group_strings(&value, &mut found);
		failures.extend(found.into_iter().map(|f| format!("{name}: {f}")));
	}
	assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n"));
}
