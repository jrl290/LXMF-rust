//! Runs tests/distro_group_sync_vectors.json, the golden vectors of the group
//! sync G (RFed-rust SPEC.md §17.14, GROUPS-DISTRO-DESIGN.md §7, §10, §11.1,
//! §19.1), against lxmf_rust::distro. The vectors were made with the Python
//! reference by tests/distro_group_sync_vectors.py; both phone bridges and
//! Retichat-js assert the same file.

use std::io::Cursor;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use lxmf_rust::distro::{
	delivery_hash, invite_members, read_group_sync, set_group_sync_fields, unwrap_blob, GroupSync, DISTRO_GROUP_TYPE,
	DISTRO_MARKERS, GROUP_SYNC_LEFT_MAX, MAX_AT_MS,
};
use lxmf_rust::lx_message::LXMessage;
use lxmf_rust::msgpack_keys::repeated_key;
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::{full_hash, Identity};
use rmpv::Value;
use serde_json::Value as Json;

fn vectors() -> Json {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/distro_group_sync_vectors.json");
	serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse vectors")
}

fn hex(s: &str) -> Vec<u8> {
	assert!(s.len() % 2 == 0, "odd hex {s}");
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn to_hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bytes(v: &Json, key: &str) -> Vec<u8> {
	hex(v[key].as_str().unwrap_or_else(|| panic!("{key} missing")))
}

fn identity(v: &Json, who: &str) -> Identity {
	Identity::from_bytes(&bytes(&v[who], "private_key_hex")).expect("identity")
}

fn d_hex(v: &Json) -> String {
	v["distro"]["lxmf_delivery_hash_hex"].as_str().unwrap().to_string()
}

fn fields_entries(fields_hex: &str) -> Vec<(Value, Value)> {
	let raw = hex(fields_hex);
	let mut cur = Cursor::new(&raw[..]);
	let value = rmpv::decode::read_value(&mut cur).expect("fields msgpack");
	assert_eq!(cur.position() as usize, raw.len());
	match value {
		Value::Map(entries) => entries,
		other => panic!("fields are not a map: {other:?}"),
	}
}

fn json(s: &str) -> Json {
	serde_json::from_str(s).unwrap_or_else(|e| panic!("not JSON ({e}): {s}"))
}

/// The keys of a §7 group_sync object, in order.
const SYNC_KEYS: [&str; 11] = ["by", "problem", "op", "group_id", "at_ms", "name", "members", "keys", "creator", "text", "left"];

#[test]
fn the_identities_are_rebuilt_from_their_private_keys() {
	let v = vectors();
	for who in ["distro", "member", "forger"] {
		let id = identity(&v, who);
		assert_eq!(to_hex(&id.get_public_key().unwrap()), v[who]["public_key_hex"].as_str().unwrap(), "{who}");
		assert_eq!(to_hex(&delivery_hash(&id).unwrap()), v[who]["lxmf_delivery_hash_hex"].as_str().unwrap(), "{who}");
	}
	assert_eq!(v["max_at_ms"].as_u64().unwrap(), MAX_AT_MS);
	assert_eq!(v["left_full"].as_array().unwrap().len(), GROUP_SYNC_LEFT_MAX);
	assert_eq!(DISTRO_GROUP_TYPE, "rfed.distro.group");
	assert_eq!(DISTRO_MARKERS, ["rfed.distro.transfer", "rfed.distro.sent", "rfed.distro.channel", "rfed.distro.group"]);
}

/// A message from D to D, as the outbox makes a G: empty title and content, no fields yet.
fn message_from_d(d: &Identity, d_hash: &[u8], timestamp: f64) -> LXMessage {
	let source = Destination::new_inbound(Some(d.clone()), DestinationType::Single, "lxmf".into(), vec!["delivery".into()])
		.expect("D's source destination");
	let mut msg = LXMessage::new(
		None,
		Some(source),
		Some(Vec::new()),
		Some(Vec::new()),
		None,
		Some(LXMessage::DIRECT),
		Some(d_hash.to_vec()),
		Some(d_hash.to_vec()),
		None,
		false,
	)
	.expect("message");
	msg.timestamp = Some(timestamp);
	msg
}

/// §19.1: each op, with an empty and a full left: set_group_sync_fields, then pack, gives
/// the bytes Python packed, and the hash Python's LXMessage computes.
#[test]
fn each_op_is_written_and_packed_to_the_python_bytes() {
	let v = vectors();
	let d = identity(&v, "distro");
	let d_hash = delivery_hash(&d).unwrap();
	let device = v["device_hex"].as_str().unwrap();
	let ops = v["ops"].as_array().unwrap();
	assert_eq!(ops.len(), 8);
	for op in ops {
		let name = op["name"].as_str().unwrap();
		let sync = GroupSync::from_json(&op["sync"].to_string()).unwrap_or_else(|e| panic!("{name}: {e}"));
		assert_eq!(json(&sync.to_json()), op["sync"], "{name}: the JSON form round-trips");
		let mut msg = message_from_d(&d, &d_hash, op["timestamp"].as_f64().unwrap());
		set_group_sync_fields(&mut msg, &sync, &d_hex(&v), device).unwrap_or_else(|e| panic!("{name}: {e}"));
		let mut fields = Vec::new();
		rmpv::encode::write_value(&mut fields, &msg.fields).unwrap();
		assert_eq!(to_hex(&fields), op["fields_hex"].as_str().unwrap(), "{name}: fields");
		msg.pack(false).unwrap();
		assert_eq!(to_hex(msg.packed.as_ref().unwrap()), op["packed_hex"].as_str().unwrap(), "{name}: packed");
		assert_eq!(to_hex(msg.hash.as_ref().unwrap()), op["hash_hex"].as_str().unwrap(), "{name}: hash");
	}
}

fn reading(v: &Json, fields_hex: &str) -> Json {
	let read = read_group_sync(&fields_entries(fields_hex), &d_hex(v)).expect("a group sync");
	let raw = read.to_json();
	let out = json(&raw);
	assert_eq!(out.as_object().unwrap().len(), SYNC_KEYS.len(), "the §7 keys and no others: {raw}");
	let at: Vec<usize> = SYNC_KEYS
		.iter()
		.map(|k| raw.find(&format!("\"{k}\":")).unwrap_or_else(|| panic!("{k} missing from {raw}")))
		.collect();
	assert!(at.windows(2).all(|w| w[0] < w[1]), "the §7 keys in order: {raw}");
	out
}

#[test]
fn each_op_and_each_variant_reads_as_python_reads_it() {
	let v = vectors();
	for set in ["ops", "variants"] {
		for vector in v[set].as_array().unwrap() {
			let name = vector["name"].as_str().unwrap();
			assert_eq!(reading(&v, vector["fields_hex"].as_str().unwrap()), vector["expected"], "{set} {name}");
		}
	}
}

#[test]
fn at_ms_is_read_by_value_in_every_integer_encoding_and_nothing_else() {
	let v = vectors();
	for vector in v["at_ms_encodings"].as_array().unwrap() {
		let why = vector["why"].as_str().unwrap();
		let got = reading(&v, vector["fields_hex"].as_str().unwrap());
		if vector["accepted"].as_bool().unwrap() {
			assert_eq!(got["problem"], Json::Null, "{why}: {got}");
			assert_eq!(got["at_ms"], vector["at_ms"], "{why}");
		} else {
			assert!(got["problem"].is_string(), "{why} must be refused: {got}");
			assert_eq!(got["at_ms"], Json::Null, "{why}");
		}
	}
}

#[test]
fn each_rule_4_failure_has_a_problem_and_nothing_else() {
	let v = vectors();
	let rejects = v["rejects"].as_array().unwrap();
	assert!(rejects.len() >= 30);
	for vector in rejects {
		let name = vector["name"].as_str().unwrap();
		let got = reading(&v, vector["fields_hex"].as_str().unwrap());
		assert!(got["problem"].as_str().is_some_and(|p| !p.is_empty()), "{name} must be refused: {got}");
		assert_eq!(got["by"], vector["by"], "{name}");
		for key in &SYNC_KEYS[2..] {
			assert_eq!(got[*key], Json::Null, "{name}: {key} is null when the form fails");
		}
	}
}

/// §17.14 "read with the invite's own parser": each entry is trimmed of Unicode Zs and U+0009 and
/// nothing else (`invite_space`, made from Python's Unicode database), the one set every phone's
/// own trim takes, so a G whose members name D here names D in each phone's own reading. Every
/// scalar value is tried around D.
#[test]
fn the_invite_parser_trims_exactly_zs_and_tab() {
	let v = vectors();
	let d = d_hex(&v);
	let m = v["member"]["lxmf_delivery_hash_hex"].as_str().unwrap();
	let space: Vec<char> = v["invite_space"]
		.as_array()
		.unwrap()
		.iter()
		.map(|c| char::from_u32(c.as_u64().unwrap() as u32).unwrap())
		.collect();
	assert_eq!(space.len(), 18, "Zs (17) and U+0009");
	let mut wrong = Vec::new();
	for c in (0..=0x10FFFFu32).filter_map(char::from_u32).filter(|&c| c != ',') {
		let listed = invite_members(&format!("{m},{c}{d}{c}{c},{c}"));
		let names_d = listed.iter().any(|x| *x == d);
		if names_d != space.contains(&c) {
			wrong.push(format!("U+{:04X}", c as u32));
		}
		assert!(listed.iter().all(|x| x.len() == 32), "U+{:04X}: {listed:?}", c as u32);
	}
	assert!(wrong.is_empty(), "trimmed or kept against invite_space: {wrong:?}");
}

/// The invite parser splits on the code point `,` (U+002C), never on grapheme clusters: a combining
/// mark after a comma does not join it (Swift's `String.split` on `Character` would), and one before
/// an entry is part of that entry, which is then not 32 lowercase hex.
#[test]
fn the_invite_parser_splits_on_the_code_point_comma() {
	let v = vectors();
	let cases = v["invite_members"].as_array().expect("invite_members");
	let names: Vec<&str> = cases.iter().map(|c| c["name"].as_str().unwrap()).collect();
	for name in ["combining_mark_after_a_comma", "combining_mark_before_an_entry"] {
		assert!(names.contains(&name), "{name} missing from invite_members");
	}
	for case in cases {
		let name = case["name"].as_str().unwrap();
		let want: Vec<String> = case["members"].as_array().unwrap().iter().map(|m| m.as_str().unwrap().to_string()).collect();
		assert_eq!(invite_members(case["csv"].as_str().unwrap()), want, "{name}");
	}
}

/// The vectors that pin the ext and bin readings, the 0xFD forms, the members csv split, and the
/// repeated keys (RFed SPEC §17.14 "Repeated keys": refused whole, as Python LXMF refuses them)
/// are present, so a generator that lost them fails here rather than passing on fewer cases. No
/// set but `refused` and `key_equality` holds a map that repeats a key.
#[test]
fn the_ext_bin_0xfd_and_repeated_key_vectors_are_present() {
	let v = vectors();
	let has = |set: &str, name: &str| v[set].as_array().unwrap().iter().any(|x| x["name"] == name);
	for name in [
		"group_id_bin_in_both_forms",
		"group_id_bin_in_0xd1_str_in_0xa0",
		"ext_beside_group_id",
		"ext_beside_group_id_in_retichat_field",
	] {
		assert!(has("group_entries", name), "group_entries {name} missing");
	}
	for name in ["leave_0xfd_int", "leave_0xfd_array", "leave_without_0xfd", "accept_members_combining_mark_after_a_comma"] {
		assert!(has("variants", name), "variants {name} missing");
	}
	assert!(has("rejects", "members_naming_d_after_a_combining_mark"), "rejects members_naming_d_after_a_combining_mark missing");
	for name in [
		"group_id_twice",
		"group_id_twice_one_malformed",
		"retichat_field_group_id_twice",
		"retichat_field_twice",
		"group_action_and_name_twice",
		"custom_type_twice_marker_first",
		"custom_type_twice_marker_last",
		"g_leave_0xfb_twice",
		"retichat_field_nested_map_repeats_a_key",
		"non_group_field_twice",
		"non_group_field_nested_repeat",
	] {
		assert!(has("refused", name), "refused {name} missing");
	}
	let pairs = v["key_equality"].as_array().unwrap();
	assert!(pairs.iter().any(|p| p["refused"] == true) && pairs.iter().any(|p| p["refused"] == false), "both outcomes");
	for name in ["true_and_int_1", "int_and_float64", "nan_twice", "str_and_bin", "array_twice", "timestamp_32_and_64"] {
		assert!(has("key_equality", name), "key_equality {name} missing");
	}
	let fields = |hex_str: &str| rmpv::decode::read_value(&mut Cursor::new(hex(hex_str))).expect("fields msgpack");
	for set in ["ops", "variants", "at_ms_encodings", "rejects", "sealed", "group_entries"] {
		for vector in v[set].as_array().unwrap() {
			let found = repeated_key(&fields(vector["fields_hex"].as_str().unwrap()));
			assert_eq!(found, None, "{set} {}: no vector outside refused repeats a key", vector["name"]);
		}
	}
	for vector in v["refused"].as_array().unwrap() {
		assert!(repeated_key(&fields(vector["fields_hex"].as_str().unwrap())).is_some(), "{}", vector["name"]);
	}
}

/// RFed SPEC §17.14 "Repeated keys" (James, 2026-10-11: parity with Python LXMF, whose umsgpack
/// raises DuplicateKeyException in `LXMessage.unpack_from_bytes`): a message whose payload holds a
/// map, at any depth, that repeats a key is refused whole on the direct path (the router's unpack)
/// and on the distro path (the unwrap), for the repeat and nothing else; each is signed by its
/// source. So no reader of the group entries or the group sync ever sees such a map.
#[test]
fn a_message_that_repeats_a_key_is_refused_whole_on_the_direct_and_the_distro_path() {
	let v = vectors();
	let mut d = identity(&v, "distro");
	let refused = v["refused"].as_array().expect("refused");
	assert_eq!(refused.len(), 11);
	for vector in refused {
		let name = vector["name"].as_str().unwrap();
		let packed = bytes(vector, "packed_hex");
		assert!(to_hex(&packed).ends_with(vector["fields_hex"].as_str().unwrap()), "{name}: the fields end the payload");
		match LXMessage::unpack_from_bytes(&packed, None) {
			Ok(_) => panic!("{name}: the direct path must refuse it"),
			Err(e) => assert!(e.contains("repeats a key"), "{name}: refused for the repeat, not for {e}"),
		}
		let blob = [packed[..16].to_vec(), d.encrypt(&packed[16..]).unwrap()].concat();
		match unwrap_blob(&mut d, &blob) {
			Ok(m) => panic!("{name}: the distro path must refuse it, not read {:?}", m.map(|m| m.to_json())),
			Err(e) => assert!(e.contains("repeats a key"), "{name}: refused for the repeat, not for {e}"),
		}
	}
}

/// Two keys are one key exactly when Python takes them for one (`key_equality`): an integer, a
/// float and a boolean of one value whatever the encoding, a str by its code points and never a
/// bin, an ext by type and data (a timestamp by its instant), NaN no key's equal, an array key
/// never compared. A message the reference reads is read here, its fields as sent.
#[test]
fn two_keys_are_one_key_exactly_when_python_takes_them_for_one() {
	let v = vectors();
	let mut d = identity(&v, "distro");
	let pairs = v["key_equality"].as_array().expect("key_equality");
	assert_eq!(pairs.len(), 22);
	for vector in pairs {
		let name = vector["name"].as_str().unwrap();
		let refused = vector["refused"].as_bool().unwrap();
		let packed = bytes(vector, "packed_hex");
		let direct = LXMessage::unpack_from_bytes(&packed, None);
		assert_eq!(direct.is_err(), refused, "{name}: direct path, {:?}", direct.err());
		let blob = [packed[..16].to_vec(), d.encrypt(&packed[16..]).unwrap()].concat();
		match unwrap_blob(&mut d, &blob) {
			Err(e) => assert!(refused && e.contains("repeats a key"), "{name}: distro path refused it: {e}"),
			Ok(m) => {
				assert!(!refused, "{name}: the distro path must refuse it");
				let out = json(&m.expect("a blob for D").to_json());
				assert_eq!(STANDARD.decode(out["fields"].as_str().unwrap()).unwrap(), bytes(vector, "fields_hex"), "{name}");
			}
		}
	}
}

/// §19.1: the unwrap reports the hash Python computed and `packed == blob[..16] | plaintext`,
/// the group entries and the group sync; the verdict here is the unwrap's own (the phones'
/// group receipt then decides an accept or leave under the key it carries).
#[test]
fn the_unwrap_reports_hash_packed_group_entries_and_group_sync() {
	let v = vectors();
	let mut d = identity(&v, "distro");
	let member_hash = hex(v["member"]["lxmf_delivery_hash_hex"].as_str().unwrap());
	assert!(Identity::recall(&member_hash).is_none(), "M must not be known here");
	// §17.14 rule 2: G is hashed and verified over the payload bytes as received. The web's G (at_ms
	// as int 64, 0xd3) is not the form rmpv packs, so an unwrap that packed the payload again would
	// give it another hash and a failed signature; this vector holds that form.
	let web = v["sealed"].as_array().unwrap().iter().find(|s| s["name"] == "g_accept_web_form_int64_at_ms").expect("the web's G");
	let web_packed = bytes(web, "packed_hex");
	let mut repacked = Vec::new();
	rmpv::encode::write_value(&mut repacked, &rmpv::decode::read_value(&mut Cursor::new(&web_packed[96..])).unwrap()).unwrap();
	assert_ne!(repacked, web_packed[96..], "the web's G is not in the form rmpv packs");
	assert_ne!(full_hash(&[&web_packed[..32], &repacked[..]].concat()), bytes(web, "hash_hex"));
	for vector in v["sealed"].as_array().unwrap() {
		let name = vector["name"].as_str().unwrap();
		let expected = &vector["expected"];
		let blob = bytes(vector, "blob_hex");
		let msg = unwrap_blob(&mut d, &blob).unwrap().expect("a blob for D");
		assert_eq!(to_hex(&msg.hash), vector["hash_hex"].as_str().unwrap(), "{name}: hash");
		assert_eq!(msg.packed, bytes(vector, "packed_hex"), "{name}: packed");
		let plaintext = d.decrypt(&blob[16..]).unwrap();
		assert_eq!(msg.packed, [&blob[..16], &plaintext[..]].concat(), "{name}: blob[..16] | plaintext");
		assert_eq!(msg.packed.len(), 16 + plaintext.len());
		// The hash is LXMF's: full_hash(dest | src | payload) of the packed bytes.
		let mut hashed = msg.packed[..32].to_vec();
		hashed.extend_from_slice(&msg.packed[96..]);
		assert_eq!(full_hash(&hashed), msg.hash, "{name}");

		let out = json(&msg.to_json());
		assert_eq!(out["hash"], Json::String(to_hex(&msg.hash)), "{name}");
		for key in ["has_group_id", "group_id", "group_action", "group_name"] {
			assert_eq!(out[key], expected[key], "{name}: {key}");
		}
		assert_eq!(out["group_sync"], expected["group_sync"], "{name}: group_sync");
		// Before any receipt: the unwrap's own verdict, no key, no packed copy.
		assert_eq!(out["sender_key"], Json::Null, "{name}");
		assert_eq!(out["packed"], Json::Null, "{name}");
		let own_verdict = if name.starts_with("g_") { (true, 0) } else { (false, 1) };
		assert_eq!(
			(out["signature_validated"].as_bool().unwrap(), out["unverified_reason"].as_u64().unwrap()),
			own_verdict,
			"{name}: D's own G validates under the distro key; M is unknown here"
		);
		assert_eq!(out["content"], vector["content"], "{name}");
		assert_eq!(STANDARD.decode(out["fields"].as_str().unwrap()).unwrap(), bytes(vector, "fields_hex"), "{name}");
	}
}

/// A blob to D from a fresh sender carrying `fields_raw` (msgpack bytes) as received.
fn blob_with_fields(d: &Identity, fields_raw: &[u8]) -> Vec<u8> {
	let sender = Identity::new(true);
	let src = delivery_hash(&sender).unwrap();
	let dest = delivery_hash(d).unwrap();
	let mut payload = vec![0x94];
	for item in [Value::F64(1_790_000_000.5), Value::Binary(Vec::new()), Value::Binary(b"x".to_vec())] {
		rmpv::encode::write_value(&mut payload, &item).unwrap();
	}
	payload.extend_from_slice(fields_raw);
	let mut hashed = [dest.clone(), src.clone(), payload.clone()].concat();
	let hash = full_hash(&hashed);
	hashed.extend_from_slice(&hash);
	let sig = sender.sign(&hashed);
	[dest, d.encrypt(&[src, sig, payload].concat()).unwrap()].concat()
}

#[test]
fn the_unwrap_reads_the_group_entries_by_the_fields_alone() {
	let v = vectors();
	let mut d = identity(&v, "distro");
	for vector in v["group_entries"].as_array().unwrap() {
		let name = vector["name"].as_str().unwrap();
		let expected = &vector["expected"];
		let blob = blob_with_fields(&d, &bytes(vector, "fields_hex"));
		let msg = unwrap_blob(&mut d, &blob).unwrap().unwrap();
		let out = json(&msg.to_json());
		for key in ["has_group_id", "group_id", "group_action", "group_name"] {
			assert_eq!(out[key], expected[key], "{name}: {key}");
		}
		assert_eq!(!out["group_sync"].is_null(), expected["group_sync"].as_bool().unwrap(), "{name}: group_sync");
	}
}
