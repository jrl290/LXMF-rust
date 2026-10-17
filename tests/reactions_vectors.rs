//! Runs tests/reactions_vectors.json, a copy of Retichat-js's
//! reactions_vectors.json (REACTIONS-DESIGN.md revision 2): the Distro Sync of
//! Group actions with a post id after `left` and the `react` op (RFed SPEC
//! §17.14), as the web writes and reads them, against lxmf_rust::distro, so
//! the web and both phones agree on the bytes. Only whether `problem` is null
//! is compared: its wording is each client's own. The web's JSON names a
//! react's reaction `content`; LXMF-rust's carries it in `text`.

use std::io::Cursor;

use lxmf_rust::distro::{read_group_sync, set_group_sync_fields, GroupSync, GroupSyncOp};
use lxmf_rust::lx_message::LXMessage;
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use rmpv::Value;
use serde_json::Value as Json;

fn vectors() -> Json {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reactions_vectors.json");
	serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse vectors")
}

fn hex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn to_hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn entries(fields_hex: &str) -> Vec<(Value, Value)> {
	let raw = hex(fields_hex);
	match rmpv::decode::read_value(&mut Cursor::new(&raw[..])).expect("fields msgpack") {
		Value::Map(entries) => entries,
		other => panic!("fields are not a map: {other:?}"),
	}
}

/// A message from D to D: any identity's message, its hashes set to D's
/// (the vectors give D's address, not its key; nothing here signs).
fn message_d_to_d(d_hex: &str) -> LXMessage {
	let id = Some(Identity::new(true));
	let source = Destination::new_inbound(id, DestinationType::Single, "lxmf".into(), vec!["delivery".into()]).unwrap();
	let mut msg = LXMessage::new(None, Some(source), Some(Vec::new()), Some(Vec::new()), None,
		Some(LXMessage::PROPAGATED), Some(hex(d_hex)), None, None, false).unwrap();
	msg.source_hash = hex(d_hex);
	msg.destination_hash = hex(d_hex);
	msg
}

#[test]
fn the_web_vectors_read_and_write_the_same_in_rust() {
	let v = vectors();
	let d_hex = v["distro_lxmf_delivery_hash_hex"].as_str().unwrap();
	let device = v["device_hex"].as_str().unwrap();
	let vectors = v["group_sync"].as_array().unwrap();
	assert!(vectors.len() >= 17);
	let (mut read_ok, mut refused, mut written) = (0, 0, 0);
	for vector in vectors {
		let name = vector["name"].as_str().unwrap();
		let expected = &vector["expected"];
		let read = read_group_sync(&entries(vector["fields_hex"].as_str().unwrap()), d_hex).expect("a group sync");
		assert_eq!(read.by, expected["by"].as_str().unwrap(), "{name}: by");
		let sync = match (&read.sync, expected["problem"].is_null()) {
			(Ok(sync), true) => sync,
			(Err(_), false) => {
				refused += 1;
				continue;
			}
			(got, _) => panic!("{name}: Rust reads {got:?}, the web's problem is {}", expected["problem"]),
		};
		assert_eq!(sync.op.as_str(), expected["op"].as_str().unwrap(), "{name}: op");
		assert_eq!(sync.group_id, expected["group_id"].as_str().unwrap(), "{name}: group_id");
		assert_eq!(sync.at_ms, expected["at_ms"].as_u64().unwrap(), "{name}: at_ms");
		let left: Vec<String> = serde_json::from_value(expected["left"].clone()).unwrap();
		assert_eq!(sync.left, left, "{name}: left");
		let text = if sync.op == GroupSyncOp::React { &expected["content"] } else { &expected["text"] };
		assert_eq!(sync.text.as_deref(), text.as_str(), "{name}: text / content");
		assert_eq!(sync.post_id.as_deref(), expected["post_id"].as_str(), "{name}: post_id");
		read_ok += 1;

		if vector["writer"].as_bool() == Some(true) {
			let mut msg = message_d_to_d(d_hex);
			set_group_sync_fields(&mut msg, sync, d_hex, device).unwrap_or_else(|e| panic!("{name}: {e}"));
			let mut fields = Vec::new();
			rmpv::encode::write_value(&mut fields, &msg.fields).unwrap();
			assert_eq!(to_hex(&fields), vector["fields_hex"].as_str().unwrap(), "{name}: Rust writes the web's bytes");
			let json = sync.to_json();
			assert_eq!(GroupSync::from_json(&json).as_ref(), Ok(sync), "{name}: the JSON form round-trips");
			written += 1;
		}
	}
	assert_eq!((read_ok, refused, written), (11, 6, 5), "every vector was checked");
}
