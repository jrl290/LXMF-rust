//! RFed SPEC §17.14 "Repeated keys" (James, 2026-10-11: parity with Python LXMF): a message whose
//! payload repeats a key is refused whole with ONE log line, on the router's direct path, the
//! unpack, the distro unwrap, a channel post and a stored container; the router never delivers
//! it. Its own test binary, because it installs the process's log callback.

use std::sync::{Arc, Mutex};

use lxmf_rust::channel;
use lxmf_rust::distro::unwrap_blob;
use lxmf_rust::lx_message::LXMessage;
use lxmf_rust::msgpack_keys;
use lxmf_rust::LXMRouter;
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use serde_json::Value as Json;

fn hex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

#[test]
fn a_refusal_is_logged_once_on_each_path_and_never_delivered() {
	let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
	let sink = lines.clone();
	reticulum_rust::ffi::set_log_callback(move |line| sink.lock().unwrap().push(line));
	reticulum_rust::set_loglevel(reticulum_rust::LOG_DEBUG);
	// The lines since the last call, and how many of them say `text`.
	let said = |text: &str| -> usize {
		let mut lines = lines.lock().unwrap();
		let n = lines.iter().filter(|l| l.contains(text)).count();
		lines.clear();
		n
	};

	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/distro_group_sync_vectors.json");
	let v: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
	let mut d = Identity::from_bytes(&hex(v["distro"]["private_key_hex"].as_str().unwrap())).unwrap();
	let refused: Vec<&Json> = v["refused"].as_array().unwrap().iter().collect();
	assert!(refused.len() >= 11);

	let storage = std::env::temp_dir().join(format!("lxmf-repeated-keys-log-{}", std::process::id()));
	let router = LXMRouter::new(
		Some(Identity::new(true)), storage.to_string_lossy().into_owned(), None, None, None, None, None,
		false, false, Vec::new(), None, false, 0, 0, 0, 0, 0, None,
	)
	.expect("router");
	let delivered = Arc::new(Mutex::new(0usize));
	let count = delivered.clone();
	router.lock().unwrap().register_delivery_callback(Arc::new(move |_: &LXMessage| *count.lock().unwrap() += 1));
	said("");

	for vector in refused {
		let name = vector["name"].as_str().unwrap();
		let packed = hex(vector["packed_hex"].as_str().unwrap());

		assert!(LXMessage::unpack_from_bytes(&packed, None).is_err(), "{name}");
		assert_eq!(said("repeats a key"), 1, "{name}: the unpack logs its refusal once");

		let blob = [packed[..16].to_vec(), d.encrypt(&packed[16..]).unwrap()].concat();
		assert!(unwrap_blob(&mut d, &blob).is_err(), "{name}");
		assert_eq!(said("repeats a key"), 1, "{name}: the unwrap logs its refusal once");

		let accepted = router.lock().unwrap().lxmf_delivery(
			&packed, Some(DestinationType::Single), None, None, Some(LXMessage::DIRECT), true, true,
		);
		assert!(!accepted, "{name}: the router refuses it");
		let lines_now = lines.lock().unwrap().clone();
		assert_eq!(said("repeats a key"), 1, "{name}: the router's refusal is one line: {lines_now:#?}");
	}
	assert_eq!(*delivered.lock().unwrap(), 0, "nothing refused is delivered");

	// Any other unpack failure is still the router's own line.
	let mut garbage = hex(v["refused"][0]["packed_hex"].as_str().unwrap())[..96].to_vec();
	garbage.push(0xc1); // a reserved msgpack marker
	assert!(!router.lock().unwrap().lxmf_delivery(
		&garbage, Some(DestinationType::Single), None, None, Some(LXMessage::DIRECT), true, true,
	));
	assert_eq!(said("unpack FAILED"), 1);

	// A channel post (lxmf_rust::channel::unpack) carrying each refused payload, from a sender
	// whose prelude key binds to its source: refused with one line, an error is_refusal knows,
	// and the sender's key never remembered.
	const CHANNEL: &str = "public.repeated-keys";
	for vector in v["refused"].as_array().unwrap() {
		let name = vector["name"].as_str().unwrap();
		let packed = hex(vector["packed_hex"].as_str().unwrap());
		let sender = Identity::new(true);
		let sender_pub = sender.get_public_key().unwrap();
		let source = channel::lxmf_delivery_hash_for_public_key(&sender_pub).unwrap();
		let mut plaintext = channel::PRELUDE_MAGIC.to_vec();
		plaintext.extend_from_slice(&sender_pub);
		plaintext.extend_from_slice(&source);
		plaintext.extend_from_slice(&packed[32..]); // the vector's signature and payload
		let mut wire = channel::channel_id_hash(CHANNEL).unwrap();
		wire.extend_from_slice(&channel::channel_destination(CHANNEL).unwrap().encrypt(&plaintext).unwrap());

		let err = channel::unpack(CHANNEL, &wire).expect_err(name);
		assert!(msgpack_keys::is_refusal(&err), "{name}: the channel unpack's error is a refusal: {err}");
		assert_eq!(said("repeats a key"), 1, "{name}: the channel unpack logs its refusal once");
		assert_eq!(Identity::recall_public_key(&source), None, "{name}: the sender's key is not remembered");
	}

	// A stored message container (LXMessage::unpack_from_file) that repeats a key is refused as
	// LXMF.py's umsgpack refuses it, with one line; the same container without the repeat is read.
	let destination = Destination::new_outbound(
		Some(Identity::new(true)), DestinationType::Single, "lxmf".into(), vec!["delivery".into()],
	)
	.unwrap();
	let source = Destination::new_outbound(
		Some(Identity::new(true)), DestinationType::Single, "lxmf".into(), vec!["delivery".into()],
	)
	.unwrap();
	let mut message = LXMessage::new(
		Some(destination), Some(source), Some(b"stored".to_vec()), Some(Vec::new()), None,
		Some(LXMessage::DIRECT), None, None, None, false,
	)
	.unwrap();
	let container = message.packed_container().unwrap();
	let mut entries = match rmpv::decode::read_value(&mut &container[..]).unwrap() {
		rmpv::Value::Map(entries) => entries,
		other => panic!("container is not a map: {other}"),
	};
	let stored = |bytes: &[u8], file: &str| {
		let path = storage.join(file);
		std::fs::create_dir_all(&storage).unwrap();
		std::fs::write(&path, bytes).unwrap();
		LXMessage::unpack_from_file(&std::fs::File::open(&path).unwrap())
	};
	said("");
	assert_eq!(stored(&container, "kept").expect("the container is read").content, b"stored");
	assert_eq!(said("repeats a key"), 0);
	entries.push((rmpv::Value::from("state"), rmpv::Value::from(0)));
	let mut twice = Vec::new();
	rmpv::encode::write_value(&mut twice, &rmpv::Value::Map(entries)).unwrap();
	let err = stored(&twice, "state_twice").err().expect("a container that repeats a key is refused");
	assert!(msgpack_keys::is_refusal(&err) && err.contains("repeats a key"), "{err}");
	assert_eq!(said("repeats a key"), 1, "the stored container's refusal is one line");
	let _ = std::fs::remove_dir_all(&storage);
}
