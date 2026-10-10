//! Runs tests/distro_sync_vectors.json, the golden vector of the distro sync
//! proof (RFed SPEC §17.13, DISTRO-SYNC-PROOF-DESIGN.md §4), against
//! lxmf_rust::distro. The vector was made with the Python reference by
//! tests/distro_sync_vectors.py; RFed and Retichat-js assert the same bytes.

use std::io::Cursor;

use lxmf_rust::distro::{
	decode_sync_extension, delivery_hash, propagation_payload, sealed_upload, seal_for_sync, sync_signed_bytes,
	sync_transient_id, unwrap_blob, verify_sync_claim, SyncClaim,
};
use lxmf_rust::lx_stamper::validate_pn_stamp;
use reticulum_rust::identity::Identity;
use rmpv::Value;
use serde_json::Value as Json;

/// Pinned here as well as in the JSON, so a regenerated file cannot move them.
const SIGNED_HEX: &str = "726665642e64697374726f2e73796e6301fae321c442e3c9bdcd7a3e79d850e03c\
	2b850d7a663f9813dbb8e55996b7a526f0e70827aead3e0ab972c9d80276b9d2";
const SIG_HEX: &str = "ed816e06936c1bcf6801784b7ec84f75d0edf2bab472c3235e761781b88bccdb\
	8411c187c3a04530a9a9971c8c15b9430f0de213ab50b44b4142908d8b98f708";

fn vectors() -> Json {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/distro_sync_vectors.json");
	serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse vectors")
}

fn hex(s: &str) -> Vec<u8> {
	let s: String = s.split_whitespace().collect();
	assert!(s.len() % 2 == 0, "odd hex {s}");
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn bytes(v: &Json, key: &str) -> Vec<u8> {
	hex(v[key].as_str().unwrap_or_else(|| panic!("{key} missing")))
}

struct Vector {
	distro: Identity,
	d_hash: [u8; 16],
	sealed: Vec<u8>,
	transient_id: [u8; 32],
	claim: SyncClaim,
	stamp: Vec<u8>,
	timebase: f64,
	v: Json,
}

fn vector() -> Vector {
	let v = vectors();
	let distro = Identity::from_bytes(&bytes(&v["distro"], "private_key_hex")).expect("D");
	let d_hash: [u8; 16] = delivery_hash(&distro).unwrap().try_into().unwrap();
	let sealed = bytes(&v, "sealed_hex");
	let transient_id = sync_transient_id(&sealed);
	let claim = SyncClaim::for_sealed(&sealed, &distro.get_public_key().unwrap(), &bytes(&v, "sig_hex")).unwrap();
	let stamp = bytes(&v, "stamp_hex");
	let timebase = v["timebase"].as_f64().unwrap();
	Vector { distro, d_hash, sealed, transient_id, claim, stamp, timebase, v }
}

#[test]
fn the_distro_is_rebuilt_from_its_private_key() {
	let x = vector();
	let d = &x.v["distro"];
	assert_eq!(x.distro.get_public_key().unwrap(), bytes(d, "public_key_hex"));
	assert_eq!(x.distro.hash.clone().unwrap(), bytes(d, "identity_hash_hex"));
	assert_eq!(x.d_hash.to_vec(), bytes(d, "lxmf_delivery_hash_hex"));
	assert_eq!(x.sealed[..16], x.d_hash, "sealed[0..16] is D_hash");
	assert_eq!(bytes(&x.v, "packed_hex")[..16], x.d_hash);
}

#[test]
fn the_signed_bytes_and_the_signature_are_the_pinned_ones() {
	let x = vector();
	assert_eq!(x.transient_id.to_vec(), bytes(&x.v, "transient_id_hex"));
	assert_eq!(x.claim.id.to_vec(), bytes(&x.v, "id_hex"));
	assert_eq!(x.claim.id[..], x.transient_id[..16]);

	let signed = sync_signed_bytes(&x.d_hash, &x.transient_id);
	assert_eq!(signed.to_vec(), bytes(&x.v, "signed_hex"));
	assert_eq!(signed.to_vec(), hex(SIGNED_HEX));
	assert_eq!(signed[16], 0x01);

	// Ed25519 is deterministic: Rust signs exactly what Python RNS signed.
	let sig = x.distro.sign(&signed);
	assert_eq!(sig, bytes(&x.v, "sig_hex"));
	assert_eq!(sig, hex(SIG_HEX));
	assert_eq!(verify_sync_claim(&x.claim, &x.transient_id, &x.sealed), Ok(()));
}

#[test]
fn the_sealed_message_is_the_distros_own_sent_copy() {
	let mut x = vector();
	let message = unwrap_blob(&mut x.distro, &x.sealed).unwrap().expect("a blob for D");
	assert!(message.signature_validated);
	let m = &x.v["message"];
	assert_eq!(message.content, m["content"].as_str().unwrap());
	assert_eq!(message.timestamp, m["timestamp"].as_f64().unwrap());
	assert_eq!(message.sent_to.as_deref(), m["sent_to"].as_str());
	assert_eq!(message.sent_by.as_deref(), m["sent_by"].as_str());
	assert_eq!(x.distro.decrypt(&x.sealed[16..]).unwrap(), bytes(&x.v, "packed_hex")[16..]);
}

#[test]
fn the_stamp_is_valid_at_the_pinned_cost() {
	let x = vector();
	let lxmf_data = bytes(&x.v, "lxmf_data_hex");
	assert_eq!(lxmf_data, [x.sealed.clone(), x.stamp.clone()].concat());
	let cost = x.v["stamp_cost"].as_u64().unwrap() as u32;
	let (transient_id, lxm_data, value, stamp) = validate_pn_stamp(&lxmf_data, cost).expect("valid stamp");
	assert_eq!(transient_id, x.transient_id.to_vec());
	assert_eq!(lxm_data, x.sealed);
	assert_eq!(stamp, x.stamp);
	assert_eq!(value as u64, x.v["stamp_value"].as_u64().unwrap());
}

#[test]
fn the_envelopes_are_python_umsgpacks_bytes() {
	let x = vector();
	let with_claim = sealed_upload(&x.sealed, &x.stamp, Some(&x.claim), x.timebase).unwrap();
	assert_eq!(with_claim, bytes(&x.v, "envelope_hex"));
	assert!(with_claim.ends_with(&bytes(&x.v, "extension_hex")));

	let legacy = sealed_upload(&x.sealed, &x.stamp, None, x.timebase).unwrap();
	assert_eq!(legacy, bytes(&x.v, "envelope_legacy_hex"));
	assert_eq!(propagation_payload(x.timebase, &bytes(&x.v, "lxmf_data_hex")), legacy);
}

#[test]
fn rfed_reads_the_claim_from_the_envelope() {
	let x = vector();
	let items = match rmpv::decode::read_value(&mut Cursor::new(bytes(&x.v, "envelope_hex"))).unwrap() {
		Value::Array(items) => items,
		other => panic!("not an array: {other:?}"),
	};
	assert_eq!(items.len(), 3);
	let claims = decode_sync_extension(&items[2], 1);
	assert_eq!(claims.by_id.len(), 1);
	assert_eq!(claims.by_id[&x.claim.id], x.claim);
	assert_eq!((claims.malformed, claims.duplicate, claims.ignored), (0, 0, 0));
}

#[test]
fn sealing_again_makes_another_message_that_proves_itself() {
	// The encryption is random, so the vector's sealed bytes are input, not
	// something seal_for_sync reproduces; a new sealing verifies on its own
	// terms and does not carry the vector's claim.
	let x = vector();
	let packed = bytes(&x.v, "packed_hex");
	let again = seal_for_sync(&x.distro, &packed).unwrap();
	assert_ne!(again.sealed, x.sealed);
	let transient_id = sync_transient_id(&again.sealed);
	let claim = SyncClaim::for_sealed(&again.sealed, &x.distro.get_public_key().unwrap(), &again.sig).unwrap();
	assert_eq!(verify_sync_claim(&claim, &transient_id, &again.sealed), Ok(()));
	assert!(verify_sync_claim(&x.claim, &transient_id, &again.sealed).is_err());
}
