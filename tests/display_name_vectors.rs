//! Runs tests/display_name_vectors.json (DISPLAY_NAMES.md §3) against
//! lxmf_rust::display_name. Retichat-js runs the same file.

use lxmf_rust::display_name::{clean, clean_announce, decode_fields_bytes, digest, NameField};
use serde_json::Value;

fn vectors() -> Value {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/display_name_vectors.json");
	serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse vectors")
}

fn hex(s: &str) -> Vec<u8> {
	assert!(s.len() % 2 == 0, "odd hex {s}");
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn run_clean(section: &str, f: fn(&[u8]) -> Option<String>) -> usize {
	let v = vectors();
	let cases = v[section].as_array().expect("section");
	let mut failures = Vec::new();
	for case in cases {
		let name = case["name"].as_str().unwrap();
		let got = f(&hex(case["input_hex"].as_str().unwrap()));
		let want = case["expected"].as_str().map(str::to_string);
		if got != want {
			failures.push(format!("{section} / {name}: got {got:?}, want {want:?}"));
		}
	}
	assert!(failures.is_empty(), "{} failure(s):\n{}", failures.len(), failures.join("\n"));
	cases.len()
}

#[test]
fn clean_vectors() {
	assert!(run_clean("clean", clean) >= 50);
}

#[test]
fn clean_announce_vectors() {
	assert!(run_clean("clean_announce", clean_announce) >= 8);
}

#[test]
fn decode_field_vectors() {
	let v = vectors();
	let mut failures = Vec::new();
	for case in v["decode_field"].as_array().unwrap() {
		let name = case["name"].as_str().unwrap();
		let got = decode_fields_bytes(&hex(case["fields_msgpack_hex"].as_str().unwrap()));
		let want = match case["state"].as_str().unwrap() {
			"absent" => NameField::Absent,
			"clear" => NameField::Clear,
			"name" => NameField::Name(case["display_name"].as_str().unwrap().to_string()),
			other => panic!("unknown state {other}"),
		};
		if got != want {
			failures.push(format!("decode_field / {name}: got {got:?}, want {want:?}"));
		}
	}
	assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn digest_vectors() {
	let v = vectors();
	for case in v["digest"].as_array().unwrap() {
		let input = case["input"].as_str().unwrap();
		let want = hex(case["digest_hex"].as_str().unwrap());
		let name = if input.is_empty() { None } else { Some(input) };
		assert_eq!(digest(name).to_vec(), want, "{}", case["name"]);
	}
}
