/// Decrypt hex-encoded LXMF ciphertext directly, bypassing network.
/// Usage: decrypt_test <hex_ciphertext>
///
/// Where hex_ciphertext is ephemeral_pub(32) + token_data
/// (i.e., the encrypted bytes WITHOUT the 16-byte destination hash prefix)

use reticulum_rust::identity::Identity;
use reticulum_rust::destination::{Destination, DestinationType};
use lxmf_rust::cli_util::to_hex;

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("Odd hex length".into()); }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|e| format!("bad hex at {}: {}", i, e)))
        .collect()
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: decrypt_test <hex_ciphertext>");
        eprintln!("  hex_ciphertext: ephemeral_pub(32) + Token(IV+ciphertext+HMAC)");
        return Err("Missing argument".to_string());
    }

    let ciphertext = hex_decode(&args[1])?;

    eprintln!("Ciphertext: {} bytes", ciphertext.len());
    if ciphertext.len() > 32 {
        eprintln!("Ephemeral pub: {}", to_hex(&ciphertext[..32]));
        eprintln!("Token data: {} bytes", ciphertext.len() - 32);
    }

    // Load identity from KEY_2
    let key_b32 = "GVQDBB7XDWV3OFVM76ZY7QGBJVFMTJP5UKCDPD6M5UCCQBCEG7MVCLNQDPKG4HJ77GOAVZMKLSLWQDYYF33KEZFBXPQA6V4UUMUBYZY";
    let key_bytes = lxmf_rust::decode_key(key_b32)
        .map_err(|e| format!("decode_key: {}", e))?;
    let mut identity = Identity::from_bytes(&key_bytes)?;

    eprintln!("Identity hash: {}", identity.hash.as_ref().map(|h| to_hex(h)).unwrap_or("NONE".into()));

    // Create destination and load ratchets
    let ratchet_file = "cli-tests/lxmf_storage/rust_receiver/lxmf/ratchets/4c0c6c7f420da5df5203554462cbb3bc.ratchets";
    let mut dest = Destination::new_inbound(
        Some(identity.clone()),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )?;
    let _ = dest.enable_ratchets(ratchet_file.to_string());
    let ratchet_count = dest.ratchets.as_ref().map(|r| r.len()).unwrap_or(0);
    eprintln!("Loaded {} ratchets", ratchet_count);
    eprintln!("Dest hash: {}", to_hex(&dest.hash));

    // Try decrypt via Destination (same path as lxmf_propagation)
    match dest.decrypt(&ciphertext) {
        Ok(plaintext) => {
            eprintln!("\n=== DECRYPT SUCCESS ===");
            eprintln!("Plaintext ({} bytes): {:?}", plaintext.len(), String::from_utf8_lossy(&plaintext));
            println!("{}", to_hex(&plaintext));
            Ok(())
        }
        Err(e) => {
            eprintln!("\n=== DECRYPT FAILED: {} ===", e);
            Err("Decryption failed".to_string())
        }
    }
}
