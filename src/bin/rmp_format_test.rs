/// Test rmp_serde ByteBuf vs Vec<u8> format behavior
/// Usage: rmp_format_test

fn main() {
    use rmp_serde::{to_vec, from_slice};
    use serde_bytes::ByteBuf;
    use std::collections::HashMap;
    
	let test_32bytes: Vec<u8> = (0..32u8).collect();
    
    // Serialize Vec<Vec<u8>> (array-of-array format - what destination.rs does)
    let ratchets_as_vecs: Vec<Vec<u8>> = vec![test_32bytes.clone(), vec![0xABu8; 32]];
    let packed_as_vecs = to_vec(&ratchets_as_vecs).unwrap();
    
    eprintln!("=== rmp_serde format test ===");
    eprintln!("Packed Vec<Vec<u8>> ({} bytes), first 8: {}", 
        packed_as_vecs.len(),
        packed_as_vecs[..8].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
    // 0x92 (fixarray len=2), 0xdc 0x00 0x20 (array16 len=32), then 32 ints...
    // OR: 0xc4 0x20 (bin8 len=32), then 32 raw bytes?
    
    // Try reading back as Vec<serde_bytes::ByteBuf>
    match from_slice::<Vec<serde_bytes::ByteBuf>>(&packed_as_vecs) {
        Ok(result) => eprintln!("ByteBuf from array-of-array: OK, {} items, first len={}", result.len(), result[0].len()),
        Err(e) => eprintln!("ByteBuf from array-of-array: FAILED - {}", e),
    }
    
    // Try reading back as Vec<Vec<u8>>
    match from_slice::<Vec<Vec<u8>>>(&packed_as_vecs) {
        Ok(result) => eprintln!("Vec<u8> from array-of-array: OK, {} items", result.len()),
        Err(e) => eprintln!("Vec<u8> from array-of-array: FAILED - {}", e),
    }
    
    // Now test with serde_bytes::ByteBuf as the inner type (produces bin format)
    let ratchets_as_bufs: Vec<ByteBuf> = vec![ByteBuf::from(test_32bytes.clone()), ByteBuf::from(vec![0xABu8; 32])];
    let packed_as_bufs = to_vec(&ratchets_as_bufs).unwrap();
    
    eprintln!("\nPacked Vec<ByteBuf> ({} bytes), first 8: {}", 
        packed_as_bufs.len(),
        packed_as_bufs[..8].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
    
    // Try reading back as Vec<ByteBuf>
    match from_slice::<Vec<ByteBuf>>(&packed_as_bufs) {
        Ok(result) => eprintln!("ByteBuf from bin: OK, {} items", result.len()),
        Err(e) => eprintln!("ByteBuf from bin: FAILED - {}", e),
    }
    
    // Cross-format: try reading array-of-array as ByteBuf and vice versa
    eprintln!("\nCross format test:");
    match from_slice::<Vec<ByteBuf>>(&packed_as_vecs) {
        Ok(result) => eprintln!("ByteBuf reading array-format: OK, {} items", result.len()),
        Err(e) => eprintln!("ByteBuf reading array-format: FAILED - {}", e),
    }
    match from_slice::<Vec<Vec<u8>>>(&packed_as_bufs) {
        Ok(result) => eprintln!("Vec<u8> reading bin-format: OK, {} items", result.len()),
        Err(e) => eprintln!("Vec<u8> reading bin-format: FAILED - {}", e),
    }
    
    // Test with actual ratchet file
    let ratchet_file = "cli-tests/lxmf_storage/rust_receiver/lxmf/ratchets/4c0c6c7f420da5df5203554462cbb3bc.ratchets";
    if std::path::Path::new(ratchet_file).exists() {
        eprintln!("\n=== Actual ratchet file test ===");
        let file_data = std::fs::read(ratchet_file).unwrap();
        
        // Try outer decode
        match from_slice::<HashMap<String, serde_bytes::ByteBuf>>(&file_data) {
            Ok(outer) => {
                eprintln!("Outer decode: keys = {:?}", outer.keys().collect::<Vec<_>>());
                if let Some(ratchets_blob) = outer.get("ratchets") {
                    eprintln!("ratchets blob: {} bytes, first 8: {}", 
                        ratchets_blob.len(),
                        ratchets_blob[..8].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
                    
                    // Try Vec<ByteBuf>
                    match from_slice::<Vec<serde_bytes::ByteBuf>>(&ratchets_blob) {
                        Ok(r) => eprintln!("Ratchets as Vec<ByteBuf>: {} items", r.len()),
                        Err(e) => eprintln!("Ratchets as Vec<ByteBuf>: FAILED - {}", e),
                    }
                    
                    // Try Vec<Vec<u8>>
                    match from_slice::<Vec<Vec<u8>>>(&ratchets_blob) {
                        Ok(r) => eprintln!("Ratchets as Vec<Vec<u8>>: {} items, first len={}", r.len(), r[0].len()),
                        Err(e) => eprintln!("Ratchets as Vec<Vec<u8>>: FAILED - {}", e),
                    }
                }
            }
            Err(e) => eprintln!("Outer decode failed: {}", e),
        }
    } else {
        eprintln!("\nRatchet file not found at: {}", ratchet_file);
    }
}
