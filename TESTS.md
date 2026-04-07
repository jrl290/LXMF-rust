# LXMF-rust Tests

Debug/test binaries in `src/bin/`.  Build with:

```bash
cargo build --bin decrypt_test
cargo build --bin rmp_format_test
```

---

| Binary | What It Tests | Usage |
|--------|---------------|-------|
| `src/bin/decrypt_test.rs` | Decrypt hex-encoded LXMF ciphertext directly (bypasses network).  Used with `test_ratchet_encrypt.py` and `test_multi_ratchet.py` to verify Rust decryption matches Python encryption. | `cargo run --bin decrypt_test -- <hex_ciphertext>` |
| `src/bin/rmp_format_test.rs` | Test `rmp_serde` ByteBuf vs `Vec<u8>` serialisation format — ensures cross-language msgpack compatibility between Rust and Python. | `cargo run --bin rmp_format_test` |
