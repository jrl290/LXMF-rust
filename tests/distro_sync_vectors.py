"""Writes tests/distro_sync_vectors.json: the golden vector of the distro sync
proof (RFed SPEC §17.13, DISTRO-SYNC-PROOF-DESIGN.md §4), made with the
Python reference (RNS 1.5.2, LXMF 1.1.1, RNS's vendored umsgpack), so that
LXMF-rust (tests/distro_sync_vectors.rs), RFed and Retichat-js assert the
same bytes against an implementation that is not their own.

Run from anywhere with the workspace venv:

    /Users/james/Offline/Reticulum/.venv/bin/python -I LXMF-rust/tests/distro_sync_vectors.py

The output is the same on every run. D's private key is fixed, the packed
message is packed from fixed values, Ed25519 is deterministic, and the stamp
is the first of a fixed sequence that is valid at STAMP_COST. Only the
encryption to D is random (an ephemeral key and an IV), so SEALED_HEX holds
the output of one RNS Identity.encrypt of the packed message, made once with
--new-sealed and fixed here. The script checks that it decrypts to the packed
message before using it. Do not replace it: every pinned value below follows
from it.
"""

import hashlib
import json
import os
import sys

import RNS
import RNS.vendor.umsgpack as msgpack
from LXMF import LXStamper

# D's private key: X25519 private key (32) | Ed25519 seed (32).
PRIVATE_KEY = bytes(range(64))

# The LXMF message D packs to itself: a §17.11 sent copy.
TIMESTAMP = 1790000000.5
TITLE = b""
CONTENT = b"distro sync golden vector"
SENT_TO = "ab" * 16
SENT_BY = "cd" * 16
FIELD_CUSTOM_TYPE = 0xFB
FIELD_CUSTOM_DATA = 0xFC
FIELD_CUSTOM_META = 0xFD
DISTRO_SENT_TYPE = "rfed.distro.sent"

# The upload around it.
TIMEBASE = 1790000001.25
STAMP_COST = 16  # LXMRouter.PROPAGATION_COST

SYNC_KEY = "rfed.distro.sync"
SYNC_TAG = b"rfed.distro.sync"
SYNC_VERSION = 0x01

# One RNS Identity.encrypt of packed[16:] to D, made with --new-sealed.
ENCRYPTED_HEX = (
    "6cbcccb1214d94344d2b7be960a8b1cc998d25da35248d23ac9c38c3dabe2c42"
    "690715fad7e0d8bb7da81f1030cd9f42866bc5d6aab95986611eae95764ee5e1"
    "9150e99a218eb5aaa0d1030bb46435f43576d6a32148547330b1f24be8a40b0a"
    "ce57101d02e9d2cda7a23e6ea83bc100efb321779c4e91feafda72dd0cb31530"
    "6618318c1ba5efdb90e93e63175a3f28ee1e7285685881f589b093f1727c4092"
    "bb97f38e7d30e69a9d53b4ba61dffa6c2b47ed23a20b23f2e2d234d2b5e542af"
    "b0be0d4d4e3742fc6104268ed2ec30663912e0676212e1ac8c0e641d9019bb25"
    "ef353a51db68e51c828f095da26c1967a88f9c8679ea92d570295266ab52607f"
    "781f7f0f67a0ee572090288cb0deb3a0cbb137ed420fb8ad1ccb7e9169ed5421"
    "358fe16266f1fbcee765644bdda20f52"
)


def packed_message(d, d_hash):
    fields = {
        FIELD_CUSTOM_TYPE: DISTRO_SENT_TYPE,
        FIELD_CUSTOM_DATA: SENT_TO,
        FIELD_CUSTOM_META: SENT_BY,
    }
    payload = [TIMESTAMP, TITLE, CONTENT, fields]
    packed_payload = msgpack.packb(payload)
    # LXMessage.pack: the signature is over dest | src | payload | hash.
    hashed_part = d_hash + d_hash + packed_payload
    message_hash = RNS.Identity.full_hash(hashed_part)
    signature = d.sign(hashed_part + message_hash)
    return d_hash + d_hash + signature + packed_payload


def signed_bytes(d_hash, transient_id):
    out = SYNC_TAG + bytes([SYNC_VERSION]) + d_hash + transient_id
    assert len(out) == 65
    return out


def mine_stamp(transient_id, cost):
    """The first stamp of a fixed sequence that is valid at `cost`, so the
    vector is reproducible (LXStamper's own miner starts from random)."""
    workblock = LXStamper.stamp_workblock(transient_id, expand_rounds=LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN)
    prefix = hashlib.sha256(workblock)
    target = 1 << (256 - cost)
    n = 0
    while True:
        stamp = RNS.Identity.full_hash(b"rfed.distro.sync golden stamp" + n.to_bytes(4, "big"))
        h = prefix.copy()
        h.update(stamp)
        if int.from_bytes(h.digest(), "big") <= target:
            assert LXStamper.stamp_valid(stamp, cost, workblock)
            return stamp, LXStamper.stamp_value(workblock, stamp)
        n += 1


def main():
    d = RNS.Identity.from_bytes(PRIVATE_KEY)
    d_hash = RNS.Destination.hash(d, "lxmf", "delivery")
    packed = packed_message(d, d_hash)

    if "--new-sealed" in sys.argv:
        print(d.encrypt(packed[16:]).hex())
        return
    assert ENCRYPTED_HEX, "run once with --new-sealed and fix ENCRYPTED_HEX"

    encrypted = bytes.fromhex(ENCRYPTED_HEX)
    assert d.decrypt(encrypted) == packed[16:], "ENCRYPTED_HEX is not packed[16:] encrypted to D"
    sealed = d_hash + encrypted
    transient_id = RNS.Identity.full_hash(sealed)
    claim_id = transient_id[:16]
    signed = signed_bytes(d_hash, transient_id)
    sig = d.sign(signed)
    assert d.validate(sig, signed)
    public_key = d.get_public_key()

    stamp, stamp_value = mine_stamp(transient_id, STAMP_COST)
    lxmf_data = sealed + stamp
    t_id, lxm_data, value, _ = LXStamper.validate_pn_stamp(lxmf_data, STAMP_COST)
    assert t_id == transient_id and lxm_data == sealed and value == stamp_value

    claim = [claim_id, public_key, sig]
    extension = {SYNC_KEY: [claim]}
    envelope = msgpack.packb([TIMEBASE, [lxmf_data], extension])
    # LXMessage.py propagation_packed: msgpack.packb([time.time(), [lxmf_data]]).
    envelope_legacy = msgpack.packb([TIMEBASE, [lxmf_data]])

    # The Python oracle reads the envelope as three native elements.
    data = msgpack.unpackb(envelope)
    assert len(data) == 3
    assert isinstance(data[1], list) and data[1] == [lxmf_data]
    assert data[2] == {SYNC_KEY: [[claim_id, public_key, sig]]}
    assert envelope[0] == 0x93 and envelope_legacy[0] == 0x92
    extension_bytes = msgpack.packb(extension)
    assert envelope == b"\x93" + envelope_legacy[1:] + extension_bytes
    assert len(msgpack.packb(claim)) == 151 and len(extension_bytes) == 170

    out = {
        "spec": "RFed-rust SPEC §17.13 (distro sync proof); DISTRO-SYNC-PROOF-DESIGN.md §4.1, §4.2",
        "notes": [
            "Generated by LXMF-rust tests/distro_sync_vectors.py with the Python reference (RNS 1.5.2, LXMF 1.1.1, RNS.vendor.umsgpack); do not edit by hand. Checked by LXMF-rust tests/distro_sync_vectors.rs; for RFed and Retichat-js to assert the same bytes.",
            "All *_hex values are lowercase hex. distro.private_key_hex is the X25519 private key (32) | Ed25519 seed (32), so D can be rebuilt; lxmf_delivery_hash_hex is D_hash = Destination.hash(D, 'lxmf', 'delivery').",
            "packed_hex is the LXMF message D packed to itself (dest = src = D_hash), a §17.11 sent copy: dest(16) | src(16) | signature(64) | msgpack [timestamp, title, content, {0xFB: 'rfed.distro.sent', 0xFC: R, 0xFD: device}].",
            "sealed_hex = D_hash | D.encrypt(packed[16:]): LXMF's lxmf_data before the stamp, what RFed stores. The encryption is random, so these bytes are fixed input, not something an implementation reproduces; it reproduces everything that follows from them. transient_id_hex = SHA-256(sealed); id_hex = transient_id[0:16], RFed's distro_message_id.",
            "signed_hex (65 bytes) = 'rfed.distro.sync' (16 ASCII) | 0x01 | D_hash (16) | transient_id (32). sig_hex = D's Ed25519 signature over it (deterministic).",
            "stamp_hex is a PN stamp over transient_id valid at stamp_cost (workblock of 1000 rounds, LXStamper.WORKBLOCK_EXPAND_ROUNDS_PN); stamp_value is its value. lxmf_data_hex = sealed | stamp.",
            "envelope_hex is the client upload with the claim: msgpack [timebase f64, [bin lxmf_data], {str 'rfed.distro.sync': [[bin16 id, bin64 distro_pubkey, bin64 sig]]}], every value native msgpack. extension_hex is its third element alone. envelope_legacy_hex is the same upload without the claim: LXMF's two-element [timebase, [lxmf_data]].",
        ],
        "distro": {
            "private_key_hex": PRIVATE_KEY.hex(),
            "public_key_hex": public_key.hex(),
            "identity_hash_hex": d.hash.hex(),
            "lxmf_delivery_hash_hex": d_hash.hex(),
        },
        "message": {
            "timestamp": TIMESTAMP,
            "content": CONTENT.decode(),
            "sent_to": SENT_TO,
            "sent_by": SENT_BY,
        },
        "packed_hex": packed.hex(),
        "sealed_hex": sealed.hex(),
        "transient_id_hex": transient_id.hex(),
        "id_hex": claim_id.hex(),
        "signed_hex": signed.hex(),
        "sig_hex": sig.hex(),
        "stamp_cost": STAMP_COST,
        "stamp_hex": stamp.hex(),
        "stamp_value": stamp_value,
        "lxmf_data_hex": lxmf_data.hex(),
        "timebase": TIMEBASE,
        "extension_hex": extension_bytes.hex(),
        "envelope_hex": envelope.hex(),
        "envelope_legacy_hex": envelope_legacy.hex(),
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "distro_sync_vectors.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
