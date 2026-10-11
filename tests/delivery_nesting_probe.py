"""Measures where the Python reference refuses a nested payload on its real
delivery paths (RFed SPEC §17.14 "Nesting"; decided 2026-10-11: one limit,
Python's measured delivery-path depth). Its findings set NESTING_MAX_DEPTH and
DELIVERY_FRAMES in tests/distro_group_sync_vectors.py.

LXMF.py reads a message with RNS's umsgpack, which recurses two Python frames
for each level of nesting, so a deep enough payload raises RecursionError and
LXMRouter.lxmf_delivery drops the message ("Could not assemble LXMF message
from received data"). How deep is "deep enough" depends on the frames under
the unpack, so it is measured on the real paths, not on a bare call:

- a private three-process network on 127.0.0.1 (its own config directories
  under a temporary directory, no shared instance, one TCP server and two
  clients, nothing else): `node` (transport and a Python LXMF propagation
  node), `rx` (the receiver under test, at Python's default recursion limit),
  `tx` (the sender, which packs the deep fields and so raises its own limit);
- DIRECT: tx sends over a link; a message this large goes as a Resource
  (assemble -> delivery_resource_concluded -> lxmf_delivery);
- PROPAGATED: tx uploads to the node, rx asks the node for its messages
  (message_get_response -> lxmf_propagation -> lxmf_delivery).

For each path it first records the frames of the thread that runs
LXMessage.unpack_from_bytes (a profile hook in rx, on a shallow message),
then sends messages whose field 0x77 nests n arrays or maps, the innermost
empty or holding one value, at and past where the refusal is expected, and
reports what rx did with each: read (its delivery callback ran) or refused
(the router's "Could not assemble" line). It stops on any surprise.

Run with the workspace venv (about five minutes; nothing leaves 127.0.0.1):

    /Users/james/Offline/Reticulum/.venv/bin/python -I LXMF-rust/tests/delivery_nesting_probe.py

Measured 2026-10-11 (CPython 3.13.5, RNS 1.5.2, LXMF 1.1.1, limit 1000):
- PROPAGATED: the unpack is the 10th frame (_bootstrap, _bootstrap_inner, run,
  job, handle_response, response_received, message_get_response,
  lxmf_propagation, lxmf_delivery, unpack_from_bytes; the node's answer came
  as one packet). A field reads 492 nested arrays or maps whose innermost is
  empty, 491 whose innermost holds a nil, an int, a str or a bin; one more is
  refused. That is "no value deeper than 493" (the payload at depth 0, its
  fields map at 1, a field's value at 2), the shared limit.
- DIRECT (a Resource): the 7th frame (_bootstrap, _bootstrap_inner, run,
  assemble, delivery_resource_concluded, lxmf_delivery, unpack_from_bytes):
  494 innermost empty, 493 holding a nil or an int, 492 holding a str, a bin
  or a uint 8.
When the node's answer comes as a Resource instead (a slow link, or many
messages), the unpack is one frame deeper (assemble,
response_resource_concluded instead of job): an empty innermost still reads
at 492, and a str, a bin or a uint 8 innermost one level less (not run end to
end here; the generator's on_delivery_stack shows it with DELIVERY_FRAMES 11).
"""

import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

PYTHON = sys.executable
# (path, kind, innermost, nested levels in field 0x77, expected verdict)
EXPECTED = [
    ("PROPAGATED", "array", "empty", 492, "read"), ("PROPAGATED", "array", "empty", 493, "refused"),
    ("PROPAGATED", "map", "empty", 492, "read"), ("PROPAGATED", "map", "empty", 493, "refused"),
    ("PROPAGATED", "array", "nil", 491, "read"), ("PROPAGATED", "array", "nil", 492, "refused"),
    ("PROPAGATED", "array", "int", 491, "read"), ("PROPAGATED", "array", "int", 492, "refused"),
    ("PROPAGATED", "array", "str", 491, "read"), ("PROPAGATED", "array", "str", 492, "refused"),
    ("PROPAGATED", "map", "bin", 491, "read"), ("PROPAGATED", "map", "bin", 492, "refused"),
    ("DIRECT", "array", "empty", 494, "read"), ("DIRECT", "array", "empty", 495, "refused"),
    ("DIRECT", "map", "empty", 494, "read"), ("DIRECT", "map", "empty", 495, "refused"),
    ("DIRECT", "array", "int", 493, "read"), ("DIRECT", "array", "int", 494, "refused"),
    ("DIRECT", "array", "str", 492, "read"), ("DIRECT", "array", "str", 493, "refused"),
]
EXPECTED_FRAMES = {
    "PROPAGATED": ["_bootstrap", "_bootstrap_inner", "run", "job", "handle_response", "response_received",
                   "message_get_response", "lxmf_propagation", "lxmf_delivery", "unpack_from_bytes"],
    "DIRECT": ["_bootstrap", "_bootstrap_inner", "run", "assemble", "delivery_resource_concluded", "lxmf_delivery",
               "unpack_from_bytes"],
}


# --- One process of the private network ------------------------------------

def role_main(role, base, port):
    import RNS
    from LXMF import LXMRouter, LXMessage

    def emit(**kw):
        sys.stdout.write(json.dumps(kw) + "\n")
        sys.stdout.flush()

    cfgdir = os.path.join(base, role)
    os.makedirs(cfgdir, exist_ok=True)
    if role == "node":
        iface = (f"  [[TCP Server]]\n    type = TCPServerInterface\n    enabled = yes\n"
                 f"    listen_ip = 127.0.0.1\n    listen_port = {port}\n")
    else:
        iface = (f"  [[TCP Client]]\n    type = TCPClientInterface\n    enabled = yes\n"
                 f"    target_host = 127.0.0.1\n    target_port = {port}\n")
    with open(os.path.join(cfgdir, "config"), "w") as f:
        f.write("[reticulum]\n  enable_transport = %s\n  share_instance = No\n  panic_on_interface_error = No\n"
                "[logging]\n  loglevel = 3\n[interfaces]\n%s" % ("Yes" if role == "node" else "No", iface))

    def log_line(msg):
        if "Could not assemble LXMF message" in msg or "contained exception" in msg:
            emit(event="log", msg=msg)

    # Every RNS log line goes to log_line (stdout carries only the events).
    RNS.Reticulum(configdir=cfgdir, loglevel=RNS.LOG_DEBUG, logdest=log_line)
    identity = RNS.Identity()
    router = LXMRouter(identity=identity, storagepath=os.path.join(cfgdir, "lxmf"),
                       propagation_cost=LXMRouter.PROPAGATION_COST_MIN)

    if role == "node":
        router.enable_propagation()
        router.announce_propagation_node()
        emit(event="ready", prop=router.propagation_destination.hash.hex())
    elif role == "rx":
        target = LXMessage.unpack_from_bytes.__code__

        # Installed only while a shallow message is recorded: a profile hook
        # runs a Python frame on every call, which would move the limit.
        def profile(frame, event, arg):
            if event == "call" and frame.f_code is target:
                chain = []
                while frame is not None:
                    chain.append(frame.f_code.co_name)
                    frame = frame.f_back
                emit(event="frames", chain=list(reversed(chain)))

        dest = router.register_delivery_identity(identity, display_name="rx")
        router.register_delivery_callback(lambda m: emit(event="delivered", title=m.title_as_string()))
        router.announce(dest.hash)
        emit(event="ready", dest=dest.hash.hex(), recursion_limit=sys.getrecursionlimit())
    else:
        sys.setrecursionlimit(20000)  # the sender packs the deep fields; it is not under test
        dest = router.register_delivery_identity(identity, display_name="tx")
        emit(event="ready", dest=dest.hash.hex())

    empty = object()
    innermost = {"pad": b"x" * 2000, "empty": empty, "nil": None, "int": 0, "str": "a", "bin": b"a"}

    def nested(n, kind, leaf):
        value = empty
        for _ in range(n):
            if value is empty:
                if kind == "array":
                    value = [] if leaf is empty else [leaf]
                else:
                    value = {} if leaf is empty else {0: leaf}
            else:
                value = [value] if kind == "array" else {0: value}
        return value

    def wait_path(destination_hash):
        if not RNS.Transport.has_path(destination_hash):
            RNS.Transport.request_path(destination_hash)
            started = time.time()
            while not RNS.Transport.has_path(destination_hash):
                time.sleep(0.1)
                if time.time() - started > 30:
                    return False
        return True

    for line in sys.stdin:
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "announce":
            if role == "node":
                router.announce_propagation_node()
            else:
                router.announce(dest.hash)
            emit(event="announced")
        elif parts[0] == "record" and role == "rx":
            threading.setprofile_all_threads(profile if parts[1] == "on" else None)
            emit(event="recording", on=parts[1] == "on")
        elif parts[0] == "send":  # send <DIRECT|PROPAGATED> <rx> <node> <kind> <innermost> <n> <label>
            path, rx_hex, node_hex, kind, leaf, n, label = parts[1:8]
            rx_hash = bytes.fromhex(rx_hex)
            if not wait_path(rx_hash):
                emit(event="error", why="no path to rx")
                continue
            if path == "PROPAGATED":
                if not wait_path(bytes.fromhex(node_hex)):
                    emit(event="error", why="no path to the node")
                    continue
                router.set_outbound_propagation_node(bytes.fromhex(node_hex))
            out = RNS.Destination(RNS.Identity.recall(rx_hash), RNS.Destination.OUT, RNS.Destination.SINGLE,
                                  "lxmf", "delivery")
            message = LXMessage(out, dest, "", label, fields={0x77: nested(int(n), kind, innermost[leaf])},
                                desired_method=LXMessage.DIRECT if path == "DIRECT" else LXMessage.PROPAGATED)
            router.handle_outbound(message)
            started = time.time()
            done = (LXMessage.DELIVERED, LXMessage.SENT, LXMessage.FAILED, LXMessage.REJECTED)
            while message.state not in done and time.time() - started < 120:
                time.sleep(0.1)
            emit(event="sent", state=message.state, representation=message.representation)
        elif parts[0] == "sync" and role == "rx":
            node_hash = bytes.fromhex(parts[1])
            if not wait_path(node_hash):
                emit(event="error", why="no path to the node")
                continue
            router.set_outbound_propagation_node(node_hash)
            router.request_messages_from_propagation_node(identity)
            started = time.time()
            while (router.propagation_transfer_state not in (LXMRouter.PR_COMPLETE, LXMRouter.PR_FAILED)
                   and time.time() - started < 120):
                time.sleep(0.1)
            emit(event="synced", state=router.propagation_transfer_state)
        elif parts[0] == "quit":
            break
    os._exit(0)


# --- The orchestrator ---------------------------------------------------------

class Process:
    def __init__(self, role, base, port):
        self.role = role
        self.events = queue.Queue()
        self.p = subprocess.Popen([PYTHON, "-I", os.path.abspath(__file__), role, base, str(port)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=open(os.path.join(base, f"{role}.stderr"), "w"), text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                self.events.put(json.loads(line))
            except ValueError:
                pass

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def wait(self, kind, seen=None, timeout=180):
        started = time.time()
        while time.time() - started < timeout:
            try:
                event = self.events.get(timeout=1)
            except queue.Empty:
                continue
            if event["event"] == kind:
                return event
            if event["event"] == "error":
                raise RuntimeError(f"{self.role}: {event}")
            if seen is not None:
                seen.append(event)
        raise TimeoutError(f"{self.role}: no {kind}")

    def drain(self, seen):
        while True:
            try:
                seen.append(self.events.get_nowait())
            except queue.Empty:
                return


def orchestrate():
    base = tempfile.mkdtemp(prefix="lxmf-nesting-probe-")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    node = Process("node", base, port)
    prop = node.wait("ready")["prop"]
    time.sleep(1)
    rx = Process("rx", base, port)
    ready = rx.wait("ready")
    rx_hex = ready["dest"]
    tx = Process("tx", base, port)
    tx.wait("ready")
    time.sleep(3)
    rx.send("announce")
    rx.wait("announced")
    node.send("announce")
    node.wait("announced")
    time.sleep(3)
    print(f"rx recursion limit {ready['recursion_limit']}, Python {sys.version.split()[0]}", flush=True)

    counter = [0]

    def deliver(path, kind, leaf, n):
        counter[0] += 1
        label = f"{path}-{kind}-{leaf}-{n}-{counter[0]}"
        seen = []
        tx.send(f"send {path} {rx_hex} {prop} {kind} {leaf} {n} {label}")
        sent = tx.wait("sent")
        for _ in range(15):
            if path == "PROPAGATED":
                rx.send(f"sync {prop}")
                rx.wait("synced", seen)
            time.sleep(2)
            rx.drain(seen)
            delivered = [e for e in seen if e["event"] == "delivered"]
            refused = [e for e in seen if e["event"] == "log" and "Could not assemble" in e["msg"]]
            if delivered or refused:
                break
        assert all(e["title"] == label for e in delivered), (label, delivered)
        assert len(delivered) + len(refused) == 1, (label, seen)
        frames = [e["chain"] for e in seen if e["event"] == "frames"]
        why = [e["msg"] for e in seen if e["event"] == "log" and "contained exception" in e["msg"]]
        return ("read" if delivered else "refused"), sent["representation"], frames, why

    results = {"frames": {}, "cases": []}
    try:
        for path in ("PROPAGATED", "DIRECT"):
            rx.send("record on")
            rx.wait("recording")
            verdict, representation, frames, _ = deliver(path, "array", "pad", 1)
            rx.send("record off")
            rx.wait("recording")
            assert verdict == "read" and representation == 2 and len(frames) == 1, (path, verdict, frames)
            results["frames"][path] = frames[0]
            print(f"{path}: the unpack is frame {len(frames[0])}: {' > '.join(frames[0])}", flush=True)
            assert frames[0] == EXPECTED_FRAMES[path], f"{path}: the delivery path's frames changed"
        for path, kind, leaf, n, expected in EXPECTED:
            verdict, representation, _, why = deliver(path, kind, leaf, n)
            case = {"path": path, "kind": kind, "innermost": leaf, "nested": n, "verdict": verdict,
                    "as_resource": representation == 2, "why": why[:1]}
            results["cases"].append(case)
            print(json.dumps(case), flush=True)
            assert verdict == expected, f"{path} {kind} {leaf} {n}: {verdict}, not {expected}"
    finally:
        for process in (tx, rx, node):
            try:
                process.send("quit")
            except (BrokenPipeError, OSError):
                pass
        time.sleep(1)
        for process in (tx, rx, node):
            process.p.kill()
        shutil.rmtree(base, ignore_errors=True)
    print("as expected: a propagated message reads 492 nested arrays or maps in a field and refuses 493")


if __name__ == "__main__":
    if len(sys.argv) == 4:
        role_main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    else:
        orchestrate()
