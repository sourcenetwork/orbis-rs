#!/usr/bin/env python3
"""Initialize one node's fixed LaKey master through the five-party MPC ceremony."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import node

PROGRAM = "lakey_init_node"


def initialize(config_path, session):
    node.private(config_path)
    if len(session) != 64 or any(c not in "0123456789abcdef" for c in session) or session == "00" * 32:
        raise ValueError("a fresh 32-byte ceremony session is required")
    config = json.loads(config_path.read_text())
    for name in ["chain", "ring"]:
        if not isinstance(config.get(name), str) or not 1 <= len(config[name].encode()) <= 1024:
            raise ValueError("invalid master namespace")
    if type(config.get("epoch")) is not int or not 0 < config["epoch"] < 2**64:
        raise ValueError("invalid master epoch")
    root, state, executable, peers, index, count, threshold, timeout = node.validate_environment(config, PROGRAM, False)
    if "master_digest" in config:
        raise ValueError("master configuration is already initialized")
    marker = root / "lakey.initializing"
    binding = hashlib.sha256(b"orbis.lakey.initialize.v1\0" + json.dumps(
        {"chain": config["chain"], "ring": config["ring"], "epoch": config["epoch"], "session": session},
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    with open(root / "lakey.lock", "a+b") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if state.exists() or marker.exists() or (root / "lakey.in-progress").exists() or (root / "lakey.recovery-required").exists():
            raise ValueError("existing or interrupted master ceremony requires operator recovery")
        node.persist(marker, {"binding": binding})
        local_input = root / "Player-Data" / f"Input-P{index}-0"
        try:
            with open(local_input, "w") as stream:
                os.chmod(local_input, 0o600)
                stream.write(str(int(binding, 16) % int(node.PRIME)) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            subprocess.run([str(executable), "-N", str(count), "-T", str(threshold - 1),
                            "-p", str(index), "-ip", str(peers), "-P", node.PRIME,
                            "-S", "128", PROGRAM], cwd=root, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout, check=True, pass_fds=(lock.fileno(),))
            node.private(state)
            with open(state, "rb") as stream:
                raw = stream.read(4096 + node.MASTER_BYTES + 1)
                if len(raw) < 8:
                    raise ValueError("incomplete initialized state")
                end = 8 + struct.unpack("<Q", raw[:8])[0] + node.MASTER_BYTES
                if not 8 + node.MASTER_BYTES <= end <= 4096 + node.MASTER_BYTES or len(raw) != end:
                    raise ValueError("invalid initialized master state")
                os.fsync(stream.fileno())
            node.sync_directory(state.parent)
            config["master_digest"] = hashlib.sha256(raw).hexdigest()
            node.persist(config_path, config)
            marker.unlink()
            node.sync_directory(root)
            return {"node": index, "epoch": config["epoch"], "master_bytes": len(raw), "initialized": True}
        finally:
            local_input.unlink(missing_ok=True)
            node.sync_directory(root / "Player-Data")


def main():
    node.guard_parent()
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--session", required=True, help="shared public ceremony nonce, freshly chosen for all five nodes")
    args = parser.parse_args()
    print(json.dumps(initialize(args.config, args.session)))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("LaKey initialization failed; inspect local ceremony state before retrying", file=sys.stderr)
        sys.exit(1)
