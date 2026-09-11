#!/usr/bin/env python3
"""Create isolated node directories from synthetic PoC fixtures for integration tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("upstream", type=Path)
args = parser.parse_args()
os.umask(0o077)
source = args.upstream.resolve()
root = Path(tempfile.mkdtemp(prefix="orbis-lakey-nodes-"))
program = "lakey_derive_node"
for i in range(5):
    node = root / str(i)
    node.mkdir(mode=0o700)
    for folder in ["Persistence", "Player-Data", "Programs/Bytecode", "Programs/Schedules", "Programs/Public-Input"]:
        (node / folder).mkdir(parents=True, exist_ok=True, mode=0o700)
    state = node / "Persistence" / f"Transactions-P{i}.data"
    shutil.copyfile(source / "Persistence" / state.name, state)
    state.chmod(0o600)
    master = state.read_bytes()
    end = 8 + struct.unpack("<Q", master[:8])[0] + 512 * 32
    if not 8 + 512 * 32 <= end <= 4096 + 512 * 32 or len(master) < end:
        raise ValueError("invalid synthetic master state")
    state.write_bytes(master[:end])
    for certificate in (source / "Player-Data").glob("*.pem"):
        shutil.copyfile(certificate, node / "Player-Data" / certificate.name)
    for hashed in (source / "Player-Data").glob("*.0"):
        shutil.copyfile(hashed, node / "Player-Data" / hashed.name)
    private = node / "Player-Data" / f"P{i}.key"
    shutil.copyfile(source / "Player-Data" / private.name, private)
    private.chmod(0o600)
    paths = [source / "malicious-shamir-party.x", *source.glob("*.so"),
             source / "Programs/Schedules" / (program + ".sch"),
             *(source / "Programs/Bytecode").glob(program + "*.bc")]
    artifacts = {}
    for path in paths:
        name = str(path.relative_to(source))
        destination = node / name
        shutil.copyfile(path, destination)
        if path.name == "malicious-shamir-party.x":
            destination.chmod(0o700)
        artifacts[name] = hashlib.sha256(destination.read_bytes()).hexdigest()
    for certificate in (node / "Player-Data").iterdir():
        if certificate.suffix == ".pem" or certificate.suffix[1:].isdigit():
            artifacts[str(certificate.relative_to(node))] = hashlib.sha256(certificate.read_bytes()).hexdigest()
    peers = node / "peers"
    peers.write_text("".join(f"127.0.0.1:{19080+j}\n" for j in range(5)))
    artifacts["peers"] = hashlib.sha256(peers.read_bytes()).hexdigest()
    config = {"root":str(node), "node":i, "nodes":5, "threshold":3,
              "chain":"fixture-chain", "ring":"fixture-ring", "epoch":1,
              "timeout_seconds":90, "artifacts":artifacts,
              "master_digest":hashlib.sha256(state.read_bytes()).hexdigest()}
    (root / f"{i}.json").write_text(json.dumps(config))
print(root)
