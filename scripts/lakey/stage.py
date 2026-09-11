#!/usr/bin/env python3
"""Stage one node from approved public MPC artifacts and its own TLS private key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import node


def public_output(args):
    return subprocess.check_output(["openssl", *args], stderr=subprocess.DEVNULL, timeout=10)


def stage(args):
    if args.node not in range(5) or not 0 < args.epoch < 2**64:
        raise ValueError("invalid node or epoch")
    if not args.chain or not args.ring or max(len(args.chain.encode()), len(args.ring.encode())) > 1024:
        raise ValueError("invalid namespace")
    if args.root.exists() or args.config.exists():
        raise ValueError("node root and configuration must be new")
    node.private(args.tls_key)
    peers = args.peers.read_text().splitlines()
    if len(peers) != 5 or any(not entry or len(entry) > 1024 for entry in peers):
        raise ValueError("exactly five ordered MPC peers are required")
    own_certificate = args.certificates / f"P{args.node}.pem"
    if public_output(["pkey", "-in", str(args.tls_key), "-pubout"]) != public_output(["x509", "-in", str(own_certificate), "-pubkey", "-noout"]):
        raise ValueError("TLS private key does not match this node's certificate")
    # Pre-read public artifacts before creating operational state.
    public = {"peers": ("\n".join(peers) + "\n").encode()}
    names = ["malicious-shamir-party.x"]
    names += [path.name for path in args.artifacts.glob("*.so")]
    for program in ["lakey_init_node", "lakey_derive_node"]:
        names.append(f"Programs/Schedules/{program}.sch")
        names.append(f"Programs/Bytecode/{program}-0.bc")
    for name in names:
        public[name] = (args.artifacts / name).read_bytes()
    for peer in range(5):
        certificate = args.certificates / f"P{peer}.pem"
        pem = public_output(["x509", "-in", str(certificate), "-outform", "PEM"])
        subject = public_output(["x509", "-in", str(certificate), "-subject_hash", "-noout"]).decode().strip()
        if len(subject) != 8 or any(c not in "0123456789abcdef" for c in subject):
            raise ValueError("invalid TLS certificate hash")
        public[f"Player-Data/P{peer}.pem"] = pem
        collision = 0
        while f"Player-Data/{subject}.{collision}" in public:
            collision += 1
        public[f"Player-Data/{subject}.{collision}"] = pem
    args.root.mkdir(mode=0o700, parents=False)
    for folder in ["Persistence", "Player-Data", "Programs/Bytecode", "Programs/Schedules", "Programs/Public-Input"]:
        (args.root / folder).mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, data in public.items():
        path = args.root / name
        path.write_bytes(data)
        path.chmod(0o700 if name == "malicious-shamir-party.x" else 0o600)
    private_key = args.root / "Player-Data" / f"P{args.node}.key"
    shutil.copyfile(args.tls_key, private_key)
    private_key.chmod(0o600)
    config = {
        "root": str(args.root.resolve()), "node": args.node, "nodes": 5, "threshold": 3,
        "chain": args.chain, "ring": args.ring, "epoch": args.epoch, "timeout_seconds": 90,
        "artifacts": {name: hashlib.sha256(data).hexdigest() for name, data in public.items()},
    }
    node.validate_environment(config, "lakey_init_node", False)
    node.persist(args.config, config)
    return {"config": str(args.config.resolve()), "initialized": False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    for name in ["root", "config", "artifacts", "certificates", "tls-key", "peers"]:
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ["chain", "ring"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--node", type=int, required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(stage(args)))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("LaKey staging failed; inspect local inputs and partial staging directory", file=sys.stderr)
        sys.exit(1)
