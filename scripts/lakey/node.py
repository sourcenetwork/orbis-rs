#!/usr/bin/env python3
"""Local MPC process boundary. Stdin/stdout are private pipes to the Orbis node."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import signal
import threading
import time

PRIME = "2111115437357092606062206234695386632838870926408408195193685246394721360383"
PROGRAM = "lakey_derive_node"
MASTER_BYTES = 512 * 32


def private(path, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or (info.st_mode & 0o077):
        raise ValueError("MPC state must be private and cannot be a symlink")
    if directory != stat.S_ISDIR(info.st_mode):
        raise ValueError("incorrect MPC state type")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def persist(path, value):
    temporary = path.with_suffix(".tmp")
    with open(temporary, "w") as f:
        os.chmod(temporary, 0o600)
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def validate_environment(config, program=PROGRAM, require_master=True):
    node = config["node"]
    count, threshold = config["nodes"], config["threshold"]
    if type(node) is not int or not 0 <= node < count or not 2 <= threshold <= count <= 32:
        raise ValueError("invalid MPC committee")
    if (count, threshold) != (5, 3):
        raise ValueError("compiled LaKey program requires five nodes and threshold three")
    if count < 2 * (threshold - 1) + 1:
        raise ValueError("MPC committee does not support malicious Shamir threshold")
    root = Path(config["root"]).resolve(strict=True)
    private(root, directory=True)
    persistence = root / "Persistence"
    private(persistence, directory=True)
    state = persistence / f"Transactions-P{node}.data"
    if require_master:
        private(state)
    elif state.exists():
        raise ValueError("MPC master already exists")
    if any(p != state for p in persistence.glob("Transactions-P*.data")):
        raise ValueError("a node cannot have another node's master state")
    private(root / "Player-Data" / f"P{node}.key")
    if any(p.name != f"P{node}.key" for p in (root / "Player-Data").glob("P*.key")):
        raise ValueError("a node cannot have another node's TLS private key")
    artifacts = config["artifacts"]
    for peer in range(count):
        name = f"Player-Data/P{peer}.pem"
        if name not in artifacts:
            raise ValueError("MPC peer certificate must be pinned")
    for certificate in (root / "Player-Data").iterdir():
        if certificate.suffix == ".pem" or certificate.suffix[1:].isdigit():
            if str(certificate.relative_to(root)) not in artifacts:
                raise ValueError("MPC TLS trust entry must be pinned")
    if not artifacts or not any(name == "Programs/Schedules/" + program + ".sch" for name in artifacts):
        raise ValueError("missing pinned MPC schedule")
    for name, digest in artifacts.items():
        path = root / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink():
            raise ValueError("invalid MPC artifact path")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("MPC artifact digest mismatch")
    schedule = (root / "Programs/Schedules" / (program + ".sch")).read_text().splitlines()
    if len(schedule) < 5 or schedule[0] != "1" or schedule[1] != "1":
        raise ValueError("unsupported MPC schedule")
    tape = schedule[2].split(":")[0]
    if tape != program + "-0" or "Programs/Bytecode/" + tape + ".bc" not in artifacts:
        raise ValueError("scheduled MPC bytecode must be pinned")
    if schedule[3:5] != ["1 0", "0"]:
        raise ValueError("unsupported MPC schedule execution")
    for bytecode in (root / "Programs/Bytecode").glob("*.bc"):
        if str(bytecode.relative_to(root)) not in artifacts:
            raise ValueError("MPC bytecode must be pinned")
    executable = root / "malicious-shamir-party.x"
    if "malicious-shamir-party.x" not in artifacts:
        raise ValueError("MPC binary must be pinned")
    peers = root / "peers"
    if "peers" not in artifacts:
        raise ValueError("MPC peers must be pinned")
    timeout = config["timeout_seconds"]
    if not 1 <= timeout <= 3600:
        raise ValueError("invalid MPC timeout")
    return root, state, executable, peers, node, count, threshold, timeout


def derive(config, matrix, binding):
    if len(binding) != 64 or any(c not in "0123456789abcdef" for c in binding):
        raise ValueError("invalid MPC session binding")
    if len(matrix) != 16 * 512 or any(type(x) is not int or not 0 <= x < 2**32 for x in matrix):
        raise ValueError("invalid REG32 matrix")
    root, state, executable, peers, node, count, threshold, timeout = validate_environment(config)
    with open(root / "lakey.lock", "a+b") as lock:
        os.chmod(root / "lakey.lock", 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (root / "lakey.initializing").exists():
            raise ValueError("MPC initialization requires operator recovery")
        if (root / "lakey.recovery-required").exists():
            raise ValueError("MPC master recovery required")
        with open(state, "r+b") as f:
            pending = root / "lakey.in-progress"
            if pending.exists():
                previous = json.loads(pending.read_text())
                size = previous["master_size"]
                if not 8 + MASTER_BYTES <= size <= 4096 + MASTER_BYTES:
                    raise ValueError("invalid interrupted MPC state")
                if hashlib.sha256(f.read(size)).hexdigest() != previous["master_digest"]:
                    persist(root / "lakey.recovery-required", {"reason":"interrupted master mutation"})
                    raise ValueError("MPC master recovery required")
                f.seek(0)
            prefix = f.read(8)
            if len(prefix) != 8:
                raise ValueError("invalid MPC state header")
            header = 8 + struct.unpack("<Q", prefix)[0]
            if header > 4096:
                raise ValueError("invalid MPC state header")
            end = header + MASTER_BYTES
            f.seek(0)
            master = f.read(end)
            if len(master) != end:
                raise ValueError("incomplete MPC master state")
            expected = config.get("master_digest", "")
            if len(expected) != 64 or hashlib.sha256(master).hexdigest() != expected:
                raise ValueError("MPC state does not match configured master digest")
            persist(pending, {"master_size":end,"master_digest":hashlib.sha256(master).hexdigest()})
            # A prior interrupted derivation may have left its single transient slot.
            f.truncate(end)
            f.flush()
            os.fsync(f.fileno())
            public_input = root / "Programs/Public-Input" / PROGRAM
            public_input.parent.mkdir(parents=True, exist_ok=True)
            with open(public_input, "w") as public:
                os.chmod(public_input, 0o600)
                public.write("\n".join(map(str, matrix)) + "\n")
                public.flush()
                os.fsync(public.fileno())
            local_input = root / "Player-Data" / f"Input-P{node}-0"
            with open(local_input, "w") as request_input:
                os.chmod(local_input, 0o600)
                request_input.write(str(int(binding, 16) % int(PRIME)) + "\n")
            try:
                subprocess.run([str(executable), "-N", str(count), "-T", str(threshold - 1),
                                "-p", str(node), "-ip", str(peers), "-P", PRIME, "-S", "128", PROGRAM],
                               cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=timeout, check=True,
                               pass_fds=(lock.fileno(),))
                f.seek(0)
                if f.read(end) != master:
                    raise ValueError("MPC derivation changed master state")
                share = f.read(32)
                if len(share) != 32 or f.read(1):
                    raise ValueError("incorrect MPC derived-share output")
                return share.hex()
            finally:
                f.seek(0)
                if f.read(end) != master:
                    persist(root / "lakey.recovery-required", {"reason":"master mutation"})
                    raise ValueError("MPC master recovery required")
                f.truncate(end)
                f.flush()
                os.fsync(f.fileno())
                public_input.unlink(missing_ok=True)
                local_input.unlink(missing_ok=True)
                pending.unlink(missing_ok=True)
                sync_directory(root)


def guard_parent():
    parent = os.getppid()
    os.setpgrp()
    group = os.getpid()
    def terminate(*_):
        os.killpg(group, signal.SIGKILL)
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    def watch():
        while os.getppid() == parent:
            time.sleep(0.1)
        terminate()
    threading.Thread(target=watch, daemon=True).start()



def main():
    guard_parent()
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    private(args.config)
    config = json.loads(args.config.read_text())
    raw = sys.stdin.buffer.readline(128 * 1024 + 1)
    if len(raw) > 128 * 1024 or not raw.endswith(b"\n"):
        raise ValueError("MPC input too large")
    request = json.loads(raw)
    print(json.dumps({"montgomery_share": derive(config, request["matrix"], request["binding"])}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("LaKey node derivation failed; no result released", file=sys.stderr)
        sys.exit(1)
