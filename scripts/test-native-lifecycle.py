#!/usr/bin/env python3
"""Qualify native PET and ordinary workflows with staged normal release binaries.

All command output, cluster state and detailed provenance stay in a private
per-run directory. Console output contains only fixed phase names and numbers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

# Helper imports must not create untracked bytecode in the source snapshot.
sys.dont_write_bytecode = True
from native_lifecycle_summary import CURVES, SCENARIOS, PET_PHASES, failure_summary

CARGO = ["cargo", "+1.98.0"]
MANIFESTS = ("bin/cli-tool/Cargo.toml", "bin/orbis-node/Cargo.toml",
             "crates/authz/Cargo.toml", "crates/bulletin/Cargo.toml")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            result.update(block)
    return result.hexdigest()


def snapshot(source):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=source).decode()
    changed = set(filter(None, git("diff", "--name-only", "--no-renames", "HEAD", "-z").split("\0")))
    changed.update(filter(None, git("ls-files", "--others", "--exclude-standard", "-z").split("\0")))
    files = {}
    for name in sorted(changed):
        path = source / name
        files[name] = ({"symlink": os.readlink(path)} if path.is_symlink()
                       else {"sha256": sha(path)} if path.is_file() else {"deleted": True})
    return {"head": git("rev-parse", "HEAD").strip(), "changed_files": files,
            "lock_sha256": sha(source / "Cargo.lock"), "status": git("status", "--short")}


def vera_pin(root):
    pins = []
    for name in MANIFESTS:
        declarations = [line for line in (root / name).read_text().splitlines()
                        if 'git = "https://github.com/sourcenetwork/vera.rs"' in line]
        require(declarations, "Missing native SDK declarations")
        for line in declarations:
            match = re.search(r'rev = "([0-9a-f]{40})"', line)
            require(match is not None, "Vera SDK revision must be immutable")
            pins.append({"manifest": name, "package": line.split("=")[0].strip(), "revision": match[1]})
    require(len({pin["revision"] for pin in pins}) == 1, "Native SDK revisions disagree")
    return pins[0]["revision"], pins


def environment(target):
    env = os.environ.copy()
    explicit = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                "CARGO_INCREMENTAL", "CARGO_BUILD_INCREMENTAL", "CARGO_BUILD_TARGET",
                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "VERA_E2E_DEADLINE_SCALE",
                "VERAD_BINARY", "ORBIS_NODE_BINARY", "VERA_E2E_DIR", "ORBIS_NATIVE_E2E_DIR",
                "ORBIS_PASSWORD", "ORBIS_PASSWORD_FILE"}
    for name in list(env):
        if (name in explicit or name.startswith(("CARGO_PROFILE_", "ORBIS_LOCAL_STORAGE_KDF_"))
                or (name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS"))):
            del env[name]
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", CARGO_TERM_COLOR="never",
               RUST_LOG="info", RUST_BACKTRACE="1", VERA_E2E_KEEP="1")
    return env


def qualify(root, curve, private_root):
    require(curve in CURVES, "Unknown native curve")
    root, private_root = root.resolve(), private_root.resolve()
    require(not private_root.is_relative_to(root), "Private run directory must be outside the checkout")
    revision, pins = vera_pin(root)
    frozen = snapshot(root)
    os.umask(0o077)
    work = Path(tempfile.mkdtemp(prefix="orbis-native-" + curve + "-", dir=private_root))
    target = work / "target"  # Fresh workspace artifacts; dependency download caches may be reused.
    vera = work / "vera"
    env = environment(target)
    features = "native,redb,iroh," + curve
    sources = {"orbis": {"path": str(root), **frozen}}
    manifest = {"status": "running", "curve": curve, "profile": "normal release",
                "features": features, "default_features": False, "sources": sources, "pins": pins,
                "toolchain": "1.98.0", "kdf": {"m_cost_kib": 262144, "t_cost": 3},
                "deadline_overrides": False, "target": str(target), "steps": [], "binaries": {}}

    def save():
        temporary = work / "manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2) + "\n")
        temporary.replace(work / "manifest.json")

    def unchanged():
        for record in sources.values():
            require(snapshot(Path(record["path"])) == {k: v for k, v in record.items() if k != "path"},
                    "Source changed during qualification")
        for record in manifest["binaries"].values():
            require(sha(Path(record["path"])) == record["sha256"], "Staged binary changed")

    def run(name, command, cwd=root):
        unchanged()
        log = work / (name + ".log")
        log.parent.mkdir(parents=True, exist_ok=True)
        step = {"name": name, "command": command, "cwd": str(cwd), "log": str(log),
                "environment": {key: env[key] for key in ("CARGO_TARGET_DIR", "VERAD_BINARY",
                    "ORBIS_NODE_BINARY", "VERA_E2E_DIR", "ORBIS_NATIVE_E2E_DIR") if key in env}}
        manifest["steps"].append(step)
        save()
        print("Starting " + name, flush=True)
        started = time.monotonic()
        with log.open("w") as output:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
        step.update(exit_code=result.returncode, elapsed_seconds=round(time.monotonic() - started, 2),
                    log_sha256=sha(log))
        save()
        print("{}: exit {}, {:.2f}s".format(name, result.returncode, step["elapsed_seconds"]), flush=True)
        unchanged()
        require(result.returncode == 0, "Qualification command failed")
        return log, step

    def stage(name, source, destination, source_name, selected_features):
        destination.parent.mkdir(parents=True, exist_ok=True)
        require(source.is_file() and os.access(source, os.X_OK), "Built executable is missing")
        shutil.copy2(source, destination)
        require(sha(source) == sha(destination), "Staged executable differs")
        manifest["binaries"][name] = {"path": str(destination), "sha256": sha(destination),
            "source_head": sources[source_name]["head"], "profile": "release", "features": selected_features}
        save()

    save()
    try:
        run("rust-toolchain", ["rustc", "+1.98.0", "--version", "--verbose"])
        run("vera-init", ["git", "init", "--quiet", str(vera)])
        run("vera-fetch", ["git", "-C", str(vera), "fetch", "--quiet", "--depth", "1",
                           "https://github.com/sourcenetwork/vera.rs.git", revision])
        run("vera-checkout", ["git", "-C", str(vera), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
        sources["vera"] = {"path": str(vera), **snapshot(vera)}
        require(sources["vera"]["head"] == revision and not sources["vera"]["changed_files"], "Vera checkout mismatch")
        run("build-verad", CARGO + ["build", "--release", "--locked", "-j2", "-p", "verad", "--bin", "verad", "--message-format=json"], vera)
        stage("verad", target / "release/verad", work / "bin/verad", "vera", "repository defaults")
        env["VERAD_BINARY"] = str(work / "bin/verad")
        native = ["--release", "--locked", "-j2", "-p", "orbis-node", "--no-default-features", "--features", features]
        run("build-orbis", CARGO + ["build"] + native + ["--bin", "orbis-node", "--message-format=json"])
        stage("orbis", target / "release/orbis-node", work / "bin/orbis-node", "orbis", features)
        env["ORBIS_NODE_BINARY"] = str(work / "bin/orbis-node")
        graph, step = run("native-dependencies", CARGO + ["tree", "--locked", "-p", "orbis-node",
            "--no-default-features", "--features", features, "--edges", "normal,build", "--prefix", "none", "--color", "never"])
        forbidden = re.search(r"^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v", graph.read_text(), re.MULTILINE)
        step["native_dependency_boundary_passed"] = not bool(forbidden)
        save()
        require(not forbidden, "Native dependency boundary failed")
        compiled, _ = run("compile-native-tests", CARGO + ["test"] + native + ["--test", "native_startup", "--no-run", "--message-format=json"])
        executables = set()
        for line in compiled.read_text().splitlines():
            try:
                artifact = json.loads(line)
            except ValueError:
                continue
            if (artifact.get("reason") == "compiler-artifact" and artifact.get("target", {}).get("name") == "native_startup"
                    and "test" in artifact.get("target", {}).get("kind", []) and artifact.get("executable")):
                executables.add(artifact["executable"])
        require(len(executables) == 1, "Expected one native test executable")
        executable = Path(executables.pop()).resolve()
        require(executable.parent == target / "release/deps", "Native test executable is outside this run")
        stage("native-tests", executable, work / "bin/native_startup", "orbis", features + " (test dependencies)")
        for scenario in SCENARIOS:
            directory = work / "scenarios" / scenario / "attempt-1"
            for child in ("vera-clusters", "orbis-clusters"):
                (directory / child).mkdir(parents=True)
            env["VERA_E2E_DIR"] = str(directory / "vera-clusters")
            env["ORBIS_NATIVE_E2E_DIR"] = str(directory / "orbis-clusters")
            log, step = run("scenarios/" + scenario + "/attempt-1/command", [str(work / "bin/native_startup"), scenario,
                "--ignored", "--exact", "--test-threads=1", "--nocapture"])
            result = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log.read_text(), re.MULTILINE)
            require(result == [("1", "0", "0")], "Expected exactly one passed native scenario")
            step["tests_passed"] = 1
            if scenario == SCENARIOS[0]:
                step["pet_phase_count"] = sum(phase in log.read_text() for phase in PET_PHASES)
                require(step["pet_phase_count"] == len(PET_PHASES), "PET lifecycle evidence is incomplete")
            save()
        unchanged()
        manifest["status"] = "passed"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = type(error).__name__ + ": " + str(error)
        last = manifest["steps"][-1] if manifest["steps"] else {}
        try:
            log = Path(last["log"]) if "log" in last else None
            if log is not None and log.is_file():
                with log.open(errors="replace") as lines:
                    summary = failure_summary(curve, last.get("name"), last.get("exit_code"),
                                              last.get("elapsed_seconds"), lines, root)
            else:
                summary = failure_summary(curve, last.get("name"), last.get("exit_code"),
                                          last.get("elapsed_seconds"), (), root)
            manifest["failure_summary"] = summary
            # This object contains only fixed enums, bounded numbers and known E-codes.
            # The private manifest and its error/environment fields are never emitted.
            print("Native lifecycle failure summary: " + json.dumps(summary, sort_keys=True), flush=True)
        except Exception:
            # Diagnostic collection must not replace the qualification failure.
            pass
        raise
    finally:
        manifest["retained_log_sha256"] = {str(path.relative_to(work)): sha(path)
            for path in (work / "scenarios").rglob("*.log") if path.is_file()}
        save()
    return work


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curve", required=True, choices=CURVES)
    parser.add_argument("--private-root", type=Path, default=Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())))
    args = parser.parse_args()
    try:
        qualify(Path(__file__).resolve().parents[1], args.curve, args.private_root)
    except Exception:
        # Runtime logs may include secrets or application data; never stream or upload them.
        parser.exit(1, "Native lifecycle qualification failed; details remain in the private run directory.\n")
    print("Native lifecycle scenarios passed: 2", flush=True)


if __name__ == "__main__":
    main()
