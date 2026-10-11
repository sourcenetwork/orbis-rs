#!/usr/bin/env python3
"""Qualify native lifecycle scenarios against unchanged normal runtime images."""
import json
import math
import os
import re
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

RUNTIME = "9c76e741f73bdbac37fab71e79192c1289b052f2"
VERA = "892cf0582e9d9395574cd5e8900988cb4a6ebd21"
# Published native-diagnostic targets from run 37940390635, built at RUNTIME.
DIAGNOSTIC_DIGESTS = {
    "bls12-381": "sha256:64f306d0db89054182becf312c421d358f0097505126ae9c8a6ebe5956a9586f",
    "jubjub": "sha256:c74ae88480f8bd20e4a61fad7e5bdd384c2a4b7a010aecf6de82ef92fe9800fd",
}
FIXTURE_FILES = {
    ".github/workflows/rust.yml", "scripts/qualify-native-restart.py",
    ".github/actions/docker-builder/action.yml", ".github/workflows/upgrade-compatibility.yml",
    "scripts/test-native-qualification.py",
    "crates/test-support/src/container.rs", "crates/test-support/src/lib.rs",
    "crates/test-support/src/native_network.rs", "crates/test-support/src/network/native.rs",
    "bin/orbis-node/tests/native_startup.rs",
    "bin/orbis-node/tests/support/defra_signer.rs",
    "bin/orbis-node/tests/support/defra_documents.rs",
    "bin/orbis-node/tests/support/defra_peers.rs",
    "bin/orbis-node/tests/support/native_pet.rs",
    "bin/orbis-node/tests/support/native_pet/document.rs",
    "bin/orbis-node/tests/support/native_pet/member_replacement.rs",
    "bin/orbis-node/tests/support/native_pet/scheduled_refresh.rs",
    "bin/orbis-node/tests/support/native_trust_gateway/runner.rs",
    "bin/orbis-node/tests/support/native_trust_gateway/go_diagnostics.rs",
    "docker/docker-compose-native-integration-test.yml",
}


def verify_fixture_changes(changed):
    if set(changed) - FIXTURE_FILES:
        raise ValueError("runtime source differs from the selected images")


def capture(command):
    return subprocess.check_output(command, text=True).strip()


def lifecycle_results(report, selected):
    """Expose only selected case names, durations and fixed failure classifications."""
    if not report.is_file() or report.stat().st_size > 2 * 1024 * 1024:
        return {"complete": False, "cases": []}
    try:
        root = ET.parse(report).getroot()
    except ET.ParseError:
        return {"complete": False, "cases": []}
    cases = []
    for name in selected:
        matches = [case for case in root.iter("testcase") if case.get("name") == name]
        if len(matches) != 1:
            cases.append({"case": name, "status": "missing" if not matches else "duplicate"})
            continue
        case = matches[0]
        failures = list(case.findall("failure")) + list(case.findall("error"))
        status = "skipped" if case.find("skipped") is not None else "failed" if failures else "passed"
        record = {"case": name, "status": status}
        try:
            seconds = float(case.get("time", ""))
            if math.isfinite(seconds) and 0 <= seconds <= 86400:
                record["seconds"] = round(seconds, 3)
        except ValueError:
            pass
        if failures:
            content = "\n".join(element.get("message", "") + "\n" +
                                "".join(element.itertext()) for element in case)
            filenames = (
                "native_startup.rs", "support/native_workflow.rs", "support/native_pet.rs",
                "support/native_pet/dkg.rs", "support/native_pet/document.rs",
                "support/native_pet/member_replacement.rs", "support/native_pet/scheduled_refresh.rs",
                "support/native_pet/scheduled_store.rs", "support/native_pet/report_fault.rs",
                "support/native_pet/report_acceptance.rs",
            )
            locations = re.findall(r"(?:bin/orbis-node/tests/|tests/)(" +
                                   "|".join(re.escape(source) for source in filenames) +
                                   r"):(\d{1,6}):(\d{1,6})", content)
            record["locations"] = [{"source": source, "line": int(line), "column": int(column)}
                                   for source, line, column in sorted(set(locations))[:8]]
            record["deadline"] = any(marker in content for marker in ("Elapsed(())", "TIMED OUT", "execution timed out"))
            record["permission_denied"] = "PermissionDenied" in content
            record["panicked"] = "panicked at" in content
        cases.append(record)
    return {"complete": all(case["status"] == "passed" for case in cases), "cases": cases}


def qualify():
    curve = os.environ["NATIVE_RESTART_CURVE"]
    if curve not in ("bls12-381", "jubjub"):
        raise ValueError("unsupported curve")
    subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", RUNTIME], check=True)
    changed = set(capture(["git", "diff", "--name-only", RUNTIME, "HEAD"]).splitlines())
    verify_fixture_changes(changed)
    if Path("docker/NATIVE_VERA_REF").read_text().strip() != VERA:
        raise ValueError("Vera source does not match the runtime image")
    suite = os.environ.get("NATIVE_RESTART_SUITE", "restart")
    scenarios = {
        "restart": ["native_startup_registers_and_preserves_identity_on_restart"],
        "fault": ["native_pet_fault_reports"],
        "threshold": ["native_distributed_threshold_workflows", "native_pet_threshold_workflows",
                      "native_pet_member_replacement", "native_pet_scheduled_refresh_after_restart"],
    }
    if suite not in scenarios:
        raise ValueError("unsupported lifecycle suite")
    selected = list(scenarios[suite])
    if suite == "threshold" and curve == "bls12-381":
        selected.append("native_defra_signing")
    requested = os.environ.get("NATIVE_LIFECYCLE_CASE", "all")
    if requested != "all":
        if suite != "threshold" or requested not in selected:
            raise ValueError("scenario does not belong to the selected suite and curve")
        selected = [requested]
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("ORBIS_LOCAL_STORAGE_KDF_"):
            del env[name]
    env.update(CARGO_BUILD_JOBS="2", RUSTUP_TOOLCHAIN="1.98.0")
    repository = "ghcr.io/sourcenetwork/orbis-rs"
    images = {
        "ORBIS_NATIVE_IMAGE": f"{repository}/node-integration:{RUNTIME}-native-{curve}",
        "ORBIS_NATIVE_VERA_IMAGE": f"{repository}/vera-native:{RUNTIME}",
    }
    if suite == "fault":
        images["ORBIS_NATIVE_DIAGNOSTIC_IMAGE"] = (
            f"{repository}/node-integration@{DIAGNOSTIC_DIGESTS[curve]}"
        )
    for variable, image in images.items():
        subprocess.run(["docker", "pull", image], check=True)
        info = json.loads(capture(["docker", "image", "inspect", image]))[0]
        if variable == "ORBIS_NATIVE_DIAGNOSTIC_IMAGE":
            if image not in info.get("RepoDigests", []):
                raise ValueError("diagnostic image differs from the qualified build digest")
            env[variable] = info["Id"]
            continue
        labels = info["Config"].get("Labels") or {}
        expected = {"org.opencontainers.image.revision": VERA}
        if variable == "ORBIS_NATIVE_IMAGE":
            expected = {
                "org.opencontainers.image.revision": RUNTIME,
                "io.sourcenetwork.orbis.backend": "native",
                "io.sourcenetwork.orbis.curve": curve,
                "io.sourcenetwork.orbis.integration-features": "false",
            }
        if any(labels.get(key) != value for key, value in expected.items()):
            raise ValueError("runtime image labels do not match the selected sources")
        env[variable] = info["Id"]
    output = Path(os.environ["RUNNER_TEMP"]) / ("native-" + suite + "-" + curve)
    output.mkdir(mode=0o700, exist_ok=False)
    unit_flags = ["--lib", "container::tests::bind_mount_user_rejects_files_and_symlinks", "--", "--exact"]
    if suite == "threshold":
        unit_flags = ["--features", "native", "--lib", "native_network::tests::"]
    commands = [
        ["cargo", "test", "--release", "--locked", "-p", "test-support", "--no-default-features", *unit_flags],
        ["cargo", "nextest", "run", "--release", "--locked", "--profile", "ci",
         "--retries", "0", "--no-tests", "fail", "--test-threads", "1", "-p", "orbis-node", "--no-default-features",
         "--features", "integration-test-native,redb,iroh," + curve,
         "--test", "native_startup", "-E", " | ".join("test(=" + name + ")" for name in selected)],
    ]
    report = Path(env.get("CARGO_TARGET_DIR", "target")) / "nextest/ci/junit.xml"
    codes = []
    for index, command in enumerate(commands):
        print(json.dumps({"curve": curve, "stage": index, "state": "running"}), flush=True)
        started = time.monotonic()
        log = output / (str(index) + ".log")
        if index == 1:
            report.unlink(missing_ok=True)
        with log.open("x") as stream:
            os.chmod(log, 0o600)
            result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
        codes.append(result.returncode)
        print(json.dumps({"curve": curve, "stage": index, "exit_code": result.returncode,
                          "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)
        passed = result.returncode == 0
        if index == 1:
            summary = lifecycle_results(report, selected)
            print(json.dumps(summary), flush=True)
            (output / "results.json").write_text(json.dumps(summary) + "\n")
            passed = passed and summary["complete"]
        if not passed:
            with log.open("rb") as stream:
                stream.seek(max(0, log.stat().st_size - 65536))
                tail = stream.read().decode("utf-8", errors="replace")
            locations = re.findall(
                r"(?:bin/orbis-node/tests/)?(native_startup\.rs|support/native_workflow\.rs|support/native_pet\.rs):(\d+):(\d+)",
                tail,
            )
            for source, line, column in sorted(set(locations))[:8]:
                print(json.dumps({"source": source, "line": int(line), "column": int(column)}), flush=True)
            errors = sorted(set(re.findall(r"error\[(E\d{4})\]", tail)))
            fields = {"restart", "connections", "responses", "last_status", "endpoint_changed", "log_read",
                      "password_loaded", "network_initializing", "bootstrap_started",
                      "permission_denied", "runtime_panicked"}
            for payload in re.findall(r"native_readiness=(\{[^\n]*\})", tail)[:8]:
                diagnostics = json.loads(payload)
                if set(diagnostics) == fields and all(
                    value is None or isinstance(value, (bool, int))
                    for value in diagnostics.values()
                ):
                    print(json.dumps({"readiness": diagnostics}), flush=True)
            print(json.dumps({"compiler_errors": errors[:8], "invalid_argument": "unexpected argument" in tail,
                              "permission_denied": "PermissionDenied" in tail,
                              "elapsed_deadline": "Elapsed(())" in tail}), flush=True)
            raise RuntimeError("focused restart qualification failed; private log retained on runner")
    print(json.dumps({"curve": curve, "runtime": RUNTIME, "vera": VERA, "exit_codes": codes}), flush=True)


if __name__ == "__main__":
    qualify()
