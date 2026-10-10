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

RUNTIME = "67ed409901ed694ac9855ef5217e2b57ee75be40"
VERA = "c8a718743b19e6e8b9320baa5643380ada2a6932"
# Published Linux amd64 targets from run 38033630305, built at RUNTIME.
VERA_DIGEST = "sha256:a463eb2b5124de81e2fa017ed919cf2aa6d0907caa53dc5347bc21a1dc9a1998"
RUNTIME_DIGESTS = {
    "bls12-381": "sha256:7d44270a6abbaf7cd9a87549d42ff92153c8d43a8f1ff9069a331eaeef620743",
    "jubjub": "sha256:b29be06d927727c3e11aa06402dfe968f72bd5fdee998584ab6d382d33c626a0",
}
DIAGNOSTIC_DIGESTS = {
    "bls12-381": "sha256:4179615af9ec5779fd3394af810477659eeb3c4ad5d30b3fe60bd072df489c79",
    "jubjub": "sha256:303b5cd70cedcc18b44aa2c55005182ff16c86bbe45d4440203c6c56372f8311",
}
FIXTURE_FILES = {
    ".config/nextest.toml",
    ".github/workflows/rust.yml", "scripts/qualify-native-restart.py",
    ".github/actions/docker-builder/action.yml", ".github/workflows/upgrade-compatibility.yml",
    "scripts/test-native-qualification.py",
    "docs/native-threshold-soak.md",
    "docs/native-trust-ring-fixture.md", "docs/native-trust-hosted.md",
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
    "bin/orbis-node/tests/support/native_pet/soak.rs",
    "bin/orbis-node/tests/support/native_pet/polynomial_state.rs",
    "bin/orbis-node/tests/support/native_trust_gateway/runner.rs",
    "bin/orbis-node/tests/support/native_trust_gateway/go_diagnostics.rs",
    "scripts/native_trust_hosted.py", "scripts/test-native-trust-hosted.py",
    "docker/docker-compose-native-integration-test.yml",
}


def verify_fixture_changes(changed):
    if set(changed) - FIXTURE_FILES:
        raise ValueError("runtime source differs from the selected images")


def verified_image_id(info, variable, image, curve):
    if image not in info.get("RepoDigests", []):
        raise ValueError("runtime image differs from the qualified build digest")
    if (info.get("Os"), info.get("Architecture")) != ("linux", "amd64"):
        raise ValueError("runtime image is not Linux amd64")
    expected = {"org.opencontainers.image.revision": VERA}
    if variable in ("ORBIS_NATIVE_IMAGE", "ORBIS_NATIVE_DIAGNOSTIC_IMAGE"):
        expected = {
            "org.opencontainers.image.revision": RUNTIME,
            "io.sourcenetwork.orbis.backend": "native",
            "io.sourcenetwork.orbis.curve": curve,
            "io.sourcenetwork.orbis.integration-features": "false",
        }
        if variable == "ORBIS_NATIVE_DIAGNOSTIC_IMAGE":
            expected["io.sourcenetwork.orbis.unsafe-testing"] = "true"
    elif variable != "ORBIS_NATIVE_VERA_IMAGE":
        raise ValueError("unsupported runtime image")
    labels = info["Config"].get("Labels") or {}
    if any(labels.get(key) != value for key, value in expected.items()):
        raise ValueError("runtime image labels do not match the selected sources")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", info.get("Id", "")):
        raise ValueError("invalid runtime image ID")
    return info["Id"]


def capture(command):
    return subprocess.check_output(command, text=True).strip()


def verified_fixture_source(runtime):
    if capture(["git", "status", "--porcelain", "--untracked-files=no"]):
        raise ValueError("qualification requires unchanged tracked source")
    source = {"head": capture(["git", "rev-parse", "HEAD"]),
              "tree": capture(["git", "rev-parse", "HEAD^{tree}"])}
    # Disabling renames keeps a removed production path visible to the allowlist.
    changed = capture(["git", "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                       "--name-only", runtime, source["head"], "--"]).splitlines()
    verify_fixture_changes(changed)
    return source


def soak_result(tail):
    matches = re.findall(r'native_threshold_soak=(\{[^\n]{1,256}\})', tail)
    if len(matches) != 1:
        return None
    try:
        result = json.loads(matches[0])
    except json.JSONDecodeError:
        return None
    if set(result) != {"cycles", "active_seconds", "restarts"}:
        return None
    if any(type(value) is not int for value in result.values()):
        return None
    if not (20 <= result["cycles"] <= 1800 and 900 <= result["active_seconds"] <= 1800
            and result["restarts"] == 3):
        return None
    return result


def polynomial_result(content):
    matches = re.findall(r'native_polynomial_state=(\{[^\n]{1,4096}\})', content)
    if len(matches) != 1:
        return None
    try:
        result = json.loads(matches[0])
    except json.JSONDecodeError:
        return None
    if set(result) != {"members", "previous", "responses"}:
        return None
    if type(result["members"]) is not int or not 1 <= result["members"] <= 4:
        return None
    if type(result["previous"]) is not bool or not isinstance(result["responses"], list):
        return None
    if len(result["responses"]) != result["members"]:
        return None
    for member in result["responses"]:
        if not isinstance(member, dict) or set(member) != {"connected", "main", "pet"}:
            return None
        if member["connected"] is not None and type(member["connected"]) is not bool:
            return None
        for response in (member["main"], member["pet"]):
            if not isinstance(response, dict) or set(response) != {"status", "present", "changed", "matches_first"}:
                return None
            status = response["status"]
            if status is not None and (type(status) is not int or not 0 <= status <= 16):
                return None
            if member["connected"] is not True and status is not None:
                return None
            if any(value is not None and type(value) is not bool for key, value in response.items() if key != "status"):
                return None
            if status != 0 and any(response[key] is not None for key in ("present", "changed", "matches_first")):
                return None
            if status == 0:
                if type(response["present"]) is not bool:
                    return None
                if result["previous"]:
                    if type(response["changed"]) is not bool:
                        return None
                elif response["changed"] is not None:
                    return None
    return result


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
                "support/native_pet/soak.rs",
            )
            locations = re.findall(r"(?:bin/orbis-node/tests/|tests/)(" +
                                   "|".join(re.escape(source) for source in filenames) +
                                   r"):(\d{1,6}):(\d{1,6})", content)
            record["locations"] = [{"source": source, "line": int(line), "column": int(column)}
                                   for source, line, column in sorted(set(locations))[:8]]
            record["deadline"] = any(marker in content for marker in ("Elapsed(())", "TIMED OUT", "execution timed out"))
            record["permission_denied"] = "PermissionDenied" in content
            record["panicked"] = "panicked at" in content
            polynomials = polynomial_result(content)
            if polynomials is not None:
                record["polynomials"] = polynomials
        cases.append(record)
    return {"complete": all(case["status"] == "passed" for case in cases), "cases": cases}


def qualify():
    curve = os.environ["NATIVE_RESTART_CURVE"]
    if curve not in ("bls12-381", "jubjub"):
        raise ValueError("unsupported curve")
    subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", RUNTIME], check=True)
    source = verified_fixture_source(RUNTIME)
    if Path("docker/NATIVE_VERA_REF").read_text().strip() != VERA:
        raise ValueError("Vera source does not match the runtime image")
    suite = os.environ.get("NATIVE_RESTART_SUITE", "restart")
    scenarios = {
        "restart": ["native_startup_registers_and_preserves_identity_on_restart"],
        "fault": ["native_pet_fault_reports"],
        "threshold": ["native_distributed_threshold_workflows", "native_pet_threshold_workflows",
                      "native_pet_member_replacement", "native_pet_scheduled_refresh_after_restart"],
        "soak": ["native_threshold_soak"],
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
        "ORBIS_NATIVE_IMAGE": f"{repository}/node-integration@{RUNTIME_DIGESTS[curve]}",
        "ORBIS_NATIVE_VERA_IMAGE": f"{repository}/vera-native@{VERA_DIGEST}",
    }
    if suite == "fault":
        images["ORBIS_NATIVE_DIAGNOSTIC_IMAGE"] = (
            f"{repository}/node-integration@{DIAGNOSTIC_DIGESTS[curve]}"
        )
    for variable, image in images.items():
        subprocess.run(["docker", "pull", image], check=True)
        info = json.loads(capture(["docker", "image", "inspect", image]))[0]
        env[variable] = verified_image_id(info, variable, image, curve)
    output = Path(os.environ["RUNNER_TEMP"]) / ("native-" + suite + "-" + curve)
    output.mkdir(mode=0o700, exist_ok=False)
    unit_flags = ["--lib", "container::tests::bind_mount_user_rejects_files_and_symlinks", "--", "--exact"]
    if suite in ("threshold", "soak"):
        unit_flags = ["--features", "native", "--lib", "native_network::tests::"]
    profile = "native-soak" if suite == "soak" else "ci"
    ignored_flags = ["--run-ignored", "only", "--success-output", "immediate"] if suite == "soak" else []
    commands = [
        ["cargo", "test", "--release", "--locked", "-p", "test-support", "--no-default-features", *unit_flags],
        ["cargo", "test", "--release", "--locked", "-p", "orbis-node", "--no-default-features",
         "--features", "integration-test-native,redb,iroh," + curve,
         "--test", "native_startup", "native_polynomial_state_"],
        ["cargo", "nextest", "run", "--release", "--locked", "--profile", profile,
         "--retries", "0", "--no-tests", "fail", "--test-threads", "1", "-p", "orbis-node", "--no-default-features",
         "--features", "integration-test-native,redb,iroh," + curve,
         "--test", "native_startup", *ignored_flags,
         "-E", " | ".join("test(=" + name + ")" for name in selected)],
    ]
    report = Path(env.get("CARGO_TARGET_DIR", "target")) / "nextest" / profile / "junit.xml"
    codes = []
    for index, command in enumerate(commands):
        is_scenario = command[1] == "nextest"
        print(json.dumps({"curve": curve, "stage": index, "state": "running"}), flush=True)
        started = time.monotonic()
        log = output / (str(index) + ".log")
        if is_scenario:
            report.unlink(missing_ok=True)
        with log.open("x") as stream:
            os.chmod(log, 0o600)
            result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
        if verified_fixture_source(RUNTIME) != source:
            raise ValueError("qualification source changed during execution")
        codes.append(result.returncode)
        print(json.dumps({"curve": curve, "stage": index, "exit_code": result.returncode,
                          "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)
        passed = result.returncode == 0
        if is_scenario:
            summary = lifecycle_results(report, selected)
            if suite == "soak":
                with log.open("rb") as stream:
                    stream.seek(max(0, log.stat().st_size - 65536))
                    soak = soak_result(stream.read().decode("utf-8", errors="replace"))
                summary["soak"] = soak
                summary["complete"] = summary["complete"] and soak is not None
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
