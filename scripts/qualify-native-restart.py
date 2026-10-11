#!/usr/bin/env python3
"""Qualify native lifecycle scenarios against unchanged normal runtime images."""
import json
import math
import os
import stat
import re
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

RUNTIME = "d80d02d6f2f3606cd0c0a9688c7a5ae09d658bd4"
VERA = "9d5c2b9ea7cb971a7871028b7b0b22d488a7ecbf"
# Source-verified Linux amd64 images from run 38160944392, built at RUNTIME.
VERA_DIGEST = "sha256:13100a948d3dc642839aeb29de747d7a0c7d9c78fb018d33bce6bfb3902bebfd"
RUNTIME_DIGESTS = {
    "bls12-381": "sha256:93e19dd7cb69003eda51172f93ca62023f8cf4b1509e608678e3cd40f33f8990",
    "jubjub": "sha256:e4b3c630c15addce4d18f19c638d2f2396d88fc8620e5c96edcaa326a9528937",
}
DIAGNOSTIC_DIGESTS = {
    "bls12-381": "sha256:09d26cdad7bc33cbe800746015347379b16135faa0d74fee0f418c756fc9f42f",
    "jubjub": "sha256:7382aa857f00c4da0f8c577bf42e62edef94fc512c8e9bdf1ec1ac4365263c97",
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
    "bin/orbis-node/tests/support/native_pet/member_churn.rs",
    "bin/orbis-node/tests/support/native_pet/signing.rs",
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
    if variable == "ORBIS_NATIVE_IMAGE" and labels.get("io.sourcenetwork.orbis.unsafe-testing") not in (None, "false"):
        raise ValueError("normal runtime image enables diagnostic features")
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


def churn_result(tail):
    matches = re.findall(r'native_threshold_churn=(\{[^\n]{1,256}\})', tail)
    if len(matches) != 1:
        return None
    try:
        result = json.loads(matches[0])
    except json.JSONDecodeError:
        return None
    expected = {"changes": 5, "reentries": 4, "crash_restarts": 10}
    if result != expected or any(type(value) is not int for value in result.values()):
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
                "support/native_pet/member_churn.rs",
                "support/native_pet/scheduled_store.rs", "support/native_pet/report_fault.rs",
                "support/native_pet/report_acceptance.rs",
                "support/native_pet/soak.rs", "support/native_pet/signing.rs",
                "support/native_pet/polynomial_state.rs", "support/pet_dkg_contract.rs",
                "support/pre_scenario.rs", "support/sign_scenario.rs",
                "support/refresh_scenario.rs", "support/reshare_scenario.rs",
                "support/native_confirmation.rs",
            )
            locations = re.findall(r"(?:bin/orbis-node/tests/|tests/)(" +
                                   "|".join(re.escape(source) for source in filenames) +
                                   r"):(\d{1,6}):(\d{1,6})", content)
            record["locations"] = [{"source": source, "line": int(line), "column": int(column)}
                                   for source, line, column in sorted(set(locations))[:8]]
            record["deadline"] = any(marker in content for marker in ("Elapsed(())", "TIMED OUT", "execution timed out"))
            record["permission_denied"] = "PermissionDenied" in content
            record["panicked"] = "panicked at" in content
            phases = re.findall(
                r"native PET phase=(paired-dkg|stored-inline-permissions-revocation-regrant|"
                r"replacement-finalized|replacement-material-ready|replacement-signing|"
                r"replacement-restart-signing|member-replacement-restart|churn-round-start|churn-finalized|"
                r"member-churn|scheduled-refresh-after-restart|reshared-pre|restart-pre|fault-report)\b",
                content,
            )
            if phases:
                record["pet_phase"] = phases[-1]
            rounds = re.findall(r"native PET phase=(?:churn-round-start|churn-finalized) round=([1-4])\b", content)
            if rounds:
                record["churn_round"] = int(rounds[-1])
            signing = re.findall(r"native_churn_sign member=([0-3]) cycle=([1-4](?:00|10|30))\b", content)
            if signing:
                member, cycle = signing[-1]
                record['churn_signing'] = {'member': int(member), 'cycle': int(cycle)}
            insufficient = re.findall(r'Insufficient shares: got ([0-9]{1,4}), need ([0-9]{1,4})\b', content)
            if insufficient:
                got, need = map(int, insufficient[-1])
                if got <= 4096 and 1 <= need <= 4096:
                    record['insufficient_shares'] = {'got': got, 'need': need}
            grpc_codes = {
                "Cancelled", "Unknown", "InvalidArgument", "DeadlineExceeded", "NotFound",
                "AlreadyExists", "PermissionDenied", "ResourceExhausted", "FailedPrecondition",
                "Aborted", "OutOfRange", "Unimplemented", "Internal", "Unavailable",
                "DataLoss", "Unauthenticated",
            }
            observed_codes = re.findall(r"Status \{ code: ([A-Za-z]{1,32}),", content)
            if observed_codes:
                record["rpc_codes"] = sorted(set(observed_codes) & grpc_codes)[:8]
            error_classes = {
                "unauthorized": "Unauthorized:", "serialization": "Serialization error:",
                "deserialization": "Deserialization error:", "network_connection": "Network connection error:",
                "network_communication": "Network communication error:", "crypto": "Cryptographic operation error:",
                "verification": "Verification failed:", "recovery": "Recovery failed:",
                "storage": "Local storage error:", "ring_not_found": "Ring not found:",
                "insufficient_shares": "Insufficient shares:", "response_timeout": "Timeout waiting for responses:",
                "invalid_input": "Invalid input:", "invalid_state": "Invalid state:",
                "nonce_state": "Nonce state error:", "protocol": "Protocol error:",
                "reshare_in_progress": "Ring reshare in progress, try again shortly",
                "generic": "Sign error:", "system_time": "System time error:", "authz": "Authz error:",
                "ring_polynomial_state": "Failed to load ring polynomial state:",
            }
            observed_classes = [name for name, prefix in error_classes.items()
                                if 'message: "' + prefix in content]
            if observed_classes:
                record["sign_error_classes"] = sorted(observed_classes)[:8]
            polynomials = polynomial_result(content)
            if polynomials is not None:
                record["polynomials"] = polynomials
        cases.append(record)
    return {"complete": all(case["status"] == "passed" for case in cases), "cases": cases}


def fixture_peer_indices(fixture):
    try:
        descriptor = os.open(fixture / 'diagnostic-peer-routes.json',
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return {}
            raw = stream.read(4097)
        if len(raw) > 4096:
            return {}
        peers = json.loads(raw)
        if not isinstance(peers, list) or len(peers) != 4 or any(
                not isinstance(peer, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', peer)
                for peer in peers):
            return {}
        if len(set(peer.lower() for peer in peers)) != 4:
            return {}
        return {peer.lower(): member for member, peer in enumerate(peers)}
    except (OSError, ValueError):
        return {}


def received_nonce_requests(tail, peers):
    received = {}
    for line in tail.splitlines():
        if 'Sign Coordinator: Received NonceRequest' not in line:
            continue
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        request = re.search(r'\brequest_id="?nonce-([A-Za-z0-9_-]{1,96})(?:"|\s|$)', line)
        sender = re.search(r'\bsender_peer="?([0-9a-fA-F]{64})(?:"|\s|$)', line)
        member = peers.get(sender[1].lower()) if sender else None
        if request and member is not None:
            key = (request[1], member)
            if key not in received and len(received) == 256:
                del received[next(iter(received))]
            received[key] = True
    return received


def signing_attempts(tail, peers, received=None, coordinator=None):
    """Correlate fixed transport events without exporting request or peer IDs."""
    attempts = {}
    for line in tail.splitlines():
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        identity = re.search(r'\brequest_id="?([A-Za-z0-9_-]{1,96})(?:"|\s|$)', line)
        if not identity:
            continue
        if 'Sign Coordinator: Initiating signing' in line:
            fields = {}
            for name in ('peer_count', 'threshold'):
                match = re.search(r'\b' + name + r'=([0-9]{1,4})\b', line)
                if match and int(match[1]) <= 4096:
                    fields[name] = int(match[1])
            for name in ('self_in_list', 'interactive'):
                match = re.search(r'\b' + name + r'=(true|false)\b', line)
                if match:
                    fields[name] = match[1] == 'true'
            if len(fields) == 4:
                if len(attempts) == 64:
                    del attempts[next(iter(attempts))]
                attempts[identity[1]] = {'configuration': fields, 'recovered': False, 'peer_errors': []}
        attempt = attempts.get(identity[1])
        if attempt is None:
            continue
        if 'Sign Coordinator: Successfully recovered signature' in line:
            attempt['recovered'] = True
        phase = ('nonce' if 'Nonce peer request failed' in line else
                 'signature' if 'Sign peer request failed' in line else None)
        if phase is None or len(attempt['peer_errors']) == 8:
            continue
        peer = re.search(r'\bpeer_id="?([0-9a-fA-F]{64})(?:@|"|\s|$)', line)
        classes = {'connection': 'Network connection error:',
                   'communication': 'Network communication error:',
                   'unauthorized': 'Unauthorized:', 'nonce_state': 'Nonce state error:',
                   'timeout': 'Timeout waiting for responses:', 'invalid_input': 'Invalid input:',
                   'invalid_state': 'Invalid state:', 'protocol': 'Protocol error:'}
        error_class = next((name for name, marker in classes.items() if marker in line), None)
        attempt['peer_errors'].append({'phase': phase,
            'member': peers.get(peer[1].lower()) if peer else None,
            'class': error_class,
            'timed_out': any(marker in line.lower() for marker in ('timed out', 'timeout', 'deadline exceeded'))})
        if received is not None and phase == 'nonce':
            receiver = attempt['peer_errors'][-1]['member']
            observed = received.get(receiver)
            attempt['peer_errors'][-1]['nonce_request_observed'] = (
                (identity[1], coordinator) in observed if observed is not None else None)
    return list(attempts.values())[-16:]


def signing_restart_diagnostics(directory, filename='pet-replacement-restart.log', selected=(2, 3)):
    """Export bounded counters from fixed private fixture logs."""
    if filename not in ('pet-replacement-restart.log', 'churn-diagnostic.log') or any(
            member not in range(4) for member in selected):
        raise ValueError('unsupported diagnostic log')
    fixtures = list(directory.glob('orbis-native-*'))
    if len(fixtures) != 1 or fixtures[0].is_symlink():
        return {'available': False, 'members': []}
    peer_indices = fixture_peer_indices(fixtures[0])
    markers = {
        'nonce_requests': 'Sign Coordinator: Received NonceRequest',
        'sign_requests': 'Sign Coordinator: Received SignRequest',
        'sign_responses': 'Sign Coordinator: Sending SignResponse',
        'nonce_peer_errors': 'Nonce peer request failed',
        'sign_peer_errors': 'Sign peer request failed',
        'nonce_deadlines': 'Nonce collection timed out; proceeding with partial responses',
        'sign_deadlines': 'Sign collection timed out; proceeding with partial responses',
        'local_signing_errors': 'Sign Coordinator: Local signing failed',
        'local_verification_errors': 'Sign Coordinator: Local share verification failed',
        'missing_nonce': 'No nonce state found for request_id',
        'nonce_context_mismatch': 'Nonce context key mismatch for request_id',
        'peer_nonce_id_mismatches': 'Sign Coordinator: nonce response node_id does not match authenticated peer',
        'peer_signature_id_mismatches': 'Sign Coordinator: signature response node_id does not match authenticated peer',
        'peer_signature_verification_errors': 'Sign Coordinator: Failed to verify share',
        'peer_signature_decode_errors': 'Sign Coordinator: Failed to deserialize sig_share',
        'peer_nonce_decode_errors': 'Sign Coordinator: Failed to deserialize nonce commitment',

        'nonce_capacity': 'Nonce state limit exceeded',
        'signatures_recovered': 'Sign Coordinator: Successfully recovered signature',
        'main_promotions': 'Reshare: promoted staged bundle after chain confirmation',
        'pet_promotions': 'Reshare: promoted staged PET bundle after bulletin confirmation',
        'pet_staged': 'Reshare PET: Phase 4 complete',
        'local_pet_not_ready': 'Reshare: local PET promotion not ready',
        'confirmation_timeouts': 'Reshare: timed out waiting for bulletin confirmation',
        'confirmation_recheck_errors': 'Reshare: failed to recheck confirmation before local promotion',
        'staged_pet_read_errors': 'Reshare: failed to read staged local PET bundle',
        'local_bundle_missing': 'local bundle missing, falling back to ring config polynomial',
        'missing_main_bundle': 'Reshare: chain confirmed but no staged bundle was found',
        'main_write_errors': 'Reshare: chain confirmed but writing the promoted bundle',
        'pet_write_errors': 'Reshare: failed to promote local PET bundle',
        'confirmation_mismatches': 'Reshare: bulletin confirmation did not match',
        'attempt_deadlines': 'SessionStateManager: Removing DKG attempt at hard deadline',
        'expired_sessions': 'SessionStateManager: Expired session cleanup complete',

    }
    members = []
    tails = {}
    for member in selected:
        parent = fixtures[0] / f'node-{member}'
        result = {'member': member, 'log_available': False}
        if not parent.is_symlink():
            try:
                descriptor = os.open(parent / filename,
                                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise OSError('restart log is not a regular file')
                    size = stream.seek(0, os.SEEK_END)
                    stream.seek(max(0, size - 1024 * 1024))
                    tail = stream.read(1024 * 1024).decode('utf-8', errors='replace')
                result.update(log_available=True, tail_truncated=size > 1024 * 1024,
                              counters={name: tail.count(marker) for name, marker in markers.items()})
                configurations = []
                for line in tail.splitlines():
                    if 'Sign Coordinator: Initiating signing' not in line:
                        continue
                    line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                    fields = {}
                    for name in ('peer_count', 'threshold'):
                        match = re.search(r'\b' + name + r'=([0-9]{1,4})\b', line)
                        if match and int(match[1]) <= 4096:
                            fields[name] = int(match[1])
                    for name in ('self_in_list', 'interactive'):
                        match = re.search(r'\b' + name + r'=(true|false)\b', line)
                        if match:
                            fields[name] = match[1] == 'true'
                    if len(fields) == 4:
                        configurations.append(fields)
                result['last_signing_configuration'] = configurations[-1] if configurations else None
                tails[member] = tail

            except OSError:
                pass
        members.append(result)
    received = {member: received_nonce_requests(tail, peer_indices)
                for member, tail in tails.items()}
    for member in members:
        if member['log_available']:
            member['signing_attempts'] = signing_attempts(
                tails[member['member']], peer_indices, received, member['member'])
    return {'available': all(member['log_available'] for member in members),
            'members': members}


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
    churn = suite == "threshold" and requested == "native_pet_member_churn"
    if churn:
        selected = [requested]
    elif requested != "all":
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
    if churn:
        nodes = output / 'nodes'
        nodes.mkdir(mode=0o700)
        env['ORBIS_NATIVE_E2E_DIR'] = str(nodes)
    unit_flags = ["--lib", "container::tests::bind_mount_user_rejects_files_and_symlinks", "--", "--exact"]
    if suite in ("threshold", "soak"):
        unit_flags = ["--features", "native", "--lib", "native_network::tests::"]
    focused_ignored = suite == "soak" or churn
    profile = "native-soak" if focused_ignored else "ci"
    ignored_flags = ["--run-ignored", "only", "--success-output", "immediate"] if focused_ignored else []
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
            if churn:
                with log.open("rb") as stream:
                    stream.seek(max(0, log.stat().st_size - 65536))
                    observed = churn_result(stream.read().decode("utf-8", errors="replace"))
                summary["churn"] = observed
                summary["complete"] = summary["complete"] and observed is not None
                if any(case['status'] == 'failed' for case in summary['cases']):
                    summary['failure_events'] = signing_restart_diagnostics(
                        output / 'nodes', 'churn-diagnostic.log', tuple(range(4)))
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
