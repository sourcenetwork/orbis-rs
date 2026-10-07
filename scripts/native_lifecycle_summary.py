"""Allowlisted CI failure facts; never copy diagnostic text or paths to output."""
import json
import math
from pathlib import Path
import re

CURVES = ("bls12-381", "jubjub")
SUITES = ("lifecycle", "fault-report")
FAULT_SCENARIO = "native_pet_fault_reports"
SCENARIOS = ("native_pet_threshold_workflows", "native_distributed_threshold_workflows",
             "native_pet_member_replacement")
PET_MEMBER_REPLACEMENT_PHASE = (
    "native PET phase=member-replacement-restart incoming-required=true "
    "paired-keys-stable=true departed-secrets-absent=true"
)
PET_PHASES = (
    "native PET phase=paired-dkg members=3 threshold=2",
    "native PET phase=stored-inline-permissions-revocation-regrant",
    "native PET phase=reshared-pre members=2 threshold=2 both-polynomials-changed=true",
    "native PET phase=restart-pre preserved-main-and-pet-shares=true",
)
TOOL_STAGES = ("rust-toolchain", "vera-init", "vera-fetch", "vera-checkout", "build-verad",
               "build-orbis", "native-dependencies", "compile-native-tests", "native-integration")
FIXTURES = {
    "bin/orbis-node/tests/native_startup.rs": "startup",
    "bin/orbis-node/tests/support/native_workflow.rs": "workflow",
    "bin/orbis-node/tests/support/native_pet.rs": "pet",
    "bin/orbis-node/tests/support/native_pet/document.rs": "pet_document",
    "bin/orbis-node/tests/support/native_pet/member_replacement.rs": "pet_replacement",
    "bin/orbis-node/tests/support/native_pet/report_fault.rs": "pet_report",
}
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
RESULT = re.compile(r"^test result: (?:ok|FAILED)\. ([0-9]{1,6}) passed; ([0-9]{1,6}) failed; ([0-9]{1,6}) ignored;")
PANIC = re.compile(r"^thread .{0,1024} panicked at ([^\r\n]+):([0-9]{1,6}):([0-9]{1,5}):$")
FAULT_REPORT = re.compile(
    r"^native PET phase=fault-report accepted_height=([1-9][0-9]{0,19}) "
    r"replicas=4 accused_demerits=1 retained_sessions=1 bundles_unchanged=true$"
)


def failure_summary(curve, step, exit_code, elapsed_seconds, lines, source_root):
    """Build a new fixed-shape object from known labels and bounded numeric facts.

    Panic/Elapsed counts are observed markers, not diagnoses of the root cause.
    Missing or ambiguous libtest footers remain unavailable instead of zero.
    """
    if (curve not in CURVES or (exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255))
            or (elapsed_seconds is not None and (type(elapsed_seconds) not in (int, float)
                or not math.isfinite(elapsed_seconds) or not 0 <= elapsed_seconds <= 604800))):
        raise ValueError("invalid failure summary context")
    stage, scenario = (step, None) if step in TOOL_STAGES else ("driver", None)
    for known in (*SCENARIOS, FAULT_SCENARIO):
        if step == "scenarios/" + known + "/attempt-1/command":
            stage, scenario = "live", known
    root = Path(source_root)
    result = {
        "curve": curve, "stage": stage, "scenario": scenario, "exit_code": exit_code,
        "elapsed_seconds": round(elapsed_seconds, 2) if elapsed_seconds is not None else None,
        "libtest_result_count": 0, "tests": None, "pet_phase_bits": 0,
        "pet_member_replacement_complete": False,
        "pet_fault_report_complete": False, "pet_fault_report_height": None,
        "pet_fault_report_markers": 0,
        "compiler_errors": 0, "compiler_warnings": 0, "compiler_error_codes": {},
        "malformed_json_lines": 0, "panic_headers": 0, "assertion_markers": 0,
        "elapsed_markers": 0, "fixture_locations": [],
    }
    results, codes, locations = [], {}, set()
    for raw in lines:
        # Do not preserve any part of a raw line in the returned object.
        line = ANSI.sub("", raw).strip()
        if len(line) > 1048576:
            result["malformed_json_lines"] += int(line.startswith("{"))
            continue
        if line.startswith("{"):
            try:
                event = json.loads(line)
            except (ValueError, RecursionError):
                result["malformed_json_lines"] += 1
                continue
            if isinstance(event, dict) and event.get("reason") == "compiler-message":
                message = event.get("message")
                if isinstance(message, dict):
                    level = message.get("level")
                    if level in ("error", "warning"):
                        result["compiler_errors" if level == "error" else "compiler_warnings"] += 1
                    code = message.get("code")
                    code = code.get("code") if isinstance(code, dict) else None
                    if level == "error" and isinstance(code, str) and re.fullmatch(r"E[0-9]{4}", code):
                        codes[code] = codes.get(code, 0) + 1
            # Never classify the rendered/source-snippet fields as runtime output.
            continue
        footer = RESULT.match(line)
        if footer:
            results.append(tuple(map(int, footer.groups())))
        for index, phase in enumerate(PET_PHASES):
            if line == phase:
                result["pet_phase_bits"] |= 1 << index
        if line == PET_MEMBER_REPLACEMENT_PHASE:
            result["pet_member_replacement_complete"] = True
        if line.startswith("native PET phase=fault-report"):
            result["pet_fault_report_markers"] += 1
            report = FAULT_REPORT.fullmatch(line)
            if report and int(report[1]) <= 2**64 - 1:
                result["pet_fault_report_height"] = int(report[1])
        result["panic_headers"] += int(line.startswith("thread ") and " panicked at " in line)
        result["assertion_markers"] += int(line.startswith("assertion ") and "failed" in line)
        result["elapsed_markers"] += line.count("Elapsed(())")
        panic = PANIC.fullmatch(line)
        if panic:
            path, row, column = panic.groups()
            for relative, identifier in FIXTURES.items():
                if path in (relative, str(root / relative)):
                    locations.add((identifier, int(row), int(column)))
    result["pet_fault_report_complete"] = (
        result["pet_fault_report_markers"] == 1 and result["pet_fault_report_height"] is not None
    )
    if not result["pet_fault_report_complete"]:
        result["pet_fault_report_height"] = None
    result["libtest_result_count"] = len(results)
    if len(results) == 1:
        result["tests"] = dict(zip(("passed", "failed", "ignored"), results[0]))
    result["compiler_error_codes"] = {code: min(codes[code], 1000000) for code in sorted(codes)[:32]}
    result["fixture_locations"] = [{"file_id": name, "line": row, "column": column}
                                   for name, row, column in sorted(locations)[:16]]
    for name in ("libtest_result_count", "compiler_errors", "compiler_warnings", "malformed_json_lines",
                 "panic_headers", "assertion_markers", "elapsed_markers", "pet_fault_report_markers"):
        result[name] = min(result[name], 1000000)
    return result


def verify_selection(document, suite="lifecycle"):
    if suite not in SUITES:
        raise ValueError("unknown native suite")
    expected = SCENARIOS if suite == "lifecycle" else (FAULT_SCENARIO,)
    suites = list(document["rust-suites"].values())
    if len(suites) != 1 or suites[0]["binary-name"] != "native_startup":
        raise ValueError("unexpected native test binaries")
    selected = set()
    for name, case in suites[0]["testcases"].items():
        if case["filter-match"]["status"] == "matches":
            if case["ignored"] is not True:
                raise ValueError("expected ignored container fixture")
            selected.add(name)
    if selected != set(expected):
        raise ValueError("native scenario selection differs")
    return len(selected)


def verify_outcome(result, suite="lifecycle"):
    if suite not in SUITES or result["exit_code"] != 0:
        raise ValueError("native scenario did not pass")
    if suite == "fault-report":
        complete = result["pet_fault_report_complete"]
    else:
        complete = (result["pet_phase_bits"] == (1 << len(PET_PHASES)) - 1
                    and result["pet_member_replacement_complete"])
    if not complete:
        raise ValueError("native scenario evidence incomplete")


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=SUITES, default="lifecycle")
    parser.add_argument("--list", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--curve", choices=CURVES)
    parser.add_argument("--exit-code", type=int)
    args = parser.parse_args()
    try:
        if args.list is not None:
            count = verify_selection(json.loads(args.list.read_text()), args.suite)
            print(json.dumps({"selected_native_scenarios": count}))
            return
        if args.log is None or args.curve is None or args.exit_code is None:
            raise ValueError("missing diagnostic arguments")
        with args.log.open(errors="replace") as stream:
            step = "native-integration" if args.suite == "lifecycle" else "scenarios/" + FAULT_SCENARIO + "/attempt-1/command"
            result = failure_summary(args.curve, step, args.exit_code, None, stream,
                                     Path(__file__).resolve().parents[1])
        print(json.dumps(result, sort_keys=True))
        verify_outcome(result, args.suite)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        parser.exit(1, "Native integration validation failed; raw diagnostics remain private.\n")

if __name__ == "__main__":
    main()
