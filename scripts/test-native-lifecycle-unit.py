#!/usr/bin/env python3
"""Driver regressions with simulated commands; no network, compiler or live nodes."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("native_lifecycle", Path(__file__).with_name("test-native-lifecycle.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class NativeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.root = self.base / "checkout"
        self.root.mkdir()
        (self.root / "Cargo.lock").write_text("frozen lock")
        for name in driver.MANIFESTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('vera-client = { git = "https://github.com/sourcenetwork/vera.rs", rev = "' + "a" * 40 + '" }\n')
        self.commands = []
        self.live = []
        self.boundary_failure = False
        self.zero_tests = False
        self.missing_phase = False
        self.replacement_phase = driver.PET_MEMBER_REPLACEMENT_PHASE
        self.mutate_source = False
        self.nonzero = False
        self.compiler_failure = False

    def snapshot(self, source):
        return {"head": "a" * 40 if source.name == "vera" else "b" * 40,
                "changed_files": {}, "lock_sha256": driver.sha(source / "Cargo.lock"), "status": ""}

    def command(self, command, cwd, env, stdout, stderr):
        self.commands.append(command)
        target = Path(env["CARGO_TARGET_DIR"])
        release = target / "release"
        release.mkdir(parents=True, exist_ok=True)
        output = ""
        self.assertFalse(any(name.startswith(("CARGO_PROFILE_", "ORBIS_LOCAL_STORAGE_KDF_")) for name in env))
        self.assertNotIn("VERA_E2E_DEADLINE_SCALE", env)
        if command[:2] == ["git", "init"]:
            Path(command[-1]).mkdir()
        elif command[0] == "git" and "checkout" in command:
            (Path(command[2]) / "Cargo.lock").write_text("Vera lock")
        elif "build" in command:
            binary = command[command.index("--bin") + 1]
            self.assertIn("--message-format=json", command)
            (release / binary).write_text("normal " + binary)
            (release / binary).chmod(0o700)
            if self.compiler_failure:
                output = json.dumps({"reason": "compiler-message", "message": {
                    "level": "error", "code": {"code": "E0308"},
                    "message": "sensitive runtime data", "rendered": "/private/secret/password"}}) + "\n"
        elif "tree" in command:
            output = "cosmos-sdk-proto v0.1.0\n" if self.boundary_failure else "orbis-node v0.0.1\n"
        elif command[:3] == ["cargo", "+1.98.0", "test"]:
            self.assertIn("--message-format=json", command)
            # Test feature unification can overwrite Cargo's ordinary node path.
            # The executable used by the live fixture must already be staged.
            (release / "orbis-node").write_text("dev feature node")
            test = release / "deps/native_startup-fixture"
            test.parent.mkdir()
            test.write_text("compiled test")
            test.chmod(0o700)
            output = json.dumps({"reason": "compiler-artifact", "target": {"name": "native_startup", "kind": ["test"]}, "executable": str(test)}) + "\n"
        elif command[0].endswith("native_startup"):
            self.assertEqual(Path(env["ORBIS_NODE_BINARY"]).read_text(), "normal orbis-node")
            self.assertEqual(Path(env["VERAD_BINARY"]).read_text(), "normal verad")
            self.assertEqual(command[2:], ["--ignored", "--exact", "--test-threads=1", "--nocapture"])
            self.live.append((command[1], env["VERA_E2E_DIR"], env["ORBIS_NATIVE_E2E_DIR"]))
            private = Path(env["ORBIS_NATIVE_E2E_DIR"]) / "node.log"
            private.write_text("sensitive runtime data")
            output = "sensitive runtime data\n"
            if command[1] == driver.SCENARIOS[0]:
                output += "\n".join(driver.PET_PHASES[:-1] if self.missing_phase else driver.PET_PHASES) + "\n"
            if command[1] == "native_pet_member_replacement":
                output += self.replacement_phase + "\n"
            count = 0 if self.zero_tests else 1
            output += f"test result: ok. {count} passed; 0 failed; 0 ignored; finished in 0.01s\n"
            if self.mutate_source:
                (self.root / "Cargo.lock").write_text("changed lock")
        stdout.write(output)
        failed = (self.nonzero and command[0].endswith("native_startup")) or (self.compiler_failure and "build" in command)
        return subprocess.CompletedProcess(command, 101 if failed else 0)

    def qualify(self, curve="bls12-381"):
        with patch.object(driver, "snapshot", side_effect=self.snapshot), patch.object(driver.subprocess, "run", side_effect=self.command):
            return driver.qualify(self.root, curve, self.base)

    def test_both_curves_stage_normal_binaries_and_run_only_three_exact_scenarios(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            outputs = [self.qualify(curve) for curve in driver.CURVES]
        self.assertEqual([entry[0] for entry in self.live], list(driver.SCENARIOS) * 2)
        self.assertEqual(len({entry[1] for entry in self.live}), 6)
        self.assertEqual(len({entry[2] for entry in self.live}), 6)
        self.assertNotIn("sensitive runtime data", captured.getvalue())
        self.assertEqual(sum("test" in command for command in self.commands), 2)
        self.assertFalse(any("clean" in command for command in self.commands))
        for output in outputs:
            result = json.loads((output / "manifest.json").read_text())
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["binaries"]["orbis"]["sha256"], driver.sha(output / "bin/orbis-node"))
            self.assertTrue(result["retained_log_sha256"])
            self.assertEqual(result["kdf"], {"m_cost_kib": 262144, "t_cost": 3})
            self.assertFalse(result["deadline_overrides"])
            self.assertTrue(result["steps"][-1]["pet_member_replacement_complete"])

    def test_compiler_failure_prints_only_structured_allowlisted_facts(self):
        self.compiler_failure = True
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), self.assertRaisesRegex(ValueError, "command failed"):
            self.qualify()
        text = captured.getvalue()
        self.assertNotIn("sensitive runtime data", text)
        self.assertNotIn("/private/secret", text)
        line = next(line for line in text.splitlines() if line.startswith("Native lifecycle failure summary: "))
        summary = json.loads(line.split(": ", 1)[1])
        self.assertEqual(summary["stage"], "build-verad")
        self.assertEqual(summary["compiler_errors"], 1)
        self.assertEqual(summary["compiler_error_codes"], {"E0308": 1})
        self.assertIsNone(summary["tests"])
        self.assertFalse(self.live)
        # Parser or log-read failures must preserve the original qualification
        # exception and must never print the diagnostic collection error.
        for error in (ValueError("sensitive parser failure"), OSError("/private/secret/log")):
            with self.subTest(error=type(error).__name__), contextlib.redirect_stdout(captured):
                with patch.object(driver, "failure_summary", side_effect=error):
                    with self.assertRaisesRegex(ValueError, "Qualification command failed"):
                        self.qualify()
        self.assertNotIn("sensitive parser failure", captured.getvalue())
        self.assertNotIn("/private/secret", captured.getvalue())

    def test_native_dependency_leak_stops_before_test_compilation(self):
        self.boundary_failure = True
        with self.assertRaisesRegex(ValueError, "dependency boundary"):
            self.qualify()
        self.assertFalse(any("test" in command for command in self.commands))
        self.assertFalse(self.live)

    def test_zero_executed_tests_fail_and_keep_private_logs_without_retry(self):
        self.zero_tests = True
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.qualify()
        self.assertEqual(len(self.live), 1)
        self.assertEqual((Path(self.live[0][2]) / "node.log").read_text(), "sensitive runtime data")
        result = json.loads(next(self.base.glob("orbis-native-*/manifest.json")).read_text())
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["retained_log_sha256"])

    def test_live_process_failure_is_not_retried_or_streamed(self):
        self.nonzero = True
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), self.assertRaisesRegex(ValueError, "command failed"):
            self.qualify()
        self.assertEqual(len(self.live), 1)
        self.assertNotIn("sensitive runtime data", captured.getvalue())
        result = json.loads(next(self.base.glob("orbis-native-*/manifest.json")).read_text())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["steps"][-1]["exit_code"], 101)
        self.assertTrue(result["retained_log_sha256"])

    def test_missing_pet_phase_fails_before_ordinary_scenario(self):
        self.missing_phase = True
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.qualify()
        self.assertEqual(len(self.live), 1)

    def test_replacement_requires_exact_completion_marker_even_when_test_passes(self):
        for marker in ("", driver.PET_MEMBER_REPLACEMENT_PHASE + " private suffix",
                       driver.PET_MEMBER_REPLACEMENT_PHASE.replace("incoming-required=true", "incoming-required=false")):
            self.replacement_phase = marker
            before = len(self.live)
            captured = io.StringIO()
            with self.subTest(marker=marker), contextlib.redirect_stdout(captured):
                with self.assertRaisesRegex(ValueError, "member replacement evidence is incomplete"):
                    self.qualify()
            self.assertEqual(len(self.live) - before, 3)
            self.assertEqual(self.live[-1][0], "native_pet_member_replacement")
            summary_line = next(line for line in captured.getvalue().splitlines()
                                if line.startswith("Native lifecycle failure summary: "))
            summary = json.loads(summary_line.split(": ", 1)[1])
            self.assertEqual(summary["scenario"], "native_pet_member_replacement")
            self.assertFalse(summary["pet_member_replacement_complete"])
            self.assertNotIn("private suffix", captured.getvalue())

    def test_source_change_stops_the_run(self):
        self.mutate_source = True
        with self.assertRaisesRegex(ValueError, "Source changed"):
            self.qualify()
        self.assertEqual(len(self.live), 1)

    def test_pin_mismatch_and_invalid_curve_fail_before_commands(self):
        with self.assertRaisesRegex(ValueError, "Unknown native curve"):
            self.qualify("unsupported")
        path = self.root / driver.MANIFESTS[0]
        path.write_text(path.read_text().replace("a" * 40, "c" * 40))
        with self.assertRaisesRegex(ValueError, "revisions disagree"):
            self.qualify()
        self.assertFalse(self.commands)

    def test_profiling_kdf_and_deadline_overrides_are_removed(self):
        overrides = {"CARGO_PROFILE_RELEASE_OPT_LEVEL": "0", "RUSTFLAGS": "-C opt-level=0",
                     "ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB": "8", "ORBIS_LOCAL_STORAGE_KDF_T_COST": "1",
                     "VERA_E2E_DEADLINE_SCALE": "8", "CARGO_BUILD_RUSTC_WRAPPER": "wrapper"}
        with patch.dict(os.environ, overrides):
            env = driver.environment(self.base / "target")
        for key in overrides:
            self.assertNotIn(key, env)
        self.assertEqual(env["VERA_E2E_KEEP"], "1")


class FailureSummaryTests(unittest.TestCase):
    def summarize(self, text, **kwargs):
        arguments = dict(curve="jubjub", step="scenarios/native_pet_threshold_workflows/attempt-1/command",
                         exit_code=101, elapsed_seconds=1.234, lines=text.splitlines(), source_root=Path("/checkout"))
        arguments.update(kwargs)
        return driver.failure_summary(**arguments)

    def test_failed_footer_phases_and_known_location_with_ansi(self):
        text = "\x1b[31mthread 'secret actor' panicked at /checkout/bin/orbis-node/tests/support/native_pet.rs:123:45:\x1b[0m\n"
        text += "assertion `secret key == private state` failed\nElapsed(())\n"
        text += "\n".join(driver.PET_PHASES[:2]) + "\n"
        text += "test result: FAILED. 0 passed; 1 failed; 0 ignored; private trailer\n"
        result = self.summarize(text)
        self.assertEqual(result["tests"], {"passed": 0, "failed": 1, "ignored": 0})
        self.assertEqual(result["pet_phase_bits"], 3)
        self.assertEqual(result["panic_headers"], 1)
        self.assertEqual(result["assertion_markers"], 1)
        self.assertEqual(result["elapsed_markers"], 1)
        self.assertEqual(result["fixture_locations"], [{"file_id": "pet", "line": 123, "column": 45}])
        for private in ("secret", "private", "/checkout", "native_pet.rs", "\x1b"):
            self.assertNotIn(private, json.dumps(result))

    def test_replacement_marker_and_location_preserve_existing_pet_bits(self):
        text = "\n".join(driver.PET_PHASES) + "\n" + driver.PET_MEMBER_REPLACEMENT_PHASE + "\n"
        text += "thread 'secret actor' panicked at /checkout/bin/orbis-node/tests/support/native_pet/member_replacement.rs:42:7:\n"
        result = self.summarize(text, step="scenarios/native_pet_member_replacement/attempt-1/command")
        self.assertEqual(result["stage"], "live")
        self.assertEqual(result["scenario"], "native_pet_member_replacement")
        self.assertEqual(result["pet_phase_bits"], 15)
        self.assertTrue(result["pet_member_replacement_complete"])
        self.assertEqual(result["fixture_locations"], [{"file_id": "pet_replacement", "line": 42, "column": 7}])
        self.assertFalse(self.summarize(driver.PET_MEMBER_REPLACEMENT_PHASE + " private suffix")
                         ["pet_member_replacement_complete"])
        for private in ("secret", "/checkout", "member_replacement.rs"):
            self.assertNotIn(private, json.dumps(result))

    def test_json_diagnostic_fields_cannot_smuggle_messages_paths_or_codes(self):
        events = []
        for code in ("E0308", "E0308/private-secret", "\x1b[31mE9999", "clippy::secret", ["E0100"]):
            events.append(json.dumps({"reason": "compiler-message", "message": {
                "level": "error", "code": {"code": code}, "message": "private secret",
                "rendered": "thread 'secret' panicked at /private/file:1:2: Elapsed(())",
                "spans": [{"file_name": "/private/secret", "text": ["key material"]}]}}))
        events.append(json.dumps({"reason": "compiler-message", "message": {"level": "warning", "code": None}}))
        result = self.summarize("\n".join(events), step="build-orbis")
        self.assertEqual(result["compiler_errors"], 5)
        self.assertEqual(result["compiler_warnings"], 1)
        self.assertEqual(result["compiler_error_codes"], {"E0308": 1})
        self.assertEqual(result["panic_headers"], 0)
        self.assertEqual(result["elapsed_markers"], 0)
        for private in ("secret", "private", "material", "file_name", "rendered", "\x1b"):
            self.assertNotIn(private, json.dumps(result))

    def test_absent_ambiguous_and_oversized_counts_remain_unavailable(self):
        footer = "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
        for text in ("", footer * 2, footer.replace("1 passed", "1000000 passed")):
            self.assertIsNone(self.summarize(text)["tests"])
        self.assertEqual(self.summarize(footer * 2)["libtest_result_count"], 2)
        zero = self.summarize(footer.replace("1 passed", "0 passed"))
        self.assertEqual(zero["tests"]["passed"], 0)

    def test_malformed_or_nonobject_json_is_ignored_without_echo(self):
        lines = ['{"private secret":', '{"reason":"compiler-message","message":[]}',
                 '{"reason":"compiler-message","message":{"level":[],"code":{}}}',
                 'thread x panicked at /private/secret:19:20:']
        result = self.summarize("\n".join(lines))
        self.assertEqual(result["malformed_json_lines"], 1)
        self.assertEqual(result["compiler_errors"], 0)
        self.assertEqual(result["fixture_locations"], [])
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn("secret", json.dumps(result))

    def test_unknown_stage_is_fixed_driver_enum_and_numeric_context_is_bounded(self):
        result = self.summarize("", step="/private/secret", exit_code=None, elapsed_seconds=None)
        self.assertEqual(result["stage"], "driver")
        self.assertIsNone(result["scenario"])
        self.assertIsNone(result["exit_code"])
        self.assertNotIn("private", json.dumps(result))
        for changes in ({"curve": "secret"}, {"exit_code": True}, {"exit_code": 999999},
                        {"elapsed_seconds": float("nan")}, {"elapsed_seconds": float("inf")},
                        {"elapsed_seconds": -1}, {"elapsed_seconds": "secret"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.summarize("", **changes)

    def test_unknown_path_and_ansi_hyperlink_are_not_published(self):
        text = "\x1b]8;;https://private-secret/path\x07thread 'private actor' panicked at /other/bin/orbis-node/tests/support/native_pet.rs:3:4:\x1b]8;;\x07"
        result = self.summarize(text)
        self.assertEqual(result["panic_headers"], 1)
        self.assertEqual(result["fixture_locations"], [])
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn("https", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
