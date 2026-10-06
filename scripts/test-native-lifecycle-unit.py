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
        self.mutate_source = False
        self.nonzero = False

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
            binary = command[-1]
            (release / binary).write_text("normal " + binary)
            (release / binary).chmod(0o700)
        elif "tree" in command:
            output = "cosmos-sdk-proto v0.1.0\n" if self.boundary_failure else "orbis-node v0.0.1\n"
        elif command[:3] == ["cargo", "+1.98.0", "test"]:
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
            count = 0 if self.zero_tests else 1
            output += f"test result: ok. {count} passed; 0 failed; 0 ignored; finished in 0.01s\n"
            if self.mutate_source:
                (self.root / "Cargo.lock").write_text("changed lock")
        stdout.write(output)
        return subprocess.CompletedProcess(command, 101 if self.nonzero and command[0].endswith("native_startup") else 0)

    def qualify(self, curve="bls12-381"):
        with patch.object(driver, "snapshot", side_effect=self.snapshot), patch.object(driver.subprocess, "run", side_effect=self.command):
            return driver.qualify(self.root, curve, self.base)

    def test_both_curves_stage_normal_binaries_and_run_only_two_exact_scenarios(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            outputs = [self.qualify(curve) for curve in driver.CURVES]
        self.assertEqual([entry[0] for entry in self.live], list(driver.SCENARIOS) * 2)
        self.assertEqual(len({entry[1] for entry in self.live}), 4)
        self.assertEqual(len({entry[2] for entry in self.live}), 4)
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


if __name__ == "__main__":
    unittest.main()
