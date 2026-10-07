#!/usr/bin/env python3
"""Bounded diagnostic parser regressions; no compiler or containers."""
import json
from pathlib import Path
import tempfile
import unittest
import sys
sys.dont_write_bytecode = True
import native_lifecycle_summary as driver

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

    def test_fault_report_certification_marker_and_private_location(self):
        text = "native PET phase=fault-report accepted_height=73 replicas=4 accused_demerits=1 retained_sessions=1 bundles_unchanged=true\n"
        text += "thread 'secret actor' panicked at /checkout/bin/orbis-node/tests/support/native_pet/report_fault.rs:42:7:\n"
        result = self.summarize(text, step="scenarios/native_pet_fault_reports/attempt-1/command", exit_code=0)
        self.assertEqual(result["scenario"], "native_pet_fault_reports")
        self.assertTrue(result["pet_fault_report_complete"])
        self.assertEqual(result["pet_fault_report_height"], 73)
        self.assertEqual(result["fixture_locations"], [{"file_id": "pet_report", "line": 42, "column": 7}])
        driver.verify_outcome(result, "fault-report")
        with self.assertRaises(ValueError):
            driver.verify_outcome(result)
        for private in ("secret", "/checkout", "report_fault.rs"):
            self.assertNotIn(private, json.dumps(result))

    def test_fault_report_rejects_incomplete_duplicate_or_unbounded_markers(self):
        marker = "native PET phase=fault-report accepted_height=73 replicas=4 accused_demerits=1 retained_sessions=1 bundles_unchanged=true"
        invalid = ("", marker + " private suffix", marker + "\n" + marker,
                   marker.replace("replicas=4", "replicas=3"),
                   marker.replace("accused_demerits=1", "accused_demerits=0"),
                   marker.replace("retained_sessions=1", "retained_sessions=2"),
                   marker.replace("bundles_unchanged=true", "bundles_unchanged=false"))
        invalid += tuple(marker.replace("height=73", "height=" + value)
                         for value in ("0", "-1", str(2**64), "9" * 100))
        for text in invalid:
            with self.subTest(text=text):
                result = self.summarize(text, exit_code=0)
                self.assertFalse(result["pet_fault_report_complete"])
                self.assertIsNone(result["pet_fault_report_height"])
                with self.assertRaises(ValueError):
                    driver.verify_outcome(result, "fault-report")

    def test_fault_marker_cannot_replace_test_success_or_normal_lifecycle(self):
        marker = "native PET phase=fault-report accepted_height=73 replicas=4 accused_demerits=1 retained_sessions=1 bundles_unchanged=true"
        with self.assertRaises(ValueError):
            driver.verify_outcome(self.summarize(marker, exit_code=101), "fault-report")
        result = self.summarize("\n".join((*driver.PET_PHASES, driver.PET_MEMBER_REPLACEMENT_PHASE)), exit_code=0)
        driver.verify_outcome(result)
        with self.assertRaises(ValueError):
            driver.verify_outcome(result, "fault-report")


class SelectionTests(unittest.TestCase):
    def listing(self):
        return {"rust-suites": {"orbis-node::native_startup": {
            "binary-name": "native_startup", "testcases": {
                name: {"ignored": True, "filter-match": {"status": "matches"}}
                for name in driver.SCENARIOS}}}}

    def test_exact_ignored_scenarios_required(self):
        listing = self.listing()
        self.assertEqual(driver.verify_selection(listing), 3)
        cases = listing["rust-suites"]["orbis-node::native_startup"]["testcases"]
        cases[driver.SCENARIOS[0]]["filter-match"] = {"status": "mismatch", "reason": "ignored"}
        with self.assertRaises(ValueError):
            driver.verify_selection(listing)
        cases[driver.SCENARIOS[0]]["filter-match"] = {"status": "matches"}
        cases[driver.SCENARIOS[0]]["ignored"] = False
        with self.assertRaises(ValueError):
            driver.verify_selection(listing)

    def test_extra_cases_or_test_binaries_cannot_widen_the_run(self):
        listing = self.listing()
        cases = listing["rust-suites"]["orbis-node::native_startup"]["testcases"]
        cases["different_test"] = {"ignored": True, "filter-match": {"status": "matches"}}
        with self.assertRaises(ValueError):
            driver.verify_selection(listing)
        listing = self.listing()
        listing["rust-suites"]["different_binary"] = {"binary-name": "other", "testcases": {}}
        with self.assertRaises(ValueError):
            driver.verify_selection(listing)

    def test_fault_selection_requires_only_the_one_ignored_test(self):
        listing = self.listing()
        cases = listing["rust-suites"]["orbis-node::native_startup"]["testcases"]
        cases.clear()
        with self.assertRaises(ValueError):
            driver.verify_selection(listing, "fault-report")
        cases[driver.FAULT_SCENARIO] = {"ignored": True, "filter-match": {"status": "matches"}}
        self.assertEqual(driver.verify_selection(listing, "fault-report"), 1)
        with self.assertRaises(ValueError):
            driver.verify_selection(listing)
        cases[driver.SCENARIOS[0]] = {"ignored": True, "filter-match": {"status": "matches"}}
        with self.assertRaises(ValueError):
            driver.verify_selection(listing, "fault-report")
        del cases[driver.SCENARIOS[0]]
        cases[driver.FAULT_SCENARIO]["ignored"] = False
        with self.assertRaises(ValueError):
            driver.verify_selection(listing, "fault-report")


class RevisionTests(unittest.TestCase):
    def test_every_sdk_manifest_must_agree_before_building_the_image(self):
        import runpy
        module = runpy.run_path(str(Path(__file__).with_name("native-vera-ref.py")))
        revision, manifests = module["revision"], module["MANIFESTS"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in manifests:
                manifest = root / name
                manifest.parent.mkdir(parents=True, exist_ok=True)
                manifest.write_text('vera-client = { git = "https://github.com/sourcenetwork/vera.rs", rev = "' + "a" * 40 + '" }\n')
            self.assertEqual(revision(root), "a" * 40)
            last = root / manifests[-1]
            original = last.read_text()
            for changed in (original.replace("a" * 40, "b" * 40),
                            original.replace("a" * 40, "develop"), ""):
                last.write_text(changed)
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    revision(root)


if __name__ == "__main__":
    unittest.main()
