import runpy
from pathlib import Path
import unittest

verify = runpy.run_path(str(Path(__file__).with_name('qualify-native-restart.py')))['verify_fixture_changes']
soak_result = runpy.run_path(str(Path(__file__).with_name('qualify-native-restart.py')))['soak_result']


class FixtureChanges(unittest.TestCase):
    def test_mirror_and_go_diagnostics_do_not_change_runtime(self):
        verify([
            '.github/actions/docker-builder/action.yml',
            '.github/workflows/upgrade-compatibility.yml',
            'bin/orbis-node/tests/support/native_trust_gateway/runner.rs',
            'bin/orbis-node/tests/support/native_trust_gateway/go_diagnostics.rs',
        ])

    def test_runtime_change_is_rejected_even_with_approved_fixtures(self):
        for path in ['bin/orbis-node/src/node.rs', 'crates/authz/src/lib.rs', 'Cargo.lock']:
            with self.subTest(path=path), self.assertRaisesRegex(
                    ValueError, '^runtime source differs from the selected images$'):
                verify(['scripts/qualify-native-restart.py', path])

    def test_unknown_workflow_or_fixture_is_not_implicitly_approved(self):
        for path in ['.github/actions/docker-builder/other.sh',
                     '.github/workflows/other.yml',
                     'bin/orbis-node/tests/support/native_trust_gateway/other.rs']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                verify([path])

    def test_similar_paths_do_not_bypass_exact_matching(self):
        path = 'bin/orbis-node/tests/support/native_trust_gateway/runner.rs'
        for changed in ['../' + path, './' + path, path + '.bak', path + '/../../src/node.rs']:
            with self.subTest(path=changed), self.assertRaises(ValueError):
                verify([changed])


class SoakSummary(unittest.TestCase):
    def test_completed_soak_has_only_bounded_numeric_evidence(self):
        result = soak_result('native_threshold_soak={"cycles":120,"active_seconds":901,"restarts":3}')
        self.assertEqual(result, dict(cycles=120, active_seconds=901, restarts=3))

    def test_missing_duplicate_or_malformed_evidence_is_rejected(self):
        good = 'native_threshold_soak={"cycles":120,"active_seconds":901,"restarts":3}'
        for text in ['', good + '\n' + good, 'native_threshold_soak={broken}']:
            with self.subTest(text=text):
                self.assertIsNone(soak_result(text))

    def test_incomplete_or_private_fields_cannot_be_published(self):
        import json
        for overrides in [dict(cycles=0), dict(cycles=True), dict(cycles=1801),
                          dict(active_seconds=899), dict(active_seconds=1801),
                          dict(restarts=2), dict(restarts=4), dict(private_key='secret')]:
            result = dict(cycles=120, active_seconds=901, restarts=3)
            result.update(overrides)
            with self.subTest(fields=overrides):
                self.assertIsNone(soak_result('native_threshold_soak=' + json.dumps(result)))


if __name__ == '__main__':
    unittest.main()
