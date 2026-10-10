import json
import runpy
import copy
from pathlib import Path
import unittest

namespace = runpy.run_path(str(Path(__file__).with_name('qualify-native-restart.py')))
verify = namespace['verify_fixture_changes']
soak_result = namespace['soak_result']
polynomial_result = namespace['polynomial_result']
verified_image_id = namespace['verified_image_id']


class RuntimeImages(unittest.TestCase):
    def image(self, curve, diagnostic=False):
        labels = {
            'org.opencontainers.image.revision': namespace['RUNTIME'],
            'io.sourcenetwork.orbis.backend': 'native',
            'io.sourcenetwork.orbis.curve': curve,
            'io.sourcenetwork.orbis.integration-features': 'false',
        }
        variable = 'ORBIS_NATIVE_IMAGE'
        digests = namespace['RUNTIME_DIGESTS']
        if diagnostic:
            variable = 'ORBIS_NATIVE_DIAGNOSTIC_IMAGE'
            digests = namespace['DIAGNOSTIC_DIGESTS']
            labels['io.sourcenetwork.orbis.unsafe-testing'] = 'true'
        image = 'ghcr.io/sourcenetwork/orbis-rs/node-integration@' + digests[curve]
        return variable, image, {
            'Id': 'sha256:' + 'a' * 64, 'RepoDigests': [image],
            'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': labels},
        }

    def test_matching_normal_diagnostic_and_vera_images_are_accepted(self):
        for curve in ('bls12-381', 'jubjub'):
            for diagnostic in (False, True):
                variable, image, info = self.image(curve, diagnostic)
                self.assertEqual(verified_image_id(info, variable, image, curve), info['Id'])
            image = 'ghcr.io/sourcenetwork/orbis-rs/vera-native@' + namespace['VERA_DIGEST']
            info = dict(Id='sha256:' + 'b' * 64, RepoDigests=[image], Os='linux',
                        Architecture='amd64',
                        Config={'Labels': {'org.opencontainers.image.revision': namespace['VERA']}})
            self.assertEqual(verified_image_id(info, 'ORBIS_NATIVE_VERA_IMAGE', image, curve), info['Id'])

    def test_wrong_source_curve_features_or_diagnostic_mode_are_rejected(self):
        for curve in ('bls12-381', 'jubjub'):
            for diagnostic in (False, True):
                variable, image, info = self.image(curve, diagnostic)
                for label in info['Config']['Labels']:
                    changed = copy.deepcopy(info)
                    changed['Config']['Labels'][label] = 'wrong'
                    with self.subTest(curve=curve, diagnostic=diagnostic, label=label):
                        with self.assertRaisesRegex(ValueError, 'labels do not match'):
                            verified_image_id(changed, variable, image, curve)
            wrong_curve = 'jubjub' if curve == 'bls12-381' else 'bls12-381'
            with self.assertRaisesRegex(ValueError, 'labels do not match'):
                verified_image_id(info, variable, image, wrong_curve)

    def test_missing_digest_wrong_platform_and_invalid_id_are_rejected(self):
        variable, image, info = self.image('bls12-381', diagnostic=True)
        for field, value in [('RepoDigests', []), ('Os', 'windows'),
                             ('Architecture', 'arm64'), ('Id', 'orbis:latest')]:
            changed = dict(info, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                verified_image_id(changed, variable, image, 'bls12-381')
        with self.assertRaisesRegex(ValueError, 'unsupported runtime image'):
            verified_image_id(info, 'UNKNOWN_IMAGE', image, 'bls12-381')


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
        for overrides in [dict(cycles=0), dict(cycles=True), dict(cycles=1801),
                          dict(active_seconds=899), dict(active_seconds=1801),
                          dict(restarts=2), dict(restarts=4), dict(private_key='secret')]:
            result = dict(cycles=120, active_seconds=901, restarts=3)
            result.update(overrides)
            with self.subTest(fields=overrides):
                self.assertIsNone(soak_result('native_threshold_soak=' + json.dumps(result)))


class PolynomialSummary(unittest.TestCase):
    def record(self):
        response = dict(status=0, present=True, changed=False, matches_first=False)
        return dict(members=1, previous=True,
                    responses=[dict(connected=True, main=response.copy(), pet=response.copy())])

    def decode(self, record):
        return polynomial_result('native_polynomial_state=' + json.dumps(record))

    def test_known_numeric_state_is_preserved(self):
        record = self.record()
        self.assertEqual(self.decode(record), record)
        record['responses'][0]['main'] = dict(status=5, present=None, changed=None, matches_first=None)
        self.assertEqual(self.decode(record), record)

    def test_private_fields_and_invalid_types_are_rejected(self):
        for field, value in [('status', True), ('status', 17), ('present', 'private-polynomial'),
                             ('changed', 1), ('polynomial', 'private-polynomial')]:
            record = self.record()
            record['responses'][0]['main'][field] = value
            with self.subTest(field=field, value=value):
                self.assertIsNone(self.decode(record))

    def test_incomplete_ambiguous_or_inconsistent_state_is_rejected(self):
        for overrides in [dict(members=True), dict(members=5), dict(members=2),
                          dict(previous=False), dict(responses=[]), dict(extra='private')]:
            record = self.record()
            record.update(overrides)
            with self.subTest(fields=overrides):
                self.assertIsNone(self.decode(record))
        record = self.record()
        record['responses'][0]['main']['status'] = 5
        self.assertIsNone(self.decode(record))
        record = self.record()
        record['responses'][0]['connected'] = False
        self.assertIsNone(self.decode(record))
        text = 'native_polynomial_state=' + json.dumps(self.record())
        for content in ['', text + '\n' + text, 'native_polynomial_state={broken}']:
            self.assertIsNone(polynomial_result(content))


if __name__ == '__main__':
    unittest.main()
