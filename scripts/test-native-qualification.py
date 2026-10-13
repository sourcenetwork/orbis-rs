import copy
import json
import os
import runpy
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

namespace = runpy.run_path(str(Path(__file__).with_name('qualify-native-restart.py')))
verify = namespace['verify_fixture_changes']
soak_result = namespace['soak_result']
churn_result = namespace['churn_result']
polynomial_result = namespace['polynomial_result']
verified_image_id = namespace['verified_image_id']
verified_fixture_source = namespace['verified_fixture_source']
build_vera_image = namespace['build_vera_image']


class FixtureSource(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.previous = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(os.chdir, self.previous)
        self.git('init', '--quiet')
        self.git('config', 'diff.renames', 'true')
        self.production = Path('bin/orbis-node/src/node.rs')
        self.fixture = Path('bin/orbis-node/tests/native_startup.rs')
        self.production.parent.mkdir(parents=True)
        self.production.write_text('original production source\n' * 100)
        self.commit()
        self.runtime = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(
            ['git', '-c', 'user.name=iverc', '-c', 'user.email=ivanverch@gmail.com', *args],
            text=True, stderr=subprocess.DEVNULL).strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'Record fixture source')

    def test_committed_fixture_change_returns_exact_source(self):
        self.fixture.parent.mkdir(parents=True)
        self.fixture.write_text('new fixture\n')
        self.commit()
        self.assertEqual(verified_fixture_source(self.runtime), {
            'head': self.git('rev-parse', 'HEAD'), 'tree': self.git('rev-parse', 'HEAD^{tree}')})

    def test_production_change_is_rejected(self):
        self.production.write_text('changed production source\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'runtime source differs'):
            verified_fixture_source(self.runtime)

    def test_separate_transport_test_module_preserves_runtime_source(self):
        test_module = self.production.parent / 'sign/v0/coordinator/network_tests.rs'
        test_module.parent.mkdir(parents=True)
        test_module.write_text('test-only transport regression\n')
        self.commit()
        self.assertEqual(verified_fixture_source(self.runtime)['head'],
                         self.git('rev-parse', 'HEAD'))
        self.production.write_text('changed production source\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'runtime source differs'):
            verified_fixture_source(self.runtime)

    def test_production_rename_cannot_hide_in_an_approved_fixture_path(self):
        self.fixture.parent.mkdir(parents=True)
        self.production.rename(self.fixture)
        self.commit()
        self.assertEqual(self.git('diff', '--name-only', self.runtime, 'HEAD'), str(self.fixture))
        with self.assertRaisesRegex(ValueError, 'runtime source differs'):
            verified_fixture_source(self.runtime)

    def test_dirty_tracked_source_is_rejected(self):
        self.production.write_text('uncommitted production source\n')
        with self.assertRaisesRegex(ValueError, 'unchanged tracked source'):
            verified_fixture_source(self.runtime)


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
            image = 'sha256:' + 'b' * 64
            info = dict(Id=image, RepoDigests=[], Os='linux',
                        Architecture='amd64',
                        Config={'Labels': {'org.opencontainers.image.revision': namespace['VERA']}})
            self.assertEqual(verified_image_id(info, 'ORBIS_NATIVE_VERA_IMAGE', image, curve), info['Id'])

    def test_private_vera_requires_exact_identity_source_and_platform(self):
        image = 'sha256:' + 'b' * 64
        info = dict(Id=image, RepoDigests=[], Os='linux', Architecture='amd64',
                    Config={'Labels': {'org.opencontainers.image.revision': namespace['VERA']}})
        for changes in ({'Id': 'sha256:' + 'c' * 64}, {'Os': 'windows'},
                        {'Architecture': 'arm64'}, {'Config': None},
                        {'Config': {'Labels': {'org.opencontainers.image.revision': 'd' * 40}}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verified_image_id({**info, **changes}, 'ORBIS_NATIVE_VERA_IMAGE', image, 'bls12-381')

    def test_private_vera_build_binds_source_before_returning_image_id(self):
        image = 'sha256:' + 'b' * 64
        info = dict(Id=image, RepoDigests=[], Os='linux', Architecture='amd64',
                    Config={'Labels': {'org.opencontainers.image.revision': namespace['VERA']}})
        capture = Mock(return_value=json.dumps([info]))
        with tempfile.TemporaryDirectory() as directory:
            with patch('subprocess.run') as run, patch.dict(build_vera_image.__globals__, {'capture': capture}):
                self.assertEqual(build_vera_image(Path(directory), {}, 'jubjub'), image)
                run.assert_called_once()
                command = run.call_args.args[0]
                self.assertIn('--load', command)
                self.assertNotIn('--push', command)
                self.assertEqual(command[command.index('--build-arg') + 1], 'VERA_REF=' + namespace['VERA'])
                self.assertEqual(command[command.index('--platform') + 1], 'linux/amd64')
                self.assertTrue(run.call_args.kwargs['check'])
                self.assertEqual(run.call_args.kwargs['timeout'], 5400)
                capture.assert_called_once_with(['docker', 'image', 'inspect', 'vera-native-qualification:' + namespace['VERA']])

    def test_private_vera_build_rejects_ambiguous_or_mismatched_inspection(self):
        info = dict(Id='sha256:' + 'b' * 64, Os='linux', Architecture='amd64',
                    Config={'Labels': {'org.opencontainers.image.revision': namespace['VERA']}})
        records = [{}, [], [info, info], [None], [{**info, 'Id': 'mutable:latest'}],
                   [{**info, 'Config': {'Labels': {'org.opencontainers.image.revision': 'c' * 40}}}]]
        for record in records:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as directory:
                with patch('subprocess.run'), patch.dict(build_vera_image.__globals__, {'capture': lambda _: json.dumps(record)}):
                    with self.assertRaises(ValueError):
                        build_vera_image(Path(directory), {}, 'bls12-381')

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

    def test_normal_runtime_rejects_diagnostic_features(self):
        for curve in ('bls12-381', 'jubjub'):
            variable, image, info = self.image(curve)
            for value in ('true', '', 'unknown'):
                info['Config']['Labels']['io.sourcenetwork.orbis.unsafe-testing'] = value
                with self.subTest(curve=curve, value=value), self.assertRaisesRegex(ValueError, 'diagnostic features'):
                    verified_image_id(info, variable, image, curve)
            info['Config']['Labels']['io.sourcenetwork.orbis.unsafe-testing'] = 'false'
            self.assertEqual(verified_image_id(info, variable, image, curve), info['Id'])

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


class ChurnResult(unittest.TestCase):
    def test_complete_churn_is_retained(self):
        record = {'changes': 5, 'reentries': 4, 'crash_restarts': 10}
        self.assertEqual(churn_result('native_threshold_churn=' + json.dumps(record)), record)

    def test_partial_or_private_results_are_rejected(self):
        for update in ({'changes': 4}, {'reentries': 3}, {'crash_restarts': 9},
                       {'changes': 5.0}, {'reentries': True}, {'private_key': 'private'}):
            record = {'changes': 5, 'reentries': 4, 'crash_restarts': 10}
            record.update(update)
            with self.subTest(fields=update):
                self.assertIsNone(churn_result('native_threshold_churn=' + json.dumps(record)))

    def test_missing_malformed_or_duplicate_completion_is_rejected(self):
        valid = 'native_threshold_churn={"changes":5,"reentries":4,"crash_restarts":10}'
        for tail in ('', 'native_threshold_churn={broken}', valid + '\n' + valid):
            with self.subTest(tail=tail):
                self.assertIsNone(churn_result(tail))

    def test_churn_failure_retains_location_without_private_message(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'junit.xml'
            report.write_text('<testsuite><testcase name="native_pet_member_churn" time="3">'
                              '<failure>panicked at bin/orbis-node/tests/support/native_pet/member_churn.rs:42:17: '
                              'private-value</failure></testcase></testsuite>')
            result = namespace['lifecycle_results'](report, ['native_pet_member_churn'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['cases'][0]['locations'], [
            {'source': 'support/native_pet/member_churn.rs', 'line': 42, 'column': 17}])
        self.assertNotIn('private-value', json.dumps(result))

    def test_shared_helper_failure_retains_only_known_source_and_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'junit.xml'
            report.write_text('<testsuite><testcase name="native_pet_member_churn" time="3">'
                              '<failure>native PET phase=paired-dkg private-key=private-value\n'
                              'native PET phase=member-replacement-restart\n'
                              'native PET phase=/private/secret\n'
                              'panicked at tests/support/native_pet/signing.rs:97:62: private-value\n'
                              'tests/support/pre_scenario.rs:14:3 private-value'
                              '</failure></testcase></testsuite>')
            result = namespace['lifecycle_results'](report, ['native_pet_member_churn'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['cases'][0]['pet_phase'], 'member-replacement-restart')
        self.assertEqual(result['cases'][0]['locations'], [
            {'source': 'support/native_pet/signing.rs', 'line': 97, 'column': 62},
            {'source': 'support/pre_scenario.rs', 'line': 14, 'column': 3}])
        for private in ('private-value', 'private-key', '/private/secret'):
            self.assertNotIn(private, json.dumps(result))

    def test_rpc_failure_exports_closed_codes_and_error_classes(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'junit.xml'
            report.write_text('<testsuite><testcase name="native_pet_member_churn" time="3">'
                              '<failure>panicked at tests/support/native_pet/signing.rs:95:65: '
                              'Status { code: DeadlineExceeded, message: "Timeout waiting for responses: private-value" }\n'
                              'Status { code: PrivateUnknown, message: "private-value" }\n'
                              'Status { code: Unavailable, message: "Ring reshare in progress, try again shortly" }'
                              '</failure></testcase></testsuite>')
            result = namespace['lifecycle_results'](report, ['native_pet_member_churn'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['cases'][0]['rpc_codes'], ['DeadlineExceeded', 'Unavailable'])
        self.assertEqual(result['cases'][0]['sign_error_classes'], ['reshare_in_progress', 'response_timeout'])
        for private in ('private-value', 'PrivateUnknown'):
            self.assertNotIn(private, json.dumps(result))


class SigningRestartDiagnostics(unittest.TestCase):
    def collect(self, directory):
        return namespace['signing_restart_diagnostics'](directory)

    def test_restart_events_are_numeric_and_private_fields_are_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for member in (2, 3):
                parent = root / 'orbis-native-1-fixture' / f'node-{member}'
                parent.mkdir(parents=True)
                (parent / 'pet-replacement-restart.log').write_text(
                    'private-key jwt request-id node-key\n'
                    'Sign Coordinator: Received NonceRequest\n'
                    'Sign peer request failed error=private-response\n'
                    'No nonce state found for request_id private-request\n')
            result = self.collect(root)
            self.assertTrue(result['available'])
            for member in result['members']:
                self.assertEqual(member['counters']['nonce_requests'], 1)
                self.assertEqual(member['counters']['sign_peer_errors'], 1)
                self.assertEqual(member['counters']['missing_nonce'], 1)
                self.assertEqual(member['counters']['signatures_recovered'], 0)
            self.assertNotIn('private', json.dumps(result))
            self.assertNotIn(str(root), json.dumps(result))

    def test_log_tail_is_bounded_and_truncation_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'orbis-native-1-fixture' / 'node-2'
            parent.mkdir(parents=True)
            (parent / 'pet-replacement-restart.log').write_bytes(
                b'Sign Coordinator: Received NonceRequest\n' + b'x' * (1024 * 1024) +
                b'\nSign Coordinator: Local signing failed\n')
            result = self.collect(root)
            self.assertFalse(result['available'])
            self.assertTrue(result['members'][0]['tail_truncated'])
            self.assertEqual(result['members'][0]['counters']['nonce_requests'], 0)
            self.assertEqual(result['members'][0]['counters']['local_signing_errors'], 1)

    def test_symlinks_and_missing_or_ambiguous_fixtures_are_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(self.collect(root), {'available': False, 'members': []})
            parent = root / 'orbis-native-1-fixture' / 'node-2'
            parent.mkdir(parents=True)
            private = root / 'private'
            private.write_text('Sign Coordinator: Local signing failed\n')
            (parent / 'pet-replacement-restart.log').symlink_to(private)
            result = self.collect(root)
            self.assertFalse(result['members'][0]['log_available'])
            (root / 'orbis-native-2-fixture').mkdir()
            self.assertEqual(self.collect(root), {'available': False, 'members': []})


    def test_churn_promotion_events_use_all_four_fixed_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for member in range(4):
                parent = root / 'orbis-native-1-fixture' / f'node-{member}'
                parent.mkdir(parents=True)
                (parent / 'churn-diagnostic.log').write_text(
                    'Reshare: promoted staged bundle after chain confirmation secret=private-value\n'
                    'Reshare: local PET promotion not ready ring=private-key\n')
            result = namespace['signing_restart_diagnostics'](
                root, 'churn-diagnostic.log', tuple(range(4)))
            self.assertTrue(result['available'])
            self.assertEqual([member['member'] for member in result['members']], [0, 1, 2, 3])
            for member in result['members']:
                self.assertEqual(member['counters']['main_promotions'], 1)
                self.assertEqual(member['counters']['local_pet_not_ready'], 1)
            self.assertNotIn('private', json.dumps(result))
            self.assertNotIn(str(root), json.dumps(result))
            with self.assertRaises(ValueError):
                namespace['signing_restart_diagnostics'](root, '../private-key')

    def test_last_phase_distinguishes_churn_from_completed_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'junit.xml'
            report.write_text('<testsuite><testcase name="native_pet_member_churn" time="3">'
                              '<failure>native PET phase=member-replacement-restart\n'
                              'native PET phase=churn-round-start round=1\n'
                              'native PET phase=churn-finalized round=1\n'
                              'native PET phase=/private/key round=123\n'
                              'panicked at tests/support/native_pet.rs:646:9: private-value'
                              '</failure></testcase></testsuite>')
            result = namespace['lifecycle_results'](report, ['native_pet_member_churn'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['cases'][0]['pet_phase'], 'churn-finalized')
        self.assertEqual(result['cases'][0]['churn_round'], 1)
        self.assertNotIn('private', json.dumps(result))


    def test_peer_rejection_counts_and_configuration_omit_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'orbis-native-1-fixture' / 'node-0'
            parent.mkdir(parents=True)
            (parent / 'churn-diagnostic.log').write_text(
                'Sign Coordinator: nonce response node_id does not match authenticated peer private=private-value\n'
                'Sign Coordinator: Failed to verify share signature=private-key\n'
                'Sign Coordinator: Initiating signing peer_count=99999 threshold=2 self_in_list=true interactive=true\n'
                'Sign Coordinator: Initiating signing peer_count=2 threshold=2 '
                'self_in_list=\x1b[32mtrue\x1b[0m interactive=true request_id=private-value\n')
            result = namespace['signing_restart_diagnostics'](root, 'churn-diagnostic.log', (0,))
        member = result['members'][0]
        self.assertEqual(member['counters']['peer_nonce_id_mismatches'], 1)
        self.assertEqual(member['counters']['peer_signature_verification_errors'], 1)
        self.assertEqual(member['last_signing_configuration'],
                         {'peer_count': 2, 'threshold': 2, 'self_in_list': True, 'interactive': True})
        self.assertNotIn('private', json.dumps(result))
        self.assertNotIn('99999', json.dumps(result))

    def test_failed_signing_exports_only_bounded_member_cycle_and_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'junit.xml'
            report.write_text('<testsuite><testcase name="native_pet_member_churn" time="3">'
                              '<failure>native_churn_sign member=0 cycle=110\n'
                              'native_churn_sign member=99 cycle=99999\n'
                              'Status { code: FailedPrecondition, message: "Insufficient shares: got 1, need 2" }'
                              '</failure></testcase></testsuite>')
            result = namespace['lifecycle_results'](report, ['native_pet_member_churn'])
        case = result['cases'][0]
        self.assertEqual(case['churn_signing'], {'member': 0, 'cycle': 110})
        self.assertEqual(case['insufficient_shares'], {'got': 1, 'need': 2})
        self.assertNotIn('99999', json.dumps(result))


    def test_transport_errors_are_correlated_to_private_request_and_peer(self):
        peers = {'a' * 64: 0, 'b' * 64: 2}
        tail = ('Sign Coordinator: Initiating signing request_id=private-request peer_count=2 '
                'threshold=2 self_in_list=true interactive=true\n'
                'Nonce peer request failed request_id=private-request peer_id=' + 'a' * 64 +
                ' error=Network communication error: private-key timed out\n'
                'Nonce peer request failed request_id=unknown-private peer_id=' + 'b' * 64 + '\n'
                'Sign Coordinator: Initiating signing request_id=private-report peer_count=1 '
                'threshold=2 self_in_list=true interactive=true\n'
                'Sign Coordinator: Successfully recovered signature request_id=private-report\n')
        attempts = namespace['signing_attempts'](tail, peers)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0]['peer_errors'],
                         [{'phase': 'nonce', 'member': 0, 'class': 'communication', 'transport_phase': None, 'timed_out': True}])
        self.assertFalse(attempts[0]['recovered'])
        self.assertTrue(attempts[1]['recovered'])
        self.assertNotIn('private', json.dumps(attempts))
        self.assertNotIn('a' * 64, json.dumps(attempts))

    def test_transport_timeout_exports_only_the_known_exchange_phase(self):
        peers = {'a' * 64: 0}
        for phase in ('connecting', 'opening', 'sending', 'receiving', 'validating', 'private-key'):
            with self.subTest(phase=phase):
                tail = ('Sign Coordinator: Initiating signing request_id=private-request peer_count=2 '
                        'threshold=2 self_in_list=true interactive=true\n'
                        'Nonce peer request failed request_id=private-request peer_id=' + 'a' * 64 +
                        ' error=Timeout waiting for responses: Peer exchange timed out while ' + phase +
                        ' for private-peer\n')
                attempts = namespace['signing_attempts'](tail, peers)
                error = attempts[0]['peer_errors'][0]
                self.assertEqual(error['transport_phase'], None if phase == 'private-key' else phase)
                self.assertNotIn('private', json.dumps(attempts))
                self.assertNotIn('a' * 64, json.dumps(attempts))

    def test_transport_route_exports_reachability_facts_without_addresses(self):
        peers = {'a' * 64: 0, 'd' * 64: 3}
        receiver = 'a' * 64 + '@172.20.0.2:9001'
        sender = 'd' * 64 + '@172.20.0.5:9001'
        log = 'Iroh peer route connection=' + receiver + '\n'
        self.assertEqual(namespace['observed_peer_routes'](log, peers), receiver)
        for suffix, present in (('', False), ('@172.20.0.2:9001', True)):
            tail = ('Sign Coordinator: Initiating signing request_id=private-request peer_count=2 '
                    'threshold=2 self_in_list=true interactive=true\n'
                    'Nonce peer request failed request_id=private-request peer_id=' + 'a' * 64 + suffix +
                    ' error=Timeout waiting for responses: Peer exchange timed out while connecting for private-peer\n')
            attempts = namespace['signing_attempts'](tail, peers, coordinator=3, routes={0: receiver, 3: sender})
            route = attempts[0]['peer_errors'][0]['route']
            self.assertEqual(route['address_present'], present)
            self.assertEqual(route['matches_observed_peer_route'], present)
            self.assertFalse(route['matches_coordinator_route'])
            encoded = json.dumps(attempts)
            for private in ('172.20.', '9001', 'a' * 64, 'd' * 64, 'private'):
                self.assertNotIn(private, encoded)

    def test_route_classification_distinguishes_loopback_wildcard_and_hostname(self):
        for address, kind, loopback, wildcard in (
                ('127.0.0.1:9001', 'ipv4', True, False),
                ('0.0.0.0:9001', 'ipv4', False, True),
                ('[::1]:9001', 'ipv6', True, False),
                ('orbis-node-0:9001', 'hostname', None, None)):
            result = namespace['transport_route_summary']('a' * 64 + '@' + address, None, None)
            self.assertEqual(result['address_kind'], kind)
            self.assertEqual(result['address_is_loopback'], loopback)
            self.assertEqual(result['address_is_unspecified'], wildcard)
            self.assertIsNone(result['matches_observed_peer_route'])
            self.assertNotIn(address, json.dumps(result))

    def test_nonce_delivery_is_correlated_across_members_without_exporting_ids(self):
        peers = {'a' * 64: 0, 'd' * 64: 3}
        receiver_log = ('Sign Coordinator: Received NonceRequest request_id=nonce-private-round '
                        'sender_peer=' + 'd' * 64 + '\n'
                        'Sign Coordinator: Received NonceRequest request_id=nonce-private-other '
                        'sender_peer=' + 'a' * 64 + '\n')
        received = namespace['received_nonce_requests'](receiver_log, peers)
        coordinator_log = ('Sign Coordinator: Initiating signing request_id=private-round peer_count=2 '
                           'threshold=2 self_in_list=true interactive=true\n'
                           'Nonce peer request failed request_id=private-round peer_id=' + 'a' * 64 +
                           ' error=Timeout waiting for responses: private-error\n')
        attempts = namespace['signing_attempts'](coordinator_log, peers, {0: received}, 3)
        self.assertTrue(attempts[0]['peer_errors'][0]['nonce_request_observed'])
        attempts = namespace['signing_attempts'](coordinator_log, peers, {0: received}, 0)
        self.assertFalse(attempts[0]['peer_errors'][0]['nonce_request_observed'])
        attempts = namespace['signing_attempts'](coordinator_log, peers, {}, 3)
        self.assertIsNone(attempts[0]['peer_errors'][0]['nonce_request_observed'])
        self.assertNotIn('private', json.dumps(attempts))
        self.assertNotIn('a' * 64, json.dumps(attempts))

    def test_failure_log_collection_links_coordinator_to_receiver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'orbis-native-1-fixture'
            (fixture / 'node-0').mkdir(parents=True)
            (fixture / 'node-3').mkdir()
            (fixture / 'diagnostic-peer-routes.json').write_text(
                json.dumps([character * 64 for character in 'abcd']))
            (fixture / 'node-0' / 'churn-diagnostic.log').write_text(
                'Sign Coordinator: Received NonceRequest request_id=nonce-private-round '
                'sender_peer=' + 'd' * 64 + '\n')
            (fixture / 'node-3' / 'churn-diagnostic.log').write_text(
                'Sign Coordinator: Initiating signing request_id=private-round peer_count=2 '
                'threshold=2 self_in_list=true interactive=true\n'
                'Nonce peer request failed request_id=private-round peer_id=' + 'a' * 64 +
                ' error=Timeout waiting for responses: private-error\n')
            result = namespace['signing_restart_diagnostics'](
                root, 'churn-diagnostic.log', tuple(range(4)))
        error = result['members'][3]['signing_attempts'][0]['peer_errors'][0]
        self.assertTrue(error['nonce_request_observed'])
        self.assertFalse(result['available'])
        self.assertNotIn('private', json.dumps(result))

    def test_nonce_delivery_rejects_unknown_senders_and_bounds_retained_events(self):
        peer = 'a' * 64
        tail = ('Sign Coordinator: Received NonceRequest request_id=nonce-private-unknown sender_peer=' +
                'b' * 64 + '\n' + ''.join(
                    'Sign Coordinator: Received NonceRequest request_id=nonce-private-' + str(index) +
                    ' sender_peer=' + peer + '\n' for index in range(300)))
        received = namespace['received_nonce_requests'](tail, {peer: 0})
        self.assertEqual(len(received), 256)
        self.assertNotIn(('private-unknown', 0), received)
        self.assertNotIn(('private-0', 0), received)
        self.assertIn(('private-299', 0), received)

    def test_private_peer_routes_are_bounded_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'diagnostic-peer-routes.json'
            path.write_text(json.dumps([character * 64 for character in 'abcd']))
            self.assertEqual(namespace['fixture_peer_indices'](root)['a' * 64], 0)
            path.write_bytes(b'x' * 4097)
            self.assertEqual(namespace['fixture_peer_indices'](root), {})
            path.unlink()
            private = root / 'private'
            private.write_text(json.dumps([character * 64 for character in 'abcd']))
            path.symlink_to(private)
            self.assertEqual(namespace['fixture_peer_indices'](root), {})

    def test_correlated_attempt_exports_are_bounded(self):
        tail = ''.join('Sign Coordinator: Initiating signing request_id=private-' + str(index) +
                       ' peer_count=2 threshold=2 self_in_list=true interactive=true\n'
                       for index in range(100))
        attempts = namespace['signing_attempts'](tail, {})
        self.assertEqual(len(attempts), 16)
        self.assertNotIn('private', json.dumps(attempts))


if __name__ == '__main__':
    unittest.main()
