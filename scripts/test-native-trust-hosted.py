#!/usr/bin/env python3
"""Offline guard/parser checks only; never invoke Cargo, Go or Docker."""
import contextlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('native_trust_hosted.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class Qualification(unittest.TestCase):
    def test_same_runtime_needs_no_source_exception(self):
        with patch.object(driver, 'capture') as capture:
            for requested in (None, 'a' * 40):
                self.assertEqual(driver.runtime_revision(Path('/root'), 'a' * 40, requested), 'a' * 40)
            capture.assert_not_called()

    def test_runtime_reuse_allows_only_exact_fixture_changes(self):
        root = Path(__file__).resolve().parents[1]
        fixture = 'bin/orbis-node/tests/support/native_trust_gateway/go_diagnostics.rs'
        with patch.object(driver, 'capture', return_value=fixture + '\n') as capture:
            self.assertEqual(driver.runtime_revision(root, 'a' * 40, 'b' * 40), 'b' * 40)
            self.assertEqual(capture.call_args.args[0], [
                'git', 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                '--name-only', 'b' * 40, 'a' * 40, '--'])
        for changed in ('bin/orbis-node/src/node.rs', 'Cargo.lock', 'docker/Dockerfile',
                        fixture + '.bak', '../' + fixture):
            with self.subTest(path=changed), patch.object(driver, 'capture', return_value=changed), \
                    self.assertRaises(ValueError):
                driver.runtime_revision(root, 'a' * 40, 'b' * 40)
        for requested in ('develop', 'A' * 40, 'b' * 39, '--help'):
            with self.subTest(revision=requested), self.assertRaises(driver.Failure):
                driver.runtime_revision(root, 'a' * 40, requested)

    def test_native_sdk_and_docker_use_the_same_vera_revision(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / 'docker/NATIVE_VERA_REF').read_text().strip(), driver.VERA)
        compose = (root / 'docker/docker-compose-native-integration-test.yml').read_text()
        defaults = re.findall(r'\$\{VERA_REF:-([0-9a-f]{40})\}', compose)
        self.assertEqual(defaults, [driver.VERA] * 4)
        declarations = []
        manifests = [root / 'Cargo.toml', *root.glob('bin/*/Cargo.toml'),
                     *root.glob('crates/*/Cargo.toml')]
        for manifest in manifests:
            for line in manifest.read_text().splitlines():
                if 'git = "https://github.com/sourcenetwork/vera.rs"' in line:
                    match = re.search(r'rev = "([0-9a-f]{40})"', line)
                    self.assertIsNotNone(match, str(manifest.relative_to(root)))
                    declarations.append(match.group(1))
        self.assertTrue(declarations)
        self.assertEqual(set(declarations), {driver.VERA})

    def test_gateway_matrix_does_not_reintroduce_cosmos_with_include(self):
        workflow = Path(__file__).resolve().parents[1].joinpath('.github/workflows/rust.yml').read_text()
        image = workflow.split('  image:\n', 1)[1].split('  # Compile every test binary', 1)[0]
        self.assertNotIn('        include:', image)
        curves = [value.strip() for value in re.search(r'        crypto: \[([^\]]+)\]', image).group(1).split(',')]
        backend_line = re.search(r'        backend: (.+)', image).group(1)
        choices = [json.loads(value) for value in re.findall(r"fromJSON\('([^']+)'\)", backend_line)]
        self.assertEqual({(curve, backend) for curve in curves for backend in choices[0]},
                         {('bls12-381', 'native'), ('jubjub', 'native')})
        self.assertEqual({(curve, backend) for curve in curves for backend in choices[1]},
                         {(curve, backend) for curve in ('bls12-381', 'jubjub') for backend in ('cosmos', 'native')})
        self.assertIn("if: matrix.backend == 'native' && inputs.scope != 'gateway'", image)

    def test_private_cwd_is_entered_only_after_identity_switch(self):
        parent, private = Path('/accessible/checkout'), Path('/private/owned-by-65532')
        def check(args, cwd, env, log, timeout):
            self.assertEqual(cwd, parent)
            self.assertNotEqual(cwd, private)
            self.assertEqual(args[:5], ['sudo', '--user', 'trust-native-ring', '--', 'env'])
            shell = args.index('/bin/sh')
            self.assertEqual(args[shell + 1], '-c')
            self.assertEqual(args[shell + 4], str(private))
            self.assertIn('cd "$1" || exit', args[shell + 2])
            self.assertEqual(timeout, 600)
        with patch.object(driver, 'command', side_effect=check) as execute:
            driver.launch_fixture(parent, private, {'PATH': '/usr/bin'}, {}, Path('/private/log'))
        self.assertEqual(execute.call_count, 1)

    def test_bounded_diagnostics_exclude_raw_messages_paths_and_ansi(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            event = {'reason': 'compiler-message', 'message': {'level': 'error',
                     'code': {'code': 'E0308'}, 'rendered': '\x1b[31msecret /private/key'}}
            invalid = {'reason': 'compiler-message', 'message': {'level': 'error', 'code': {'code': '/private/secret'}}}
            (root / 'compile.jsonl').write_text(json.dumps(event) + '\nmalformed\n' + json.dumps(invalid) + '\n[]\n')
            (root / 'executable.log').write_text("thread panicked at tests/support/native_trust_gateway.rs:123:4:\nsecret /private/key Elapsed\nthread panicked at /secret/file.rs:8:2:\n")
            result = driver.safe_diagnostics(root)
            self.assertEqual(result, {'compiler_errors': 2, 'compiler_codes': ['E0308'],
                                     'panics': 2, 'elapsed': 1, 'locations': [[1, 123]],
                                     'build': {'disk_full': 0, 'killed': 0, 'exit_codes': [],
                                               'rust_codes': [], 'go_locations': [],
                                               'buildkit_metadata': 0, 'gateway_archive': 0,
                                               'command_status': [], 'command_timeouts': 0,
                                               'failure_kinds': []}})
            encoded = json.dumps(result)
            for forbidden in ('secret', '/private', '/secret', '\x1b', 'rendered'):
                self.assertNotIn(forbidden, encoded)

    def test_requires_immutable_input(self):
        for value in ('main', 'a' * 39, 'A' * 40, 'a' * 40 + '\n', 'secret;$(command)'):
            with self.assertRaises(driver.Failure):
                driver.revision(value)
        self.assertEqual(driver.revision('a' * 40), 'a' * 40)

    def test_fixture_uses_read_only_test_sources_outside_production_context(self):
        command = driver.fixture_build_command(Path('/pinned/trust'), Path('/private/payload'))
        self.assertIn('type=bind,src=/pinned/trust,dst=/fixture,readonly', command)
        self.assertIn('type=bind,src=/private/payload/bin,dst=/out', command)
        self.assertEqual(command[command.index('trust-ring-builder:local') + 1:][:3], ['-C', '/fixture', 'test'])
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertIn('GOFLAGS=-mod=readonly -p=2', command)

    def test_build_diagnostics_exclude_commands_assertions_and_private_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'trust-build.log').write_text('private-key /private/keys error[E0308]\n'
                '#42 1.01 cmd/trust-api/api_server.go:323:18: private assertion\n'
                'no space left on device; signal: killed; exit code: 1\n'
                'exit code: 999999; cmd/trust-api/api_server.go:0:0: invalid\n')
            result = driver.build_diagnostics(root)
            self.assertEqual(result['disk_full'], 1)
            self.assertEqual(result['killed'], 1)
            self.assertEqual(result['exit_codes'], [1])
            self.assertEqual(result['rust_codes'], ['E0308'])
            self.assertEqual(result['go_locations'], [['api_server.go', 323, 18]])
            for forbidden in ('private-key', '/private', 'assertion', '999999'):
                self.assertNotIn(forbidden, json.dumps(result))

    def test_build_failure_classification_is_bounded_and_reports_command_status(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'trust-build.log').write_text('ERROR: failed to solve: failed to fetch /private/token\n'
                'connection reset by peer; ResourceExhausted; unknown revision private-ref\n'
                'additional privileges requested: fs.read=/private/context\n')
            with patch.object(driver, 'COMMANDS', [{'returncode': 1, 'timed_out': False},
                                                  {'returncode': -9, 'timed_out': True}]):
                result = driver.build_diagnostics(root)
            self.assertEqual(result['command_status'], [-9, 1])
            self.assertEqual(result['command_timeouts'], 1)
            self.assertEqual(result['failure_kinds'], ['docker_build', 'filesystem_entitlement', 'network', 'resources', 'source_revision'])
            for forbidden in ('/private', 'token', 'private-ref', 'connection reset'):
                self.assertNotIn(forbidden, json.dumps(result))

    def test_bake_context_is_checked_before_compiling_defra(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            trust = root / 'trust'
            trust.mkdir()
            output = root / 'output'
            output.mkdir()
            args = SimpleNamespace(trust=str(trust), vera=str(root / 'vera'), defra=str(root / 'defra'),
                                   trust_ref='a' * 40, image='ghcr.io/source/test:run', local_image=True)
            def reject(command, cwd, env, log, timeout):
                self.assertEqual(command[:3], ['docker', 'buildx', 'bake'])
                self.assertIn('--check', command)
                self.assertNotIn('--allow', command)
                self.assertEqual(cwd, trust.resolve())
                self.assertEqual(timeout, 300)
                self.assertEqual(log.name, 'trust-bake-check.log')
                graph = json.loads((output / 'bake.json').read_text())
                self.assertEqual(graph['target']['gateway']['context'], str(cwd))
                raise driver.Failure()
            with patch.object(driver, 'pins', return_value={}), \
                 patch.object(driver, 'capture', return_value='cargo 1.98.0 test'), \
                 patch.object(driver, 'command', side_effect=reject) as command:
                with self.assertRaises(driver.Failure):
                    driver.build(root / 'orbis', args, output)
                self.assertEqual(command.call_count, 1)
            actual = driver.bake_command(output)
            self.assertIn('--metadata-file', actual)
            self.assertNotIn('--check', actual)

    def test_clears_inherited_overrides_without_changing_artifact_inputs(self):
        inherited = {'RUSTUP_TOOLCHAIN': 'nightly', 'RUSTC': '/secret/compiler',
                     'CARGO_PROFILE_RELEASE_DEBUG': '2', 'CARGO_TARGET_X_RUSTFLAGS': 'secret',
                     'ORBIS_LOCAL_STORAGE_KDF_T_COST': '1', 'VERA_E2E_DEADLINE_SCALE': '99',
                     'TRUST_NATIVE_GATEWAY_IMAGE': 'old', 'ORBIS_NATIVE_IMAGE': 'normal'}
        with patch.dict(os.environ, inherited, clear=True):
            result = driver.environment()
        self.assertEqual(result['ORBIS_NATIVE_IMAGE'], 'normal')
        self.assertEqual(result['CARGO_BUILD_JOBS'], '2')
        for key in inherited.keys() - {'ORBIS_NATIVE_IMAGE'}:
            self.assertNotIn(key, result)

    def test_real_builder_and_runtime_share_build_identity(self):
        config = driver.bake(Path('/checkout/trust'), 'ghcr.io/source/test:run', 'a' * 40)
        builder, runtime = (config['target'][name] for name in ('builder', 'gateway'))
        for key in ('context', 'dockerfile', 'args', 'platforms', 'cache-from'):
            self.assertEqual(builder[key], runtime[key])
        self.assertEqual(builder['target'], 'builder')
        self.assertNotIn('target', runtime)  # the unchanged final production stage
        self.assertEqual(runtime['args']['VERA_REVISION'], driver.VERA)
        self.assertEqual(runtime['cache-to'], ['type=registry,ref=ghcr.io/source/test:buildcache,mode=max'])

    def test_artifact_selection_rejects_wrong_curve_unsafe_outside_and_duplicates(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            event = {'reason': 'compiler-artifact', 'target': {'name': 'native_startup'},
                     'features': ['native', 'redb', 'iroh', 'bls12-381'], 'executable': str(root.resolve() / 'release/test')}
            path = root / 'build.jsonl'
            path.write_text(json.dumps(event) + '\n')
            self.assertEqual(driver.test_binary(path, root, 'bls12-381'), root.resolve() / 'release/test')
            for change in ({'features': ['native', 'redb', 'iroh', 'jubjub']},
                           {'features': event['features'] + ['unsafe-testing']},
                           {'executable': '/outside/secret'}):
                path.write_text(json.dumps({**event, **change}) + '\n')
                with self.assertRaises(driver.Failure):
                    driver.test_binary(path, root, 'bls12-381')
            path.write_text((json.dumps(event) + '\n') * 2)
            with self.assertRaises(driver.Failure):
                driver.test_binary(path, root, 'bls12-381')

    def test_requires_one_live_pass_and_exact_production_marker(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'runtime.log'
            valid = driver.MARKER + '\ntest result: ok. 1 passed; 0 failed; 0 ignored; 5 filtered out\n'
            path.write_text(valid)
            driver.outcome(path)
            for text in (valid.replace('1 passed', '0 passed'), valid + valid,
                         valid.replace('production_kdf=true', 'production_kdf=false'),
                         valid.replace(driver.MARKER, driver.MARKER + ' extra')):
                path.write_text(text)
                with self.assertRaises(driver.Failure):
                    driver.outcome(path)

    def test_go_version_is_bound_to_one_digest_pinned_builder(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / 'Dockerfile.native'
            for version in ('1.27.1', '1.27.2'):
                line = 'FROM golang:' + version + '-bookworm@sha256:' + 'a' * 64 + ' AS builder\n'
                path.write_text(line)
                self.assertEqual(driver.builder_go_version(root), 'go version go' + version + ' linux/amd64')
                path.write_text(line + line)
                with self.assertRaises(driver.Failure):
                    driver.builder_go_version(root)
            for content in ('FROM golang:latest AS builder\n', 'FROM golang:1.27.2-bookworm AS builder\n'):
                path.write_text(content)
                with self.assertRaises(driver.Failure):
                    driver.builder_go_version(root)

    def test_local_bake_never_publishes_or_reads_registry_cache(self):
        config = driver.bake(Path('/checkout/trust'), 'ghcr.io/source/test:run', 'a' * 40, local=True)
        for target in config['target'].values():
            self.assertEqual(target['output'], ['type=docker'])
            self.assertNotIn('cache-from', target)
            self.assertNotIn('cache-to', target)
        self.assertNotIn('push=true', json.dumps(config))

    def test_local_image_requires_exact_loaded_identity_without_pull(self):
        image = 'sha256:' + 'a' * 64
        with patch.object(driver, 'command') as execute, patch.object(driver, 'capture', return_value=image):
            self.assertEqual(driver.image_id(Path('/root'), {}, image, Path('/log')), image)
            execute.assert_not_called()
        with patch.object(driver, 'command') as execute, patch.object(driver, 'capture', return_value='sha256:' + 'b' * 64):
            with self.assertRaises(driver.Failure):
                driver.image_id(Path('/root'), {}, image, Path('/log'))
            execute.assert_not_called()

    def test_registry_image_is_pulled_and_resolved_to_immutable_identity(self):
        image = 'ghcr.io/source/test@sha256:' + 'b' * 64
        identifier = 'sha256:' + 'a' * 64
        with patch.object(driver, 'command') as execute, patch.object(driver, 'capture', return_value=identifier):
            self.assertEqual(driver.image_id(Path('/root'), {}, image, Path('/log')), identifier)
            self.assertEqual(execute.call_args.args[0], ['docker', 'pull', image])

    def test_rejects_transfer_path_escape_and_wrong_source(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            payload = root / 'payload'
            payload.mkdir()
            hashes = {}
            for name in driver.FILES:
                path = payload / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'fixture-artifact')
                hashes[name] = driver.sha(path)
            manifest = {'version': 1, 'profile': 'release', 'rust': '1.98.0', 'binary_sha256': hashes,
                        'sources': {name: {'head': ref} for name, ref in (
                            ('orbis', 'a' * 40), ('trust', 'b' * 40), ('vera', driver.VERA), ('defra', driver.DEFRA))}}
            (payload / 'manifest.json').write_text(json.dumps(manifest))
            archive = root / 'native-trust-artifacts.tar'
            def pack(extra=False, local=False):
                with tarfile.open(archive, 'w') as tar:
                    for name in (*driver.FILES, 'manifest.json'):
                        tar.add(payload / name, arcname=name)
                    if local:
                        tar.add(payload / driver.IMAGE_ARCHIVE, arcname=driver.IMAGE_ARCHIVE)
                    if extra:
                        tar.add(payload / 'manifest.json', arcname='../private-secret')
                (root / 'native-trust-artifacts.sha256').write_text(driver.sha(archive) + '\n')
            pack()
            driver.restore(root, root / 'ok', 'a' * 40, 'b' * 40)
            with self.assertRaises(driver.Failure):
                driver.restore(root, root / 'wrong', 'c' * 40, 'b' * 40)
            pack(True)
            with self.assertRaises(driver.Failure):
                driver.restore(root, root / 'escape', 'a' * 40, 'b' * 40)
            self.assertFalse((root / 'private-secret').exists())
            (payload / driver.IMAGE_ARCHIVE).write_bytes(b'private-image-fixture')
            manifest['trust_image'] = 'sha256:' + 'c' * 64
            manifest['image_archive_sha256'] = driver.sha(payload / driver.IMAGE_ARCHIVE)
            (payload / 'manifest.json').write_text(json.dumps(manifest))
            pack(local=True)
            restored = driver.restore(root, root / 'local', 'a' * 40, 'b' * 40)
            self.assertEqual(restored['trust_image'], manifest['trust_image'])
            pack()
            with self.assertRaises(driver.Failure):
                driver.restore(root, root / 'missing-image', 'a' * 40, 'b' * 40)
            pack(local=True)
            manifest['image_archive_sha256'] = 'd' * 64
            (payload / 'manifest.json').write_text(json.dumps(manifest))
            pack(local=True)
            with self.assertRaises(driver.Failure):
                driver.restore(root, root / 'changed-image', 'a' * 40, 'b' * 40)
            del manifest['image_archive_sha256']
            (payload / 'manifest.json').write_text(json.dumps(manifest))
            pack(local=True)
            with self.assertRaises(driver.Failure):
                driver.restore(root, root / 'unrecorded-image', 'a' * 40, 'b' * 40)

    def test_failure_console_never_copies_raw_messages_or_paths(self):
        output = io.StringIO()
        with patch('sys.argv', ['driver', 'validate', '--trust-ref', '\x1b[31msecret /private/key']), contextlib.redirect_stdout(output):
            self.assertEqual(driver.main(), 1)
        decoded = json.loads(output.getvalue())
        self.assertEqual(decoded['passed'], 0)
        self.assertTrue(all(type(value) in (int, float) for value in decoded.values()))
        self.assertNotIn('secret', output.getvalue())
        self.assertNotIn('/private', output.getvalue())
        self.assertNotIn('\x1b', output.getvalue())


if __name__ == '__main__':
    unittest.main()
