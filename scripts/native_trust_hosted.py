#!/usr/bin/env python3
"""Opt-in native Trust ring qualification. Runtime output and state stay private."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

VERA = 'b3131f408078107f59254cfe9e107e510b3139c2'
DEFRA = 'cd8958601fa5319c6b4bcf5053c840c8606708a9'
SELECTOR = 'native_trust_gateway_ring_dkg'
MARKER = 'native Trust phase=ring-dkg rings=2 replicas=4 paired_keys=true production_kdf=true'
STAGE = 0
COMPLETED = 0
COMMANDS = []
IMAGE_ARCHIVE = 'gateway-image.tar'
FILES = ('bin/defra', 'bin/trust-api', 'bin/trust-api.test', 'lib/libvera_verifier.so', 'include/vera_verifier.h')


class Failure(Exception):
    pass


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def revision(value):
    if not re.fullmatch('[0-9a-f]{40}', value):
        raise Failure()
    return value


def runtime_revision(root, fixture, requested):
    fixture = revision(fixture)
    runtime = revision(requested) if requested is not None else fixture
    if runtime != fixture:
        changed = capture(['git', 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                           '--name-only', runtime, fixture, '--'], root).splitlines()
        guard = runpy.run_path(str(root / 'scripts/qualify-native-restart.py'))
        guard['verify_fixture_changes'](changed)
    return runtime


def environment():
    result = dict(os.environ)
    exact = {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS', 'RUSTC', 'RUSTDOC',
             'RUSTUP_TOOLCHAIN', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_TARGET_DIR',
             'CARGO_BUILD_TARGET', 'VERA_E2E_DEADLINE_SCALE', 'TRUST_NATIVE_GATEWAY_IMAGE',
             'TRUST_NATIVE_GATEWAY_BINARY', 'TRUST_NATIVE_RING_FIXTURE', 'GORACE'}
    for key in list(result):
        if key in exact or key.startswith(('CARGO_PROFILE_', 'ORBIS_LOCAL_STORAGE_KDF_',
                                           'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTDOC')) or (
                key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS')):
            result.pop(key)
    result.update(CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0', CARGO_BUILD_INCREMENTAL='false',
                  CARGO_TERM_COLOR='never', GOTOOLCHAIN='local', GOFLAGS='-mod=readonly -p=2',
                  CGO_ENABLED='1')
    return result


def command(args, cwd, env, log, timeout=5400):
    record = {'args': args, 'cwd': str(cwd), 'timeout': timeout, 'returncode': None, 'timed_out': False}
    COMMANDS.append(record)
    with log.open('wb') as output:
        process = subprocess.Popen(args, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record['timed_out'] = True
            raise
        finally:
            if args[0] == 'sudo':
                # The fixture group contains another UID; the invoking runner
                # cannot reliably signal every member of that group itself.
                subprocess.run(['sudo', '--non-interactive', '/bin/kill', '-KILL', '--', '-' + str(process.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            record['returncode'] = process.wait()
    if status:
        raise Failure()


def capture(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, stderr=subprocess.DEVNULL, text=True).strip()


def source(path, expected):
    if capture(['git', 'rev-parse', 'HEAD'], path) != revision(expected):
        raise Failure()
    if capture(['git', 'status', '--porcelain', '--untracked-files=no'], path):
        raise Failure()
    return {'head': expected, 'tree': capture(['git', 'rev-parse', 'HEAD^{tree}'], path)}


def pins(root, trust, vera, defra, trust_ref):
    sources = {name: source(path, ref) for name, path, ref in (
        ('orbis', root, os.environ['GITHUB_SHA']), ('trust', trust, trust_ref),
        ('vera', vera, VERA), ('defra', defra, DEFRA))}
    if capture([sys.executable, str(root / 'scripts/native-vera-ref.py')]) != VERA:
        raise Failure()
    if re.findall(r'^ARG VERA_REVISION=([0-9a-f]{40})$', (trust / 'Dockerfile.native').read_text(), re.M) != [VERA]:
        raise Failure()
    if f'DEFRADB_REVISION: {DEFRA}' not in (trust / '.github/workflows/native-gateway.yml').read_text():
        raise Failure()
    return sources


def builder_go_version(trust):
    versions = re.findall(r'^FROM golang:([0-9]+\.[0-9]+\.[0-9]+)-bookworm@sha256:[0-9a-f]{64} AS builder$',
                          (trust / 'Dockerfile.native').read_text(), re.M)
    if len(versions) != 1:
        raise Failure()
    return 'go version go' + versions[0] + ' linux/amd64'


def bake(trust, image, trust_ref, local=False):
    # Both targets share the exact context, Dockerfile and args in one BuildKit
    # graph. The final target remains the real distroless production stage.
    common = {'context': str(trust), 'dockerfile': 'Dockerfile.native',
              'args': {'VERA_REVISION': VERA, 'VERSION': 'native-trust-rings', 'REVISION': trust_ref},
              'cache-from': [f'type=registry,ref={image.rsplit(":", 1)[0]}:buildcache'],
              'platforms': ['linux/amd64']}
    gateway = {**common, 'tags': [image], 'output': ['type=docker' if local else 'type=image,push=true']}
    if local:
        common.pop('cache-from')
        gateway.pop('cache-from')
    else:
        gateway['cache-to'] = [f'type=registry,ref={image.rsplit(":", 1)[0]}:buildcache,mode=max']
    return {'group': {'default': {'targets': ['builder', 'gateway']}}, 'target': {
        'builder': {**common, 'target': 'builder', 'tags': ['trust-ring-builder:local'], 'output': ['type=docker']},
        'gateway': gateway}}


def bake_command(output, check=False):
    args = ['docker', 'buildx', 'bake', '--progress', 'plain', '--file', str(output / 'bake.json')]
    return args + (['--check'] if check else ['--metadata-file', str(output / 'buildkit.json')])


def build(root, args, output):
    global STAGE
    STAGE = 10
    trust, vera, defra = (Path(value).resolve() for value in (args.trust, args.vera, args.defra))
    sources = pins(root, trust, vera, defra, args.trust_ref)
    cargo_version = capture(['cargo', '+1.98.0', '--version'])
    if not cargo_version.startswith('cargo 1.98.0 '):
        raise Failure()
    env = environment()
    payload = output / 'payload'
    for directory in ('bin', 'lib', 'include'):
        (payload / directory).mkdir(parents=True, mode=0o700)
    STAGE = 15
    (output / 'bake.json').write_text(json.dumps(bake(trust, args.image, args.trust_ref, args.local_image)))
    # Keep the build context within Bake's working directory; no filesystem entitlement is needed.
    command(bake_command(output, check=True), trust, env, output / 'trust-bake-check.log', 300)
    # This one private target is never shared with other source checkouts.
    target = output / 'defra-target'
    env['CARGO_TARGET_DIR'] = str(target)
    STAGE = 20
    command(['cargo', '+1.98.0', 'build', '--release', '--locked', '-j2', '-p', 'cli', '--bin', 'defra', '--features', 'vera'],
            defra, env, output / 'defra-build.log')
    shutil.copy2(target / 'release/defra', payload / 'bin/defra')
    shutil.rmtree(target)  # Only this newly-created job-private target; downloaded dependencies remain cached.
    env.pop('CARGO_TARGET_DIR')
    STAGE = 30
    command(bake_command(output), trust, env, output / 'trust-build.log')
    STAGE = 31
    meta = json.loads((output / 'buildkit.json').read_text())
    if args.local_image:
        STAGE = 32
        image_ref = capture(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}'])
        if not re.fullmatch('sha256:[0-9a-f]{64}', image_ref):
            raise Failure()
        command(['docker', 'image', 'save', '--output', str(payload / IMAGE_ARCHIVE), image_ref],
                root, env, output / 'gateway-save.log')
    else:
        digest = meta['gateway']['containerimage.digest']
        if not re.fullmatch('sha256:[0-9a-f]{64}', digest):
            raise Failure()
        image_ref = args.image + '@' + digest
    STAGE = 33
    container = capture(['docker', 'create', 'trust-ring-builder:local', 'true'])
    try:
        for src, dst in (('/runtime/app/trust-api', 'bin/trust-api'),
                         ('/opt/vera/lib/libvera_verifier.so', 'lib/libvera_verifier.so'),
                         ('/opt/vera/include/vera_verifier.h', 'include/vera_verifier.h')):
            command(['docker', 'cp', container + ':' + src, str(payload / dst)], root, env, output / ('copy-' + Path(dst).name + '.log'))
    finally:
        command(['docker', 'rm', '--force', container], root, env, output / 'builder-cleanup.log', 30)
    if sha(payload / 'include/vera_verifier.h') != sha(vera / 'crates/vera-verifier/include/vera_verifier.h'):
        raise Failure()
    STAGE = 40
    go_version = capture(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'go', 'trust-ring-builder:local', 'version'])
    if go_version != builder_go_version(trust):
        raise Failure()
    # Production excludes test sources; mount the pinned checkout read-only.
    command(fixture_build_command(trust, payload),
            trust, env, output / 'go-fixture-build.log')
    if not (payload / 'bin/trust-api.test').is_file():
        raise Failure()
    if pins(root, trust, vera, defra, args.trust_ref) != sources:
        raise Failure()
    env['LD_LIBRARY_PATH'] = str(payload / 'lib')
    command(['ldd', *[str(payload / name) for name in FILES if not name.endswith('.h')]], root, env, output / 'libraries.log', 30)
    if 'not found' in (output / 'libraries.log').read_text():
        raise Failure()
    STAGE = 50
    (output / 'commands.json').write_text(json.dumps(COMMANDS, indent=2) + '\n')
    manifest = {'version': 1, 'sources': sources, 'trust_image': image_ref,
                'binary_sha256': {name: sha(payload / name) for name in FILES},
                'build_sha256': {name: sha(output / name) for name in ('bake.json', 'buildkit.json', 'commands.json')},
                'profile': 'release', 'rust': '1.98.0', 'cargo_version': cargo_version, 'go_version': go_version, 'normal_gateway_before_test_driver': True,
                'source_files_sha256': {'trust/Dockerfile.native': sha(trust / 'Dockerfile.native'),
                    'trust/go.mod': sha(trust / 'go.mod'), 'trust/go.sum': sha(trust / 'go.sum'),
                    'orbis/Cargo.lock': sha(root / 'Cargo.lock'), 'defra/Cargo.lock': sha(defra / 'Cargo.lock')}}
    if args.local_image:
        manifest['image_archive_sha256'] = sha(payload / IMAGE_ARCHIVE)
    (payload / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    archive = output / 'native-trust-artifacts.tar'
    with tarfile.open(archive, 'w') as tar:
        for name in (*FILES, 'manifest.json', *((IMAGE_ARCHIVE,) if args.local_image else ())):
            tar.add(payload / name, arcname=name, recursive=False)
    (output / 'native-trust-artifacts.sha256').write_text(sha(archive) + '\n')
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as result:
        result.write('trust_image=' + image_ref + '\n')


def fixture_build_command(trust, payload):
    return ['docker', 'run', '--rm', '--network', 'none', '--user', '0:0',
            '-e', 'GOFLAGS=-mod=readonly -p=2',
            '-e', 'CGO_CFLAGS=-I/opt/vera/include', '-e', 'CGO_LDFLAGS=-L/opt/vera/lib',
            '--mount', f'type=bind,src={trust},dst=/fixture,readonly',
            '--mount', f'type=bind,src={payload / "bin"},dst=/out', '--entrypoint', 'go',
            'trust-ring-builder:local', '-C', '/fixture', 'test', '-c', '-tags', 'vera_native',
            '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', '/out/trust-api.test', './cmd/trust-api']


def restore(directory, destination, expected_orbis, expected_trust):
    archive = directory / 'native-trust-artifacts.tar'
    if (directory / 'native-trust-artifacts.sha256').read_text().strip() != sha(archive):
        raise Failure()
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        expected = {*FILES, 'manifest.json'}
        if IMAGE_ARCHIVE in names:
            expected.add(IMAGE_ARCHIVE)
        if set(names) != expected or len(names) != len(expected):
            raise Failure()
        if any(not m.isfile() for m in members):
            raise Failure()
        destination.mkdir(mode=0o700)
        for member in members:
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tar.extractfile(member) as content, target.open('xb') as output:
                shutil.copyfileobj(content, output, 1024 * 1024)
            target.chmod(0o555 if member.name.startswith(('bin/', 'lib/')) else 0o444)
    manifest = json.loads((destination / 'manifest.json').read_text())
    if manifest['version'] != 1 or manifest['profile'] != 'release' or manifest['rust'] != '1.98.0':
        raise Failure()
    for name, expected in [('orbis', expected_orbis), ('trust', expected_trust), ('vera', VERA), ('defra', DEFRA)]:
        if manifest['sources'][name]['head'] != revision(expected):
            raise Failure()
    if set(manifest['binary_sha256']) != set(FILES):
        raise Failure()
    if any(sha(destination / name) != value for name, value in manifest['binary_sha256'].items()):
        raise Failure()
    local_image = (destination / IMAGE_ARCHIVE).is_file()
    if local_image != ('image_archive_sha256' in manifest):
        raise Failure()
    if local_image and (not re.fullmatch('sha256:[0-9a-f]{64}', manifest['trust_image']) or
                        sha(destination / IMAGE_ARCHIVE) != manifest['image_archive_sha256']):
        raise Failure()
    return manifest


def image_id(root, env, image, log):
    if not re.fullmatch('sha256:[0-9a-f]{64}', image):
        command(['docker', 'pull', image], root, env, log)
    identifier = capture(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'])
    if not re.fullmatch('sha256:[0-9a-f]{64}', identifier):
        raise Failure()
    if image.startswith('sha256:') and identifier != image:
        raise Failure()
    return identifier


def test_binary(path, target, curve):
    found = []
    for line in path.read_text().splitlines():
        event = json.loads(line)
        if event.get('reason') == 'compiler-artifact' and event['target']['name'] == 'native_startup' and event.get('executable'):
            features = set(event['features'])
            if not {'native', 'redb', 'iroh', curve} <= features or {'unsafe-testing', 'integration-test', {'bls12-381': 'jubjub', 'jubjub': 'bls12-381'}[curve]} & features:
                raise Failure()
            binary = Path(event['executable']).resolve()
            if not binary.is_relative_to(target.resolve()):
                raise Failure()
            found.append(binary)
    if len(found) != 1:
        raise Failure()
    return found[0]


def outcome(path):
    content = path.read_text(errors='replace')
    if content.splitlines().count(MARKER) != 1:
        raise Failure()
    summaries = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', content, re.M)
    if summaries != [('1', '0', '0')]:
        raise Failure()



def launch_fixture(root, private, run_env, env, log):
    # chdir must occur after sudo changes identity: the original runner cannot
    # enter the owner-only 65532 directory. Keep the parent cwd accessible.
    command(['sudo', '--user', 'trust-native-ring', '--', 'env', '-i',
             *[key + '=' + value for key, value in run_env.items()],
             '/bin/sh', '-c', 'cd "$1" || exit; shift; exec "$@"', 'native-trust-fixture',
             str(private), str(private / 'bin/native_startup'), SELECTOR,
             '--exact', '--ignored', '--nocapture', '--test-threads=1'],
            root, env, log, 600)


def run(root, args, output):
    global STAGE, COMPLETED
    STAGE = 60
    env = environment()
    artifacts = output / 'artifacts'
    manifest = restore(Path(args.artifacts), artifacts, os.environ['GITHUB_SHA'], args.trust_ref)
    source(root, manifest['sources']['orbis']['head'])
    runtime = runtime_revision(root, manifest['sources']['orbis']['head'],
                               env.get('ORBIS_NATIVE_RUNTIME_REVISION'))
    env['CARGO_TARGET_DIR'] = str(output / 'target')
    STAGE = 70
    stdout = output / 'compile.jsonl'
    with stdout.open('wb') as out, (output / 'compile.log').open('wb') as err:
        process = subprocess.Popen(['cargo', '+1.98.0', 'test', '--release', '--locked', '-j2', '-p', 'orbis-node',
                '--no-default-features', '--features', 'native,redb,iroh,' + args.curve,
                '--test', 'native_startup', '--no-run', '--message-format=json'], cwd=root, env=env,
                stdout=out, stderr=err, start_new_session=True)
        try:
            status = process.wait(timeout=5400)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    if status:
        raise Failure()
    binary = test_binary(stdout, output / 'target', args.curve)
    binary_hash = sha(binary)
    listed = capture([str(binary), '--list', '--ignored'])
    if listed.splitlines().count(SELECTOR + ': test') != 1:
        raise Failure()
    STAGE = 80
    images = {}
    for name in ('ORBIS_NATIVE_IMAGE', 'ORBIS_NATIVE_VERA_IMAGE'):
        images[name] = image_id(root, env, env[name], output / (name + '.log'))
    if 'image_archive_sha256' in manifest:
        command(['docker', 'image', 'load', '--input', str(artifacts / IMAGE_ARCHIVE)],
                root, env, output / 'gateway-load.log')
    gateway_image = image_id(root, env, manifest['trust_image'], output / 'gateway-pull.log')
    info = json.loads(capture(['docker', 'image', 'inspect', gateway_image]))[0]['Config']
    if info['User'] != '65532:65532' or info['Labels']['org.opencontainers.image.revision'] != args.trust_ref or info['Labels']['io.sourcenetwork.vera.revision'] != VERA:
        raise Failure()
    labels = json.loads(capture(['docker', 'image', 'inspect', images['ORBIS_NATIVE_IMAGE']]))[0]['Config']['Labels']
    if labels.get('org.opencontainers.image.revision') != runtime or labels.get('io.sourcenetwork.orbis.backend') != 'native' or labels.get('io.sourcenetwork.orbis.curve') != args.curve or labels.get('io.sourcenetwork.orbis.integration-features') != 'false':
        raise Failure()
    vera_labels = json.loads(capture(['docker', 'image', 'inspect', images['ORBIS_NATIVE_VERA_IMAGE']]))[0]['Config']['Labels']
    if vera_labels.get('org.opencontainers.image.revision') != VERA:
        raise Failure()
    image_binaries = {}
    for name, image, path in [('orbis', images['ORBIS_NATIVE_IMAGE'], '/usr/local/bin/orbis-node'),
                              ('vera', images['ORBIS_NATIVE_VERA_IMAGE'], '/usr/local/bin/verad'),
                              ('gateway', gateway_image, '/app/trust-api'),
                              ('verifier', gateway_image, '/app/lib/libvera_verifier.so')]:
        container = capture(['docker', 'create', image, 'true'])
        destination = output / ('image-' + name)
        try:
            command(['docker', 'cp', container + ':' + path, str(destination)], root, env, output / ('image-' + name + '.log'))
        finally:
            command(['docker', 'rm', '--force', container], root, env, output / ('image-' + name + '-cleanup.log'), 30)
        image_binaries[name] = sha(destination)
    if image_binaries['gateway'] != manifest['binary_sha256']['bin/trust-api'] or image_binaries['verifier'] != manifest['binary_sha256']['lib/libvera_verifier.so']:
        raise Failure()
    # The existing container contract requires host fixtures to own the same
    # private files as the unchanged production image UID/GID.
    command(['sudo', 'groupadd', '--gid', '65532', 'trust-native-ring'], root, env, output / 'group.log', 30)
    command(['sudo', 'useradd', '--uid', '65532', '--gid', '65532', '--groups', 'docker',
             '--no-create-home', '--home-dir', '/nonexistent', 'trust-native-ring'], root, env, output / 'user.log', 30)
    private_roots = []
    try:
        for mode in ('executable', 'container'):
            STAGE = 90 if mode == 'executable' else 91
            private = Path(tempfile.mkdtemp(prefix='trust-ring-' + mode + '-', dir='/tmp'))
            private_roots.append(private)
            (private / 'bin').mkdir(mode=0o700)
            (private / 'lib').mkdir(mode=0o700)
            (private / 'state').mkdir(mode=0o700)
            (private / 'home').mkdir(mode=0o700)
            for name in FILES:
                if name.endswith('.h'):
                    continue
                dst = private / name
                shutil.copy2(artifacts / name, dst)
                dst.chmod(0o555)
            shutil.copy2(binary, private / 'bin/native_startup')
            (private / 'bin/native_startup').chmod(0o555)
            run_env = {**images, 'PATH': env['PATH'], 'HOME': str(private / 'home'),
                       'RUST_LOG': 'warn', 'VERA_E2E_KEEP': '1',
                       'VERA_E2E_DIR': str(private / 'state'), 'ORBIS_NATIVE_E2E_DIR': str(private / 'state'),
                       'LD_LIBRARY_PATH': str(private / 'lib'),
                       'TRUST_NATIVE_GATEWAY_TEST_BINARY': str(private / 'bin/trust-api.test'),
                       'DEFRADB_RUST_BINARY': str(private / 'bin/defra'),
                       'TRUST_NATIVE_CONTAINER_LABEL': 'native-ring-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'] + '-' + args.curve}
            run_env['TRUST_NATIVE_GATEWAY_' + ('BINARY' if mode == 'executable' else 'IMAGE')] = str(private / 'bin/trust-api') if mode == 'executable' else gateway_image
            command(['sudo', 'chown', '-R', '65532:65532', str(private)], root, env, output / (mode + '-ownership.log'), 30)
            launch_fixture(root, private, run_env, env, output / (mode + '.log'))
            outcome(output / (mode + '.log'))
            staged = [name for name in FILES if not name.endswith('.h')] + ['bin/native_startup']
            hashes = capture(['sudo', 'sha256sum', *[str(private / name) for name in staged]]).splitlines()
            expected = [manifest['binary_sha256'].get(name, binary_hash) for name in staged]
            if [line.split()[0] for line in hashes] != expected:
                raise Failure()
            COMPLETED += 1
            if sha(binary) != binary_hash or any(sha(artifacts / name) != value for name, value in manifest['binary_sha256'].items()):
                raise Failure()
        source(root, manifest['sources']['orbis']['head'])
        (output / 'result.json').write_text(json.dumps({'source': manifest['sources'], 'orbis_runtime_revision': runtime, 'binary_sha256': binary_hash,
            'images': {**images, 'trust': gateway_image}, 'image_binary_sha256': image_binaries, 'curve': args.curve, 'executions': 2, 'passed': 2,
            'production_kdf_stores': 6, 'go_tests': 2, 'ring_records_checked': 16}, indent=2) + '\n')
    finally:
        # Restrict cleanup to the exact Trust label and containers whose bind
        # mounts lie beneath this job's private roots; never docker prune.
        ids = capture(['docker', 'ps', '--all', '--quiet', '--filter', 'label=io.sourcenetwork.trust.native-fixture=native-ring-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'] + '-' + args.curve])
        owned = ids.splitlines()
        compose = capture(['docker', 'ps', '--all', '--quiet', '--filter', 'label=com.docker.compose.project'])
        for identifier in compose.splitlines():
            info = json.loads(capture(['docker', 'inspect', identifier]))[0]
            if any(Path(mount.get('Source', '/')).is_relative_to(private)
                   for mount in info.get('Mounts', []) for private in private_roots):
                owned.append(identifier)
        if owned:
            command(['docker', 'rm', '--force', *sorted(set(owned))], root, env, output / 'container-cleanup.log', 30)


def safe_diagnostics(output):
    # Only bounded counts/codes and fixed fixture IDs leave the private runner.
    result = {'compiler_errors': 0, 'compiler_codes': [], 'panics': 0, 'elapsed': 0, 'locations': []}
    codes, locations = set(), set()
    compiler = output / 'compile.jsonl'
    if compiler.is_file():
        with compiler.open(errors='replace') as stream:
            for _ in range(100000):
                line = stream.readline(1024 * 1024 + 1)
                if not line:
                    break
                if len(line) > 1024 * 1024:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                message = event.get('message') if isinstance(event, dict) and event.get('reason') == 'compiler-message' else None
                if not isinstance(message, dict) or message.get('level') != 'error':
                    continue
                result['compiler_errors'] += 1
                code = message.get('code')
                if isinstance(code, dict) and isinstance(code.get('code'), str) and re.fullmatch(r'E[0-9]{4}', code['code']):
                    codes.add(code['code'])
    for name in ('executable.log', 'container.log'):
        path = output / name
        if not path.is_file():
            continue
        with path.open(errors='replace') as stream:
            content = stream.read(4 * 1024 * 1024)
        result['panics'] += content.count('panicked at ')
        result['elapsed'] += len(re.findall(r'\bElapsed\b', content))
        for filename, number in re.findall(r'panicked at (?:bin/orbis-node/)?(tests/support/native_trust_gateway(?:/runner)?\.rs):([0-9]{1,6}):[0-9]{1,6}:', content):
            if 0 < int(number) < 1000000:
                locations.add((2 if '/runner.rs' in filename else 1, int(number)))
    result['compiler_codes'] = sorted(codes)[:16]
    result['locations'] = [list(value) for value in sorted(locations)[:16]]
    result['build'] = build_diagnostics(output)
    return result


def build_diagnostics(output):
    result = {'disk_full': 0, 'killed': 0, 'exit_codes': [], 'rust_codes': [], 'go_locations': [],
              'buildkit_metadata': int((output / 'buildkit.json').is_file()),
              'gateway_archive': int((output / 'payload' / IMAGE_ARCHIVE).is_file()),
              'command_status': sorted({record['returncode'] for record in COMMANDS
                                        if isinstance(record.get('returncode'), int)})[:16],
              'command_timeouts': sum(bool(record.get('timed_out')) for record in COMMANDS),
              'failure_kinds': []}
    patterns = {
        'network': r'connection (?:refused|reset)|network is unreachable|i/o timeout|TLS handshake timeout|temporary failure in name resolution|failed to fetch',
        'source_revision': r'not our ref|unknown revision|could not find remote ref|reference is not a tree',
        'credentials': r'unauthorized|authentication required|permission denied|pull access denied',
        'resources': r'resource temporarily unavailable|resourceexhausted|cannot allocate memory',
        'export': r'failed to (?:export|load)|error exporting',
        'toolchain': r'toolchain.*not installed|command not found|requires rustc|cannot find.*(?:clang|cc)',
        'checksum': r'checksum mismatch|checksum.*changed|verification failed',
        'docker_build': r'failed to solve|ERROR:',
        'filesystem_entitlement': r'filesystem entitle|additional privileges|fs\.read|access[^\n]*outside',
    }
    kinds = set()
    exit_codes, rust_codes, locations = set(), set(), set()
    for name in ('defra-build.log', 'trust-bake-check.log', 'trust-build.log', 'go-fixture-build.log'):
        path = output / name
        if not path.is_file():
            continue
        with path.open('rb') as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 4 * 1024 * 1024))
            content = stream.read().decode(errors='replace')
        kinds.update(kind for kind, pattern in patterns.items() if re.search(pattern, content, re.I))
        result['disk_full'] += content.lower().count('no space left on device')
        result['killed'] += len(re.findall(r'\bsignal: killed\b|\bSIGKILL\b|\bOOMKilled\b', content))
        exit_codes.update(int(code) for code in re.findall(r'exit code: ([0-9]{1,3})\b', content) if int(code) < 256)
        rust_codes.update(re.findall(r'error\[(E[0-9]{4})\]', content))
        for filename, row, column in re.findall(r'\bcmd/trust-api/([a-z_]+\.go):([0-9]{1,6}):([0-9]{1,6}):', content):
            if 0 < int(row) < 1000000 and 0 < int(column) < 1000000:
                locations.add((filename, int(row), int(column)))
    result['exit_codes'] = sorted(exit_codes)[:16]
    result['rust_codes'] = sorted(rust_codes)[:16]
    result['go_locations'] = [list(value) for value in sorted(locations)[:16]]
    result['failure_kinds'] = sorted(kinds)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('validate', 'build', 'run'))
    parser.add_argument('--trust-ref', required=True)
    parser.add_argument('--output', type=Path)
    for name in ('trust', 'vera', 'defra', 'image', 'artifacts'):
        parser.add_argument('--' + name)
    parser.add_argument('--local-image', action='store_true', help='Transfer the gateway image privately without publishing it')
    parser.add_argument('--curve', choices=('bls12-381', 'jubjub'))
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    started = time.monotonic()
    report = {'phase': ('validate', 'build', 'run').index(args.phase), 'passed': 0, 'executions': 0}
    try:
        revision(args.trust_ref)
        if args.phase == 'build' and not re.fullmatch(r'ghcr\.io/[a-z0-9_./-]+:[a-z0-9_.-]+', args.image or ''):
            raise Failure()
        root = Path(__file__).resolve().parents[1]
        if args.phase != 'validate':
            if args.output is None:
                raise Failure()
            args.output.mkdir(mode=0o700)
            (build if args.phase == 'build' else run)(root, args, args.output)
        report['passed'] = 1
        report['executions'] = COMPLETED
    except (Failure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, KeyboardInterrupt):
        pass
    report['stage'] = STAGE
    report['executions'] = COMPLETED
    report['duration_seconds'] = round(time.monotonic() - started, 2)
    if args.output is not None and args.output.is_dir():
        try:
            report['diagnostics'] = safe_diagnostics(args.output)
        except OSError:
            report['diagnostics_unavailable'] = 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
