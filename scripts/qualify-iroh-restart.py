"""Qualify same-key, same-socket Iroh peer crashes without the application stack."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

CASE = 'iroh::tests::restart::cold_dial_reconnects_after_same_key_and_socket_peer_crashes'


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def main():
    output = Path(os.environ['RUNNER_TEMP']) / 'iroh-restart-results'
    output.mkdir(mode=0o700, exist_ok=False)
    source, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    if git('status', '--porcelain', '--untracked-files=no'):
        raise ValueError('transport qualification requires clean tracked source')
    command = ['cargo', '+1.98.0', 'test', '--frozen', '--release', '-p', 'network', '--lib',
               CASE, '--', '--exact', '--nocapture', '--test-threads=1']
    log = output / 'transport.private.log'
    with log.open('x') as stream:
        os.chmod(log, 0o600)
        completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=2400)
    with log.open('rb') as stream:
        stream.seek(max(0, log.stat().st_size - 65536))
        tail = stream.read().decode(errors='replace')
    samples = re.findall(r'\biroh_restart_transport=(\{[^\n]{1,1024}\})', tail)
    observed = json.loads(samples[0]) if len(samples) == 1 else None
    expected = {'peer_crashes': 2, 'fresh_client_dials': 3, 'echoes': 3, 'loopback_only': True}
    proof = {'source': source, 'tree': tree, 'exit_code': completed.returncode,
             'toolchain': subprocess.check_output(['rustc', '+1.98.0', '--version'], text=True).strip(),
             'case': CASE, 'observed': observed,
             'test_source_sha256': hashlib.sha256(Path('crates/network/src/iroh/restart_tests.rs').read_bytes()).hexdigest(),
             'compiler_errors': sorted(set(re.findall(r'error\[(E[0-9]{4})\]', tail)))[:8],
             'source_locations': sorted(set(re.findall(r'(crates/[A-Za-z0-9_./-]+\.rs:\d+:\d+)', tail)))[:16],
             'scope': 'Loopback-only transport; server killed with SIGKILL twice, same identities/sockets and fresh clients. Orbis/Docker/ACP/threshold qualification remains separate.'}
    proof['complete'] = (completed.returncode == 0 and observed == expected
                         and git('rev-parse', 'HEAD') == source and not git('status', '--porcelain', '--untracked-files=no'))
    (output / 'results.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof))
    if not proof['complete']:
        raise RuntimeError('isolated transport restart qualification failed; private log retained')


if __name__ == '__main__':
    main()
