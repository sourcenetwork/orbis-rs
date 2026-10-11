#!/usr/bin/env python3
"""Check signing transport recovery before and after retiring failed connections."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

BASELINE = '1fdd8d2986f3de5a8f873ea01afddd183276a083'
FIXED = '17de3caf4689882d083b8b272c9affe1a93f8a0e'
PREFIX = 'sign::v0::coordinator::network::tests::'
FAILED_BEFORE = {
    'timed_out_receive_retires_connection_without_replaying_request',
    'timed_out_stream_open_retires_connection_before_next_request',
    'failed_send_retires_connection_without_replaying_request',
}
CASES = FAILED_BEFORE | {
    'successful_exchanges_reuse_connection',
    'response_validation_failure_does_not_retire_transport',
    'late_timeout_preserves_replacement_connection',
}


def git(root, *arguments):
    return subprocess.check_output(['git', '-C', str(root), *arguments], text=True).strip()


def main():
    root = Path(os.environ['GITHUB_WORKSPACE']) / 'candidate'
    curve = os.environ['QUALIFICATION_CURVE']
    if curve not in ('bls12-381', 'jubjub'):
        raise ValueError('unsupported curve')
    output = Path(os.environ['RUNNER_TEMP']) / ('sign-peer-recovery-' + curve)
    output.mkdir(mode=0o700, exist_ok=False)
    proof = {'curve': curve, 'complete': False, 'runs': [],
             'runner_source': git(Path(os.environ['GITHUB_WORKSPACE']), 'rev-parse', 'HEAD'),
             'toolchain': subprocess.check_output(['rustc', '+1.98.0', '--version'], text=True).strip(),
             'profile': 'release', 'features': 'integration-test-native,redb,iroh,' + curve,
             'locked_dependencies': True}
    evidence = output / 'results.json'
    for source, expected_failures in ((BASELINE, FAILED_BEFORE), (FIXED, set())):
        subprocess.run(['git', '-C', str(root), 'checkout', '--quiet', '--detach', source], check=True)
        if git(root, 'rev-parse', 'HEAD') != source or git(root, 'status', '--porcelain', '--untracked-files=no'):
            raise ValueError('qualification source changed')
        command = ['cargo', '+1.98.0', 'test', '--frozen', '--release', '-p', 'orbis-node',
                   '--no-default-features', '--features', 'integration-test-native,redb,iroh,' + curve,
                   '--lib', PREFIX, '--', '--test-threads=1']
        log = output / (source + '.private.log')
        with log.open('x') as stream:
            os.chmod(log, 0o600)
            completed = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                                       timeout=2400)
        with log.open('rb') as stream:
            stream.seek(max(0, log.stat().st_size - 65536))
            tail = stream.read().decode('utf-8', errors='replace')
        results = re.findall(r'^test ' + re.escape(PREFIX) + r'([a-z_]+) \.\.\. (ok|FAILED)$', tail, re.M)
        observed = dict(results)
        failures = {name for name, outcome in results if outcome == 'FAILED'}
        valid = (len(results) == len(CASES) and set(observed) == CASES and failures == expected_failures
                 and completed.returncode == (101 if expected_failures else 0)
                 and git(root, 'rev-parse', 'HEAD') == source
                 and not git(root, 'status', '--porcelain', '--untracked-files=no'))
        record = {'source': source, 'tree': git(root, 'rev-parse', 'HEAD^{tree}'),
                  'exit_code': completed.returncode, 'expected_failures': sorted(expected_failures),
                  'results': {name: observed.get(name) for name in sorted(CASES)},
                  'expected_outcome': valid,
                  'test_source_sha256': hashlib.sha256((root / 'bin/orbis-node/src/sign/v0/coordinator/network_tests.rs').read_bytes()).hexdigest(),
                  'compiler_errors': sorted(set(re.findall(r'error\[(E[0-9]{4})\]', tail)))[:8]}
        proof['runs'].append(record)
        evidence.write_text(json.dumps(proof, indent=2) + '\n')
        print(json.dumps(record), flush=True)
        if not valid:
            raise RuntimeError('focused signing recovery regression did not match its expected result')
    if proof['runs'][0]['test_source_sha256'] != proof['runs'][1]['test_source_sha256']:
        raise ValueError('baseline and fixed test cases differ')
    proof['complete'] = True
    proof['scope'] = 'Scripted Network/PeerConnection transport regressions only; real threshold lifecycle qualification remains required.'
    evidence.write_text(json.dumps(proof, indent=2) + '\n')


if __name__ == '__main__':
    main()
