import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

BASE = 'df74650d2683659baf254b52ae34f87256a15347'
FIX = '002755526eb880bf36f6d02b4ef634a57198b496'
TARGET = 'bin/orbis-node/src/dkg/v0/coordinator/reshare/selection.rs'
curve = os.environ['SELECTION_CURVE']
assert curve in ('bls12-381', 'jubjub')
output = Path(os.environ['RUNNER_TEMP']) / ('selection-' + curve)
output.mkdir(mode=0o700)
path = Path(TARGET)
fixed = path.read_bytes()
assert fixed == subprocess.check_output(['git', 'show', FIX + ':' + TARGET])
command = ['cargo', 'test', '--locked', '-p', 'orbis-node', '--no-default-features',
           '--features', 'native,redb,iroh,' + curve, '--lib']
report = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'fix': FIX, 'baseline': BASE, 'curve': curve,
          'fixed_source_sha256': hashlib.sha256(fixed).hexdigest(), 'phases': []}


def save():
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def run(phase, selector):
    with (output / (phase + '.log')).open('x') as log:
        result = subprocess.run(command + [selector, '--', '--test-threads=1'],
                                stdout=log, stderr=subprocess.STDOUT, timeout=3000)
    content = (output / (phase + '.log')).read_text(errors='replace')
    outcomes = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', content)
    record = {'phase': phase, 'exit_code': result.returncode,
              'outcomes': [{'success': status == 'ok', 'passed': int(passed),
                            'failed': int(failed), 'ignored': int(ignored)}
                           for status, passed, failed, ignored in outcomes]}
    report['phases'].append(record)
    save()
    return record, content


try:
    result, _ = run('fixed', 'coordinator::reshare::selection::tests')
    assert result['exit_code'] == 0
    assert result['outcomes'] == [{'success': True, 'passed': 8, 'failed': 0, 'ignored': 0}]
    baseline = subprocess.check_output(['git', 'show', BASE + ':' + TARGET], text=True)
    current = fixed.decode()
    start, end = 'fn validate_reshare_participant_set_state', '#[cfg(test)]'
    original = baseline[baseline.index(start):baseline.index(end)]
    assert current.count(start) == baseline.count(start) == 1
    path.write_text(current[:current.index(start)] + original + current[current.index(end):])
    report['baseline_validator_sha256'] = hashlib.sha256(original.encode()).hexdigest()
    result, content = run('baseline', 'departing_dealer_observes_main_and_pet_selection_without_accepting_new_shares')
    expected = 'ReshareParticipantSet received by node outside new committee'
    report['baseline_reproduced_outside_committee_rejection'] = expected in content
    assert result['exit_code'] == 101
    assert result['outcomes'] == [{'success': False, 'passed': 0, 'failed': 1, 'ignored': 0}]
    assert report['baseline_reproduced_outside_committee_rejection']
    report['qualified'] = True
finally:
    path.write_bytes(fixed)
    save()
print(json.dumps(report))
