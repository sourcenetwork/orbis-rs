"""Check crash/restart dials on two isolated Docker bridge endpoints."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

CHILD = 'iroh::tests::restart::transport_server_child'


def main():
    output = Path(os.environ['RUNNER_TEMP']) / 'iroh-bridge-results'
    output.mkdir(mode=0o700, exist_ok=False)
    proof = {'complete': False, 'stage': 'compile', 'checks': [],
             'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
             'toolchain': subprocess.check_output(['rustc', '+1.98.0', '--version'], text=True).strip(),
             'scope': 'Two quiet Iroh endpoints on a Docker bridge; same key/IP/UDP socket after SIGKILL. Orbis authorization, threshold processing and workload remain separate.'}
    log = output / 'transport.private.log'
    log.touch(mode=0o600)
    prefix = 'orbis-transport-' + uuid.uuid4().hex[:12]
    network, image = prefix + '-network', prefix + '-image'
    containers = []

    def run(arguments, timeout=120):
        with log.open('a') as stream:
            result = subprocess.run(arguments, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError('transport command failed at ' + proof['stage'])

    def capture(arguments):
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('transport inspection failed at ' + proof['stage'])
        return result.stdout.strip()

    def wait_file(path, container):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if path.exists():
                raw = path.read_bytes()
                if len(raw) > 2048:
                    raise ValueError('transport output exceeds bound')
                return raw
            if capture(['docker', 'inspect', '--format', '{{.State.Running}}', container]) != 'true':
                raise RuntimeError('transport endpoint exited at ' + proof['stage'])
            time.sleep(.05)
        raise RuntimeError('transport fixture deadline at ' + proof['stage'])

    try:
        build = output / 'build.private.log'
        with build.open('x') as stream:
            os.chmod(build, 0o600)
            result = subprocess.run(['cargo', '+1.98.0', 'test', '--frozen', '--release', '-p', 'network',
                                     '--lib', '--no-run', '--message-format=json'], stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=2400)
        if result.returncode:
            raise RuntimeError('transport fixture compilation failed')
        executables = []
        for line in build.read_text().splitlines():
            if line.startswith('{'):
                row = json.loads(line)
                if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'network' and row.get('executable'):
                    executables.append(row['executable'])
        if len(executables) != 1:
            raise ValueError('transport test executable missing or ambiguous')
        proof['test_binary_sha256'] = hashlib.sha256(Path(executables[0]).read_bytes()).hexdigest()
        context = output / 'image'
        context.mkdir(mode=0o700)
        shutil.copy2(executables[0], context / 'transport-test')
        (context / 'Dockerfile').write_text('FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y --no-install-recommends libgcc-s1 libssl3t64 ca-certificates && rm -rf /var/lib/apt/lists/*\nCOPY transport-test /usr/local/bin/transport-test\nENTRYPOINT ["/usr/local/bin/transport-test"]\n')
        proof['stage'] = 'image'
        run(['docker', 'build', '--quiet', '-t', image, str(context)], timeout=600)
        proof['image_id'] = capture(['docker', 'image', 'inspect', '--format', '{{.Id}}', image])
        proof['stage'] = 'network'
        run(['docker', 'network', 'create', network])
        settings = json.loads(capture(['docker', 'network', 'inspect', '--format', '{{json .IPAM.Config}}', network]))
        subnet = next(ipaddress.ip_network(row['Subnet']) for row in settings if ipaddress.ip_network(row['Subnet']).version == 4)
        directories, routes = [], []
        for member in range(2):
            directory = output / f'node-{member}'
            directory.mkdir(mode=0o700)
            directories.append(directory)
            address = str(subnet.network_address + 10 + member)
            container = prefix + f'-node-{member}'
            proof['stage'] = 'startup'
            run(['docker', 'run', '-d', '--name', container, '--network', network, '--ip', address,
                 '--user', f'{os.getuid()}:{os.getgid()}', '--mount', f'type=bind,source={directory},target=/data',
                 '-e', 'ORBIS_IROH_RESTART_DIRECTORY=/data', '-e', 'ORBIS_IROH_RESTART_PORT=9001',
                 '-e', f'ORBIS_IROH_RESTART_SEED={2 + member}', '-e', 'ORBIS_IROH_RESTART_BIND_IP=0.0.0.0',
                 '-e', f'ORBIS_IROH_RESTART_ADVERTISED_IP={address}', '-e', 'ORBIS_IROH_RESTART_COMMANDS=1',
                 image, '--exact', CHILD, '--ignored', '--nocapture', '--test-threads=1'])
            containers.append(container)
            routes.append(wait_file(directory / 'ready', container).decode())
        sequences = [0, 0]
        for cycle in range(3):
            if cycle:
                proof['stage'] = 'crash'
                run(['docker', 'kill', '--signal', 'SIGKILL', *containers])
                for container in containers:
                    assert capture(['docker', 'inspect', '--format', '{{.State.ExitCode}}', container]) == '137'
                for directory in directories:
                    for path in directory.iterdir():
                        if path.name == 'ready' or path.name.startswith(('command-', 'result-')):
                            path.unlink()
                sequences = [0, 0]
                run(['docker', 'start', *containers])
                for member, directory in enumerate(directories):
                    assert wait_file(directory / 'ready', containers[member]).decode() == routes[member]
            for sender, receiver in [(0, 1), (1, 0)]:
                proof['stage'] = f'dial-{cycle}-{sender}'
                sequences[sender] += 1
                command = directories[sender] / f'command-{sequences[sender]}.json'
                pending = command.with_suffix('.tmp')
                pending.write_text(json.dumps({'peer': routes[receiver]}))
                pending.rename(command)
                result = json.loads(wait_file(directories[sender] / f'result-{sequences[sender]}.json', containers[sender]))
                assert result == {'echoed': True}
                proof['checks'].append({'cycle': cycle, 'sender': sender, 'receiver': receiver, 'echoed': True})
        proof['complete'] = True
        proof['stage'] = 'complete'
    finally:
        for container in containers:
            with (output / (container + '.private.log')).open('w') as stream:
                os.chmod(stream.name, 0o600)
                subprocess.run(['docker', 'logs', container], stdout=stream, stderr=subprocess.STDOUT, timeout=30)
        if containers:
            subprocess.run(['docker', 'rm', '--force', *containers], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        (output / 'results.json').write_text(json.dumps(proof, indent=2) + '\n')
        print(json.dumps(proof))
    if not proof['complete']:
        raise RuntimeError('bridge transport qualification failed')


if __name__ == '__main__':
    main()
