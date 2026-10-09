#!/usr/bin/env python3
"""Qualify the shared restart fixture against unchanged normal runtime images."""
import json
import os
from pathlib import Path
import subprocess

RUNTIME = "9c76e741f73bdbac37fab71e79192c1289b052f2"
VERA = "892cf0582e9d9395574cd5e8900988cb4a6ebd21"
FIXTURE_FILES = {
    ".github/workflows/rust.yml", "scripts/qualify-native-restart.py",
    "crates/test-support/src/container.rs", "crates/test-support/src/lib.rs",
    "crates/test-support/src/native_network.rs", "crates/test-support/src/network/native.rs",
    "bin/orbis-node/tests/native_startup.rs",
    "docker/docker-compose-native-integration-test.yml",
}


def capture(command):
    return subprocess.check_output(command, text=True).strip()


def qualify():
    curve = os.environ["NATIVE_RESTART_CURVE"]
    if curve not in ("bls12-381", "jubjub"):
        raise ValueError("unsupported curve")
    subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", RUNTIME], check=True)
    changed = set(capture(["git", "diff", "--name-only", RUNTIME, "HEAD"]).splitlines())
    if changed - FIXTURE_FILES:
        raise ValueError("runtime source differs from the selected images")
    if Path("docker/NATIVE_VERA_REF").read_text().strip() != VERA:
        raise ValueError("Vera source does not match the runtime image")
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("ORBIS_LOCAL_STORAGE_KDF_"):
            del env[name]
    env.update(CARGO_BUILD_JOBS="2", RUSTUP_TOOLCHAIN="1.98.0")
    repository = "ghcr.io/sourcenetwork/orbis-rs"
    images = {
        "ORBIS_NATIVE_IMAGE": f"{repository}/node-integration:{RUNTIME}-native-{curve}",
        "ORBIS_NATIVE_VERA_IMAGE": f"{repository}/vera-native:{RUNTIME}",
    }
    for variable, image in images.items():
        subprocess.run(["docker", "pull", image], check=True)
        info = json.loads(capture(["docker", "image", "inspect", image]))[0]
        labels = info["Config"]["Labels"]
        expected = {"org.opencontainers.image.revision": VERA}
        if variable == "ORBIS_NATIVE_IMAGE":
            expected = {
                "org.opencontainers.image.revision": RUNTIME,
                "io.sourcenetwork.orbis.backend": "native",
                "io.sourcenetwork.orbis.curve": curve,
                "io.sourcenetwork.orbis.integration-features": "false",
            }
        if any(labels.get(key) != value for key, value in expected.items()):
            raise ValueError("runtime image labels do not match the selected sources")
        env[variable] = info["Id"]
    output = Path(os.environ["RUNNER_TEMP"]) / ("native-restart-" + curve)
    output.mkdir(mode=0o700, exist_ok=False)
    commands = [
        ["cargo", "test", "--release", "--locked", "-p", "test-support",
         "--no-default-features", "--lib", "container::tests::bind_mount_user_rejects_files_and_symlinks", "--", "--exact"],
        ["cargo", "nextest", "run", "--release", "--locked", "--profile", "ci",
         "--no-retries", "--test-threads", "1", "-p", "orbis-node", "--no-default-features",
         "--features", "integration-test-native,redb,iroh," + curve,
         "--test", "native_startup", "-E", "test(=native_startup_registers_and_preserves_identity_on_restart)"],
    ]
    codes = []
    for index, command in enumerate(commands):
        log = output / (str(index) + ".log")
        with log.open("x") as stream:
            os.chmod(log, 0o600)
            result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
        codes.append(result.returncode)
        print(json.dumps({"curve": curve, "stage": index, "exit_code": result.returncode}), flush=True)
        if result.returncode:
            raise RuntimeError("focused restart qualification failed; private log retained on runner")
    print(json.dumps({"curve": curve, "runtime": RUNTIME, "vera": VERA, "exit_codes": codes}), flush=True)


if __name__ == "__main__":
    qualify()
