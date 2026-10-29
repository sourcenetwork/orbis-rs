#!/usr/bin/env python3
"""Read the immutable native Vera image revision from the SDK manifests."""
from pathlib import Path
import re

MANIFESTS = ("bin/cli-tool/Cargo.toml", "bin/orbis-node/Cargo.toml",
             "crates/authz/Cargo.toml", "crates/bulletin/Cargo.toml", "crates/test-support/Cargo.toml")

def revision(root, repository="vera.rs", manifests=MANIFESTS):
    pins = []
    if repository == "vera.rs":
        manifests = ("Cargo.toml",)
    for name in manifests:
        declarations = [line for line in (root / name).read_text().splitlines()
                        if f'git = "https://github.com/sourcenetwork/{repository}"' in line]
        if not declarations:
            raise ValueError("missing native SDK declarations")
        for line in declarations:
            match = re.search(r'rev = "([0-9a-f]{40})"', line)
            if match is None:
                raise ValueError("native SDK revision must be immutable")
            pins.append(match[1])
    if len(set(pins)) != 1:
        raise ValueError("native SDK revisions disagree")
    return pins[0]

if __name__ == "__main__":
    print(revision(Path(__file__).resolve().parents[1]))
