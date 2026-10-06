#!/usr/bin/env python3
"""Report exact Common library results without exposing compiler or test logs."""

from pathlib import Path
import re
import sys

path, backend, expected = sys.argv[1:]
if backend not in ("cosmos", "shared"):
    raise SystemExit(2)
results = re.findall(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
    Path(path).read_text(),
)
if results != [(expected, "0", "0", "0", "0")]:
    print(f"common backend={backend} results=invalid", file=sys.stderr)
    raise SystemExit(1)
print(f"common backend={backend} passed={expected} failed=0 ignored=0")
