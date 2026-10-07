#!/usr/bin/env python3
"""Report Common checks without exposing compiler messages or test logs."""

import json
from pathlib import Path
import re
import sys


def diagnostics(path, backend):
    source = {str(p) for p in Path("crates/common/src").rglob("*.rs")}
    result = []
    seen = set()
    with path.open(encoding="utf-8", errors="replace") as stream:
        while len(result) < 16:
            line = stream.readline(1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 1024 * 1024:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict) or event.get("reason") != "compiler-message":
                continue
            message = event.get("message")
            if not isinstance(message, dict) or message.get("level") != "error":
                continue
            code = message.get("code")
            if not isinstance(code, dict):
                continue
            code = code.get("code")
            if not isinstance(code, str) or not re.fullmatch(r"E[0-9]{4}|clippy::[a-z_]+", code):
                continue
            spans = message.get("spans", [])
            if not isinstance(spans, list):
                continue
            for span in spans:
                if not isinstance(span, dict) or span.get("is_primary") is not True:
                    continue
                name, number = span.get("file_name"), span.get("line_start")
                if not isinstance(name, str) or type(number) is not int or not 0 < number < 1_000_000:
                    continue
                if name not in source:
                    name = "crates/common/" + name
                if name not in source:
                    continue
                key = (code, name, number)
                if key not in seen:
                    seen.add(key)
                    result.append({"code": code, "file": name, "line": number})
                if len(result) == 16:
                    break
    print(json.dumps({"backend": backend, "diagnostics": result}, sort_keys=True))


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--diagnostics":
        path, backend = sys.argv[2:]
        if backend not in ("cosmos", "shared"):
            return 2
        diagnostics(Path(path), backend)
        return 0
    if len(sys.argv) != 4:
        return 2
    path, backend, expected = sys.argv[1:]
    if backend not in ("cosmos", "shared"):
        return 2
    results = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
        Path(path).read_text(),
    )
    if results != [(expected, "0", "0", "0", "0")]:
        print(f"common backend={backend} results=invalid", file=sys.stderr)
        return 1
    print(f"common backend={backend} passed={expected} failed=0 ignored=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
