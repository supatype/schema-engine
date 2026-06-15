#!/usr/bin/env python3
"""Convert inline v1 schema JSON in Rust test files to AST v2."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Reuse fixture converter logic
sys.path.insert(0, str(Path(__file__).parent))
from convert_fixture_v2 import convert_schema  # type: ignore


RAW_JSON_RE = re.compile(
    r'r#"(?P<body>\{.*?\})"#',
    re.DOTALL,
)


def convert_body(body: str) -> str | None:
    body = body.strip()
    if not body.startswith("{"):
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "models" not in data:
        return None
    if data.get("astVersion") == 2:
        return None
    return json.dumps(convert_schema(data), indent=2)


def convert_file(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    changed = False

    def repl(m: re.Match[str]) -> str:
        nonlocal changed
        body = m.group("body")
        new_body = convert_body(body)
        if new_body is None:
            return m.group(0)
        changed = True
        return f'r#"{new_body}"#'

    new_text = RAW_JSON_RE.sub(repl, text)
    if changed:
        path.write_text(new_text, encoding="utf-8")
    return changed


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    for pattern in ("tests/**/*.rs", "src/**/*.rs"):
        for path in root.glob(pattern):
            if convert_file(path):
                print("converted", path.relative_to(root))


if __name__ == "__main__":
    main()
