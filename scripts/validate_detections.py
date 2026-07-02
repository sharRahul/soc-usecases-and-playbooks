#!/usr/bin/env python3
"""Validate the detection blocks embedded in the use-case files.

Walks every file in use-cases/ and checks each fenced ```kql and ```yaml
block:

- blocks must be non-empty,
- YAML blocks must load cleanly and contain a mapping,
- KQL blocks must pass a basic structural lint: balanced brackets outside
  string literals, a recognised leading statement, and a recognised operator
  after every pipe,
- every use case must contain at least one detection block.

Exits non-zero and prints one line per problem when validation fails.

Usage:
    python3 scripts/validate_detections.py
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
USE_CASES_DIR = ROOT / "use-cases"

FENCE_RE = re.compile(r"^```(kql|ya?ml)\n(.*?)^```", re.DOTALL | re.MULTILINE)
# String literals first, then // comments, so brackets and pipes inside
# strings (and slashes inside strings) do not confuse the lint.
KQL_STRING_RE = re.compile(r"@?\"(?:[^\"\\]|\\.)*\"|@?'(?:[^'\\]|\\.)*'")
KQL_COMMENT_RE = re.compile(r"//[^\n]*")

KQL_PIPE_OPERATORS = {
    "as", "consume", "count", "distinct", "evaluate", "extend", "facet",
    "fork", "getschema", "invoke", "join", "limit", "lookup", "make-series",
    "mv-apply", "mv-expand", "order", "parse", "parse-kv", "parse-where",
    "partition", "project", "project-away", "project-keep", "project-rename",
    "project-reorder", "reduce", "render", "sample", "sample-distinct",
    "scan", "search", "serialize", "sort", "summarize", "take", "top",
    "top-hitters", "top-nested", "union", "where",
}
KQL_LEADING_KEYWORDS = {"let", "union", "search", "print", "range", "datatable"}
BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}


def lint_kql(block):
    """Return a list of problems found in one KQL block."""
    problems = []
    stripped = KQL_COMMENT_RE.sub("", KQL_STRING_RE.sub('""', block))

    stack = []
    for char in stripped:
        if char in "([{":
            stack.append(char)
        elif char in BRACKET_PAIRS:
            if not stack or stack[-1] != BRACKET_PAIRS[char]:
                problems.append(f"unbalanced bracket {char!r}")
                break
            stack.pop()
    if stack and not problems:
        problems.append(f"unclosed bracket {stack[-1]!r}")

    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if not lines:
        return problems

    first_token = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", lines[0])
    if not first_token:
        problems.append(f"query does not start with a statement or table name: {lines[0]!r}")
    elif first_token.group(0) not in KQL_LEADING_KEYWORDS and not re.match(
        r"^[A-Za-z_][A-Za-z0-9_]*\s*($|\|)", lines[0]
    ):
        # Not a known keyword, so it must be a bare table reference.
        problems.append(f"unrecognised leading statement: {lines[0]!r}")

    for line in lines:
        if not line.startswith("|"):
            continue
        rest = line[1:].strip()
        operator = re.match(r"[A-Za-z][A-Za-z0-9-]*", rest)
        if not operator or operator.group(0).lower() not in KQL_PIPE_OPERATORS:
            problems.append(f"unrecognised operator after pipe: {line!r}")

    return problems


def validate_file(path):
    problems = []
    text = path.read_text(encoding="utf-8")
    blocks = FENCE_RE.findall(text)
    if not blocks:
        problems.append("no fenced kql or yaml detection blocks found")

    for index, (language, body) in enumerate(blocks, start=1):
        label = f"block {index} ({language})"
        if not body.strip():
            problems.append(f"{label}: block is empty")
            continue
        if language == "kql":
            problems.extend(f"{label}: {p}" for p in lint_kql(body))
        else:
            try:
                loaded = yaml.safe_load(body)
            except yaml.YAMLError as exc:
                problems.append(f"{label}: YAML does not parse: {exc}")
                continue
            if not isinstance(loaded, dict):
                problems.append(f"{label}: YAML must contain a mapping")
    return problems


def main():
    paths = sorted(USE_CASES_DIR.glob("UC-*.md"))
    if not paths:
        print("ERROR: no use-case files found in use-cases/", file=sys.stderr)
        sys.exit(1)

    failed = False
    checked = 0
    for path in paths:
        rel = path.relative_to(ROOT)
        problems = validate_file(path)
        checked += len(FENCE_RE.findall(path.read_text(encoding="utf-8")))
        for problem in problems:
            failed = True
            print(f"ERROR: {rel}: {problem}", file=sys.stderr)

    if failed:
        sys.exit(1)
    print(f"Validated {checked} detection blocks across {len(paths)} use cases.")


if __name__ == "__main__":
    main()
