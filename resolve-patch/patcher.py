#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path
from dataclasses import dataclass

SYMBOL = r'[-a-zA-Z$._][-a-zA-Z$._0-9]*'

FUNC_RE = re.compile(rf'^\s*define\b.*@(?P<name>{SYMBOL})\s*\(')
DECLARE_RE = re.compile(rf'^\s*declare\b.*@(?P<name>{SYMBOL})\s*\(')
GLOBAL_RE = re.compile(rf'^\s*@(?P<name>{SYMBOL})\s*=')
PATCH_MARKER_RE = re.compile(r'^\s*;\s*resolve\.patch\.replace\s*$')


@dataclass
class Item:
    kind: str
    name: str | None
    text: str
    replace: bool = False


def brace_delta(line: str) -> int:
    code = line.split(";", 1)[0]
    return code.count("{") - code.count("}")


def parse_ir(text: str) -> list[Item]:
    lines = text.splitlines(keepends=True)
    items: list[Item] = []

    pending: list[str] = []
    replace_next_func = False
    i = 0

    while i < len(lines):
        line = lines[i]

        if PATCH_MARKER_RE.match(line):
            replace_next_func = True
            pending.append(line)
            i += 1
            continue

        m = FUNC_RE.match(line)
        if m:
            name = m.group("name")

            prefix = ""
            if pending:
                prefix = "".join(pending)
                pending.clear()

            buf = [prefix, line]
            depth = brace_delta(line)
            i += 1

            while i < len(lines) and depth > 0:
                buf.append(lines[i])
                depth += brace_delta(lines[i])
                i += 1

            if depth != 0:
                raise ValueError(f"unterminated function @{name}")

            items.append(Item("func", name, "".join(buf), replace_next_func))
            replace_next_func = False
            continue

        m = DECLARE_RE.match(line)
        if m:
            if pending:
                items.append(Item("text", None, "".join(pending)))
                pending.clear()

            items.append(Item("declare", m.group("name"), line))
            i += 1
            continue

        m = GLOBAL_RE.match(line)
        if m:
            if pending:
                items.append(Item("text", None, "".join(pending)))
                pending.clear()

            items.append(Item("global", m.group("name"), line))
            i += 1
            continue

        pending.append(line)
        i += 1

    if pending:
        items.append(Item("text", None, "".join(pending)))

    return items


def strip_patch_marker(text: str) -> str:
    return "".join(
        line
        for line in text.splitlines(keepends=True)
        if not PATCH_MARKER_RE.match(line)
    )


def merge(input_ir: str, patch_ir: str) -> str:
    input_items = parse_ir(input_ir)
    patch_items = parse_ir(patch_ir)

    replacements = {
        item.name: item
        for item in patch_items
        if item.kind == "func" and item.replace
    }

    if not replacements:
        raise ValueError("patch contains no marked replacement functions")

    input_funcs = {
        item.name
        for item in input_items
        if item.kind == "func"
    }

    missing = sorted(set(replacements) - input_funcs)
    if missing:
        raise ValueError(
            "replacement target(s) not found in input: "
            + ", ".join(f"@{name}" for name in missing)
        )

    emitted_funcs = set()
    emitted_decls = set()
    emitted_globals = set()

    out: list[str] = []

    for item in input_items:
        if item.kind == "func" and item.name in replacements:
            out.append(strip_patch_marker(replacements[item.name].text))
            emitted_funcs.add(item.name)
            continue

        out.append(item.text)

        if item.kind == "func" and item.name:
            emitted_funcs.add(item.name)
        elif item.kind == "declare" and item.name:
            emitted_decls.add(item.name)
        elif item.kind == "global" and item.name:
            emitted_globals.add(item.name)

    # Append patch helpers/globals/declarations.
    for item in patch_items:
        if item.kind == "func" and item.replace:
            continue

        if item.kind == "text":
            # Skip patch module headers/comments/preamble.
            continue

        if item.kind == "func":
            if item.name in emitted_funcs:
                continue
            emitted_funcs.add(item.name)

        elif item.kind == "declare":
            if item.name in emitted_funcs or item.name in emitted_decls:
                continue
            emitted_decls.add(item.name)

        elif item.kind == "global":
            if item.name in emitted_globals:
                continue
            emitted_globals.add(item.name)

        if out and not out[-1].endswith("\n\n"):
            out.append("\n")

        out.append(strip_patch_marker(item.text))

    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve LLVM IR patch merger")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-p", "--patch", required=True)
    parser.add_argument("-o", "--output", default="resolve-patched.ll")
    args = parser.parse_args()

    try:
        input_ir = Path(args.input).read_text()
        patch_ir = Path(args.patch).read_text()
        merged = merge(input_ir, patch_ir)
        Path(args.output).write_text(merged)
    except Exception as e:
        print(f"resolve-patch: error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())