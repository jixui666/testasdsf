#!/usr/bin/env python3
"""Split every `return ModuleOutcome(...)` into one expression per argument.

Why: the whole call is a single expression, and each argument is a chain of `String +`
(plus ternaries). The solver explores the cross-product of every `+` overload in every
argument at once and gives up with "unable to type-check this expression in reasonable
time". One `let` per argument makes each chain its own expression and leaves a call whose
arguments are bare identifiers. Semantics are identical; the `_out…` names cannot collide
with locals such as `detail: [String]` that the closures already use.

String-aware: commas, parentheses and `+` inside literals, and inside `\\( … )`
interpolations, are not treated as structure.
"""
import re
import sys

LABELS = ("headline", "detail", "evidence", "artifacts")


def scan_end(text, start):
    """Index just past the `)` that closes the call whose `(` is at `start`."""
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i = skip_string(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise SystemExit("unbalanced call at %d" % start)


def skip_string(text, i):
    """`text[i]` is a quote. Return the index just past the closing quote."""
    n = len(text)
    if text.startswith('"""', i):
        j = text.find('"""', i + 3)
        return n if j < 0 else j + 3
    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        i += 1
    return n


def split_top(text, sep):
    """Split on `sep` only at nesting depth 0 and outside literals."""
    parts, depth, cur, i = [], 0, [], 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = skip_string(text, i)
            cur.append(text[i:j])
            i = j
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if depth == 0 and text.startswith(sep, i):
            parts.append("".join(cur))
            cur = []
            i += len(sep)
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def split_label(arg):
    """`headline: expr` -> ("headline", "expr"); unlabeled -> (None, arg)."""
    pieces = split_top(arg, ":")
    if len(pieces) < 2:
        return None, arg
    label = pieces[0].strip()
    if label in LABELS:
        return label, ":".join(pieces[1:]).strip()
    return None, arg


def transform(path):
    with open(path, encoding="utf-8", newline="") as fh:
        text = fh.read()
    eol = "\r\n" if "\r\n" in text[:4096] else "\n"

    out = []
    pos = 0
    count = 0
    for m in re.finditer(r"^([ \t]*)return ModuleOutcome\(", text, re.M):
        indent = m.group(1)
        open_paren = m.end() - 1
        end = scan_end(text, open_paren)
        inner = text[open_paren + 1:end - 1]
        args = [a for a in split_top(inner, ",") if a.strip()]

        hoisted, call_args = [], []
        ok = True
        for arg in args:
            label, expr = split_label(arg)
            if label is None:
                ok = False
                break
            name = "_out" + label[0].upper() + label[1:]
            hoisted.append("%slet %s = %s" % (indent, name, expr.strip()))
            call_args.append("%s: %s" % (label, name))
        if not ok:
            continue

        out.append(text[pos:m.start()])
        out.append(eol.join(hoisted) + eol)
        out.append("%sreturn ModuleOutcome(%s)" % (indent, ", ".join(call_args)))
        pos = end
        count += 1

    if count == 0:
        return 0, eol

    out.append(text[pos:])
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("".join(out))
    return count, eol


if __name__ == "__main__":
    for path in sys.argv[1:]:
        n, eol = transform(path)
        print("%-32s rewritten=%d eol=%s" % (path, n, repr(eol)))
