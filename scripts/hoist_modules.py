#!/usr/bin/env python3
"""Hoist every ExploitModule literal out of its array and into its own declaration.

Why: `static let x: [ExploitModule] = [ ExploitModule(...), ... ]` is one expression. With
closures of this size the Swift solver gives up ("unable to type-check this expression in
reasonable time") on both 6.0 and 6.2. One declaration per module gives the solver one
expression per module, which is exactly what the diagnostic asks for. Element order and the
array contents are preserved, so nothing observable changes.

Newline-agnostic: the working tree may hold CRLF while the blob is LF.
"""
import re
import sys

DECL = re.compile(r'^(\s*)static (let|var) (\w+): \[ExploitModule\] = \[$')


def sanitize(module_id: str) -> str:
    return "m_" + re.sub(r'[^0-9A-Za-z_]', '_', module_id)


def transform(path: str) -> tuple[int, int, str]:
    with open(path, encoding="utf-8", newline="") as fh:
        text = fh.read()

    eol = "\r\n" if "\r\n" in text.split("\n", 1)[0] or "\r\n" in text[:4096] else "\n"
    lines = text.splitlines(keepends=True)
    body = lambda raw: raw.rstrip("\r\n")

    out: list[str] = []
    i = 0
    arrays = 0
    hoisted = 0

    while i < len(lines):
        m = DECL.match(body(lines[i]))
        if not m:
            out.append(lines[i])
            i += 1
            continue

        indent, kind, name = m.group(1), m.group(2), m.group(3)
        body_indent = indent + "    "      # element start: indent + 4
        closer_indent = indent + "        "  # element end: indent + 8
        # the original `= [` line is dropped: the one-line array replaces it, and the
        # hoisted declarations have to be emitted *before* that line.
        i += 1
        arrays += 1

        pending: list[str] = []       # hoisted declarations, in order
        symbols: list[str] = []
        carry: list[str] = []         # comments / blank lines between elements

        closed = False
        while i < len(lines):
            raw = lines[i]
            stripped = body(raw).strip()

            if stripped == "]" and body(raw).startswith(indent):
                out.extend(pending)
                out.extend(carry)
                out.append("%sstatic %s %s: [ExploitModule] = [%s]%s"
                           % (indent, kind, name, ", ".join(symbols), eol))
                i += 1
                closed = True
                break

            if body(raw) == body_indent + "ExploitModule(":
                start = i
                j = i + 1
                close = None
                while j < len(lines):
                    if body(lines[j]) == closer_indent + "}),":
                        close = j
                        break
                    j += 1
                if close is None:
                    raise SystemExit("unterminated element in %s at line %d" % (path, start + 1))

                span = "".join(lines[start:close + 1])
                idm = re.search(r'\bid: "([^"]+)"', span)
                if not idm:
                    raise SystemExit("no module id in %s at line %d" % (path, start + 1))
                symbol = sanitize(idm.group(1))
                if symbol in symbols:
                    raise SystemExit("duplicate symbol %s in %s" % (symbol, path))

                pending.extend(carry)
                carry = []
                pending.append("%sprivate static let %s: ExploitModule = ExploitModule(%s"
                               % (indent, symbol, eol))
                pending.extend(lines[start + 1:close])
                pending.append(closer_indent + "})" + eol)
                symbols.append(symbol)
                hoisted += 1
                i = close + 1
                continue

            if stripped == "" or stripped.startswith("//"):
                carry.append(raw)
            else:
                raise SystemExit("unexpected line in %s: %r" % (path, stripped))
            i += 1

        if not closed:
            raise SystemExit("array %s never closed in %s" % (name, path))

    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("".join(out))
    return arrays, hoisted, eol


if __name__ == "__main__":
    total_a = total_m = 0
    for path in sys.argv[1:]:
        a, h, eol = transform(path)
        total_a += a
        total_m += h
        print("%-32s arrays=%-3d hoisted=%-3d eol=%s" % (path, a, h, repr(eol)))
    print("total: %d arrays, %d declarations" % (total_a, total_m))
