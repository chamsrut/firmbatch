"""A small, strict reader for the HCL this repository writes.

This is not a general HCL implementation. It reads block structure, attribute assignments
and literal values -- strings, numbers, booleans, null, tuples, objects and function calls
over them -- well enough for the repository's structural policy checks. An expression it
does not model (a reference, an operator, a conditional, a `for` expression) is returned as
:class:`Raw`, carrying its exact source text, so a check can still match on it.

It raises :class:`HclError` on anything it cannot tokenize. A construct the reader does not
understand therefore fails the check that asked, rather than being skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["Block", "Call", "HclError", "Raw", "Template", "parse", "parse_file"]


class HclError(ValueError):
    """The source could not be read."""


class Raw(str):
    """An expression the reader does not evaluate; the value is its source text."""


class Template(str):
    """A quoted string containing an interpolation; the value is its unescaped body."""


@dataclass(frozen=True)
class Call:
    name: str
    args: tuple


@dataclass
class Block:
    type: str
    labels: list[str]
    attributes: dict[str, object] = field(default_factory=dict)
    raw_attributes: dict[str, str] = field(default_factory=dict)
    blocks: list["Block"] = field(default_factory=list)
    line: int = 0

    def children(self, block_type: str, *labels: str) -> list["Block"]:
        return [
            b for b in self.blocks
            if b.type == block_type and list(b.labels[: len(labels)]) == list(labels)
        ]

    def walk(self):
        yield self
        for child in self.blocks:
            yield from child.walk()


@dataclass(frozen=True)
class _Token:
    kind: str  # ident | string | heredoc | number | punct | op | newline
    text: str
    start: int
    end: int
    line: int


_OPERATORS = ("==", "!=", "<=", ">=", "&&", "||", "=>", "...")
_PUNCT = "{}[]()=,:?"


def _scan_interpolation(source: str, index: int, line: int) -> int:
    """Return the index just past the `}` closing an interpolation opened before `index`."""
    depth = 1
    n = len(source)
    while index < n:
        ch = source[index]
        if ch == '"':
            index = _scan_string(source, index, line)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise HclError(f"line {line}: unterminated interpolation")


def _scan_string(source: str, index: int, line: int) -> int:
    """Return the index just past the closing quote of the string starting at `index`."""
    n = len(source)
    j = index + 1
    while j < n:
        ch = source[j]
        if ch == "\\":
            j += 2
            continue
        if ch == '"':
            return j + 1
        if ch == "\n":
            raise HclError(f"line {line}: newline inside a quoted string")
        if source.startswith(("$${", "%%{"), j):
            j += 3
            continue
        if source.startswith(("${", "%{"), j):
            j = _scan_interpolation(source, j + 2, line)
            continue
        j += 1
    raise HclError(f"line {line}: unterminated string")


_HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def _tokenize(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    i, n, line = 0, len(source), 1
    while i < n:
        c = source[i]
        if c == "\n":
            tokens.append(_Token("newline", "\n", i, i + 1, line))
            line += 1
            i += 1
            continue
        if c in " \t\r":
            i += 1
            continue
        if c == "#" or source.startswith("//", i):
            j = source.find("\n", i)
            i = n if j == -1 else j
            continue
        if source.startswith("/*", i):
            j = source.find("*/", i + 2)
            if j == -1:
                raise HclError(f"line {line}: unterminated block comment")
            line += source.count("\n", i, j)
            i = j + 2
            continue
        heredoc = _HEREDOC.match(source, i)
        if heredoc:
            marker = heredoc.group(2)
            pos = heredoc.end()
            body_start = pos
            while True:
                j = source.find("\n", pos)
                end = n if j == -1 else j
                if source[pos:end].strip() == marker:
                    break
                if j == -1:
                    raise HclError(f"line {line}: unterminated heredoc {marker}")
                pos = j + 1
            tokens.append(_Token("heredoc", source[body_start:pos], i, end, line))
            line += source.count("\n", i, end)
            i = end
            continue
        if c == '"':
            j = _scan_string(source, i, line)
            tokens.append(_Token("string", source[i:j], i, j, line))
            line += source.count("\n", i, j)
            i = j
            continue
        ident = _IDENT.match(source, i)
        if ident:
            tokens.append(_Token("ident", ident.group(0), i, ident.end(), line))
            i = ident.end()
            continue
        number = _NUMBER.match(source, i)
        if number:
            tokens.append(_Token("number", number.group(0), i, number.end(), line))
            i = number.end()
            continue
        operator = next((op for op in _OPERATORS if source.startswith(op, i)), None)
        if operator:
            tokens.append(_Token("op", operator, i, i + len(operator), line))
            i += len(operator)
            continue
        if c in _PUNCT:
            tokens.append(_Token("punct", c, i, i + 1, line))
            i += 1
            continue
        if c in ".*/%+-<>!":
            tokens.append(_Token("op", c, i, i + 1, line))
            i += 1
            continue
        raise HclError(f"line {line}: unexpected character {c!r}")
    return tokens


_OPEN = {"{": "}", "[": "]", "(": ")"}


def _unquote(text: str) -> str:
    body = text[1:-1]
    return re.sub(r'\\(["\\nrt])', lambda m: {"n": "\n", "r": "\r", "t": "\t"}.get(m.group(1), m.group(1)), body)


class _Parser:
    def __init__(self, source: str):
        self.source = source
        self.tokens = _tokenize(source)

    # ---------------------------------------------------------------- bodies

    def body(self, pos: int, closing: bool) -> tuple[Block, int]:
        block = Block(type="", labels=[])
        tokens = self.tokens
        while True:
            while pos < len(tokens) and tokens[pos].kind == "newline":
                pos += 1
            if pos >= len(tokens):
                if closing:
                    raise HclError("unexpected end of file inside a block")
                return block, pos
            tok = tokens[pos]
            if closing and tok.kind == "punct" and tok.text == "}":
                return block, pos + 1
            if tok.kind != "ident":
                raise HclError(f"line {tok.line}: expected an attribute or block, found {tok.text!r}")
            if pos + 1 < len(tokens) and tokens[pos + 1].kind == "punct" and tokens[pos + 1].text == "=":
                start = pos + 2
                end = self._expression_end(start, closing)
                if end == start:
                    raise HclError(f"line {tok.line}: attribute {tok.text} has no value")
                if tok.text in block.attributes:
                    raise HclError(f"line {tok.line}: duplicate attribute {tok.text}")
                block.raw_attributes[tok.text] = self.source[tokens[start].start:tokens[end - 1].end]
                block.attributes[tok.text] = self.value(start, end)
                pos = end
                continue
            labels: list[str] = []
            j = pos + 1
            while j < len(tokens) and tokens[j].kind in ("string", "ident"):
                labels.append(_unquote(tokens[j].text) if tokens[j].kind == "string" else tokens[j].text)
                j += 1
            if j >= len(tokens) or tokens[j].kind != "punct" or tokens[j].text != "{":
                raise HclError(f"line {tok.line}: expected '{{' to open block {tok.text}")
            child, pos = self.body(j + 1, closing=True)
            child.type, child.labels, child.line = tok.text, labels, tok.line
            block.blocks.append(child)

    def _expression_end(self, pos: int, closing: bool) -> int:
        depth: list[str] = []
        tokens = self.tokens
        while pos < len(tokens):
            tok = tokens[pos]
            if tok.kind == "punct" and tok.text in _OPEN:
                depth.append(_OPEN[tok.text])
            elif tok.kind == "punct" and tok.text in "}])":
                if not depth:
                    if closing and tok.text == "}":
                        return pos
                    raise HclError(f"line {tok.line}: unbalanced {tok.text!r}")
                if depth.pop() != tok.text:
                    raise HclError(f"line {tok.line}: mismatched {tok.text!r}")
            elif tok.kind == "newline" and not depth:
                return pos
            pos += 1
        if depth:
            raise HclError("unexpected end of file inside an expression")
        return pos

    # ---------------------------------------------------------------- values

    def _split(self, start: int, end: int) -> list[tuple[int, int]]:
        """Split [start, end) into items separated by top-level commas or newlines."""
        items, depth, item_start = [], 0, start
        for i in range(start, end):
            tok = self.tokens[i]
            if tok.kind == "punct" and tok.text in _OPEN:
                depth += 1
            elif tok.kind == "punct" and tok.text in "}])":
                depth -= 1
            elif depth == 0 and (tok.kind == "newline" or (tok.kind == "punct" and tok.text == ",")):
                if i > item_start:
                    items.append((item_start, i))
                item_start = i + 1
        if end > item_start:
            items.append((item_start, end))
        return [(a, b) for a, b in items if any(t.kind != "newline" for t in self.tokens[a:b])]

    def _raw(self, start: int, end: int) -> Raw:
        return Raw(self.source[self.tokens[start].start:self.tokens[end - 1].end])

    def _closes_at_end(self, open_index: int, end: int) -> bool:
        depth = 0
        for i in range(open_index, end):
            tok = self.tokens[i]
            if tok.kind == "punct" and tok.text in _OPEN:
                depth += 1
            elif tok.kind == "punct" and tok.text in "}])":
                depth -= 1
                if depth == 0:
                    return i == end - 1
        return False

    def value(self, start: int, end: int):
        while start < end and self.tokens[start].kind == "newline":
            start += 1
        while end > start and self.tokens[end - 1].kind == "newline":
            end -= 1
        if start >= end:
            raise HclError("empty expression")
        first = self.tokens[start]
        if end - start == 1:
            if first.kind == "string":
                body = _unquote(first.text)
                return Template(body) if re.search(r"(?<![$%])[$%]\{", first.text) else body
            if first.kind == "heredoc":
                return first.text
            if first.kind == "number":
                return float(first.text) if any(ch in first.text for ch in ".eE") else int(first.text)
            if first.kind == "ident" and first.text in ("true", "false"):
                return first.text == "true"
            if first.kind == "ident" and first.text == "null":
                return None
            return self._raw(start, end)
        if first.kind == "punct" and first.text == "[" and self._closes_at_end(start, end):
            inner = self.tokens[start + 1]
            if inner.kind == "ident" and inner.text == "for":
                return self._raw(start, end)
            return tuple(self.value(a, b) for a, b in self._split(start + 1, end - 1))
        if first.kind == "punct" and first.text == "{" and self._closes_at_end(start, end):
            inner = next((t for t in self.tokens[start + 1:end] if t.kind != "newline"), None)
            if inner is not None and inner.kind == "ident" and inner.text == "for":
                return self._raw(start, end)
            return self._object(start + 1, end - 1)
        if (
            first.kind == "ident"
            and self.tokens[start + 1].kind == "punct"
            and self.tokens[start + 1].text == "("
            and self._closes_at_end(start + 1, end)
        ):
            args = tuple(self.value(a, b) for a, b in self._split(start + 2, end - 1))
            return Call(first.text, args)
        return self._raw(start, end)

    def _object(self, start: int, end: int) -> dict:
        result: dict = {}
        for a, b in self._split(start, end):
            sep = next(
                (
                    i for i in range(a, b)
                    if self.tokens[i].kind == "punct" and self.tokens[i].text in "=:"
                ),
                None,
            )
            if sep is None or sep == a:
                raise HclError(f"line {self.tokens[a].line}: object item without a key")
            key_tokens = self.tokens[a:sep]
            if len(key_tokens) == 1 and key_tokens[0].kind == "string":
                key = _unquote(key_tokens[0].text)
            elif len(key_tokens) == 1 and key_tokens[0].kind == "ident":
                key = key_tokens[0].text
            else:
                key = Raw(self.source[key_tokens[0].start:key_tokens[-1].end])
            result[key] = self.value(sep + 1, b)
        return result


def parse(source: str) -> Block:
    """Parse HCL source into a root :class:`Block` whose children are its top-level blocks."""
    parser = _Parser(source)
    root, _ = parser.body(0, closing=False)
    root.type = "<root>"
    return root


def parse_file(path) -> Block:
    with open(path, encoding="utf-8") as handle:
        return parse(handle.read())
