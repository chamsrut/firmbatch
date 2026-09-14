"""A strict reader for the subset of YAML this repository's workflow files use.

PyYAML is not in either lock file, and adding a dependency to check four files would be the
wrong trade. This reader handles block mappings, block sequences, plain, single- and
double-quoted scalars, literal and folded block scalars, empty flow collections and simple
one-line flow sequences, and comments. It raises :class:`YamlError` on anything else --
anchors, aliases, tags, multi-document streams, complex keys -- so a workflow written outside
the subset fails the policy check rather than being misread.

It also fails closed wherever a real YAML parser -- GitHub's -- could read the same text differently
from this one: a quoted key (whose escapes or spelling could name a key this reader would not see,
such as a second `on`), a key that is not a plain identifier, a double-quoted scalar with an escape
other than \\" and \\\\, a plain scalar containing ": " or starting with a reserved indicator, and a
flow sequence whose items are not plainly separable.

Every scalar is returned as a string, so `on:` stays the key "on" and `true` stays "true".
"""

from __future__ import annotations

import re

__all__ = ["YamlError", "parse"]


class YamlError(ValueError):
    pass


_KEY = re.compile(r"""^(?P<key>"[^"]*"|'[^']*'|[^\s:#'"][^:#]*?)\s*:(?:\s+(?P<rest>.*))?$""")
# The only keys a workflow in this repository needs: plain identifiers. Anything else -- a quoted
# key, a merge key, an anchor or tag on a key, a key with spaces -- is outside the subset.
_PLAIN_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def _strip_comment(text: str) -> str:
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def _scalar(text: str, line_no: int) -> object:
    text = text.strip()
    if not text:
        return ""
    if text[0] in "&*!%@`" or text.startswith("---"):
        raise YamlError(f"line {line_no}: anchors, aliases, tags, directives, reserved indicators and documents are outside the subset")
    if text[0] == '"':
        if not text.endswith('"') or len(text) < 2:
            raise YamlError(f"line {line_no}: unterminated double-quoted scalar")
        body = text[1:-1]
        if re.search(r'\\(?![\\"])', body) or re.search(r'(?<!\\)"', body.replace("\\\\", "")):
            raise YamlError(f"line {line_no}: a double-quoted scalar with an escape or quote this reader does not interpret")
        return body.replace('\\"', '"').replace("\\\\", "\\")
    if text[0] == "'":
        if not text.endswith("'") or len(text) < 2:
            raise YamlError(f"line {line_no}: unterminated single-quoted scalar")
        if re.search(r"(?<!')'(?!')", text[1:-1].replace("''", "")):
            raise YamlError(f"line {line_no}: a single-quoted scalar with an unescaped quote")
        return text[1:-1].replace("''", "'")
    if text == "{}":
        return {}
    if text == "[]":
        return []
    if text[0] == "[" and text.endswith("]"):
        items = []
        for part in text[1:-1].split(","):
            item = part.strip()
            if not item:
                continue
            quoted = len(item) >= 2 and item[0] == item[-1] and item[0] in "'\""
            if any(q in (item[1:-1] if quoted else item) for q in "'\"[]{}"):
                raise YamlError(f"line {line_no}: a flow sequence whose items are not plainly separable")
            items.append(_scalar(item, line_no))
        return items
    if text[0] in "{[":
        raise YamlError(f"line {line_no}: flow collections other than {{}}, [] and one-line sequences are outside the subset")
    if ": " in text or text.endswith(":"):
        raise YamlError(f"line {line_no}: a plain scalar containing ': ', which YAML reads as a nested mapping")
    return text


class _Reader:
    def __init__(self, source: str):
        self.lines: list[tuple[int, int, str]] = []  # (line number, indent, content)
        self.raw = source.splitlines()
        for number, line in enumerate(self.raw, start=1):
            if "\t" in line[: len(line) - len(line.lstrip())]:
                raise YamlError(f"line {number}: tab indentation")
            content = _strip_comment(line)
            if not content.strip():
                continue
            self.lines.append((number, len(content) - len(content.lstrip()), content.strip()))
        self.pos = 0

    def block_scalar(self, parent_indent: int, header_line: int, style: str) -> str:
        collected = []
        raw_index = header_line  # the raw line after the header (1-based header -> index)
        indent = None
        while raw_index < len(self.raw):
            text = self.raw[raw_index]
            if text.strip():
                current = len(text) - len(text.lstrip())
                if current <= parent_indent:
                    break
                indent = current if indent is None else indent
                collected.append(text[indent:])
            else:
                collected.append("")
            raw_index += 1
        while self.pos < len(self.lines) and self.lines[self.pos][0] <= raw_index:
            self.pos += 1
        body = "\n".join(collected).rstrip("\n")
        return body if style.startswith("|") else " ".join(body.split("\n"))

    def node(self, indent: int):
        if self.pos >= len(self.lines):
            return None
        _, current, content = self.lines[self.pos]
        if current < indent:
            return None
        if content.startswith("- ") or content == "-":
            return self.sequence(current)
        return self.mapping(current)

    def mapping(self, indent: int) -> dict:
        result: dict = {}
        while self.pos < len(self.lines):
            number, current, content = self.lines[self.pos]
            if current < indent:
                break
            if current > indent:
                raise YamlError(f"line {number}: unexpected indentation")
            if content.startswith("- "):
                break
            match = _KEY.match(content)
            if not match:
                raise YamlError(f"line {number}: expected 'key: value'")
            if not _PLAIN_KEY.fullmatch(match.group("key")):
                raise YamlError(
                    f"line {number}: the key {match.group('key')!r} is quoted or not a plain identifier, "
                    "which this reader cannot safely interpret"
                )
            key = match.group("key")
            if key in result:
                raise YamlError(f"line {number}: duplicate key {key!r}")
            rest = match.group("rest")
            self.pos += 1
            if rest is None or rest == "":
                child = self.node(indent + 1)
                result[key] = "" if child is None else child
            elif rest[0] in "|>":
                if not re.fullmatch(r"[|>][+-]?", rest):
                    raise YamlError(f"line {number}: a block scalar header this reader does not interpret")
                result[key] = self.block_scalar(indent, number, rest)
            else:
                result[key] = _scalar(rest, number)
        return result

    def sequence(self, indent: int) -> list:
        result: list = []
        while self.pos < len(self.lines):
            number, current, content = self.lines[self.pos]
            if current < indent or not (content.startswith("- ") or content == "-"):
                if current > indent:
                    raise YamlError(f"line {number}: unexpected indentation")
                break
            if current > indent:
                raise YamlError(f"line {number}: unexpected indentation")
            item = content[1:].strip()
            if not item:
                self.pos += 1
                result.append(self.node(indent + 1))
                continue
            if _KEY.match(item) and item[0] not in "\"'[{":
                # A mapping that starts on the dash line: re-read it at the item's own indent.
                item_indent = current + (len(content) - len(item))
                self.lines[self.pos] = (number, item_indent, item)
                result.append(self.mapping(item_indent))
                continue
            if item[0] in "\"'" and _KEY.match(item):
                raise YamlError(f"line {number}: a quoted key on a sequence item, which this reader cannot safely interpret")
            self.pos += 1
            result.append(_scalar(item, number))
        return result


def parse(source: str):
    reader = _Reader(source)
    if not reader.lines:
        return {}
    document = reader.node(reader.lines[0][1])
    if reader.pos != len(reader.lines):
        raise YamlError(f"line {reader.lines[reader.pos][0]}: content after the document")
    return document
