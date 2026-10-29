"""A strict reader for the small YAML subset the trusted workflow files use (PLAN-177-R7 change 5).

Python's standard library has no YAML reader, and the tests must run with `python3 -I` and nothing installed.
This reader accepts only what the starters need, and refuses everything else, so a construct it does not
understand can never be read differently from how GitHub reads it:

* block mappings and block sequences, indented with spaces;
* plain, single-quoted and double-quoted scalars, all kept as strings (no type guessing);
* flow mappings and flow sequences of plain or quoted scalars, one level deep (`{ contents: read }`, `[a, b]`);
* literal block scalars (`|`, `|-`), kept byte for byte;
* comments.

Refused: tabs in indentation, anchors (`&`), aliases (`*`), tags (`!`), merge keys (`<<`), folded scalars (`>`),
documents (`---`), duplicate keys and multi-line plain or quoted scalars.
"""

import re


class YamlError(ValueError):
    pass


_KEY_RE = re.compile(r"""^(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s'"#&*!|>%@`{}\[\],:-][^:#]*?|-[^\s:#][^:#]*?)\s*:(?:\s+|$)""")


def _strip_comment(text):
    """Remove a trailing ` # comment` that is outside quotes."""
    out = []
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            out.append(ch)
            if quote == "'" and ch == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    out.append("'")
                    i += 1
                else:
                    quote = None
            elif quote == '"' and ch == "\\":
                if i + 1 < len(text):
                    out.append(text[i + 1])
                    i += 1
            elif quote == '"' and ch == '"':
                quote = None
        else:
            if ch == "#" and (i == 0 or text[i - 1] in " \t"):
                break
            if ch in "'\"" and (i == 0 or text[i - 1] in " \t[{,:"):
                quote = ch
            out.append(ch)
        i += 1
    if quote:
        raise YamlError("unterminated quoted scalar: %r" % text)
    return "".join(out).rstrip()


_DQ_ESCAPES = {"\\": "\\", '"': '"', "/": "/", "n": "\n", "t": "\t", "r": "\r", "0": "\0", "b": "\b", "f": "\f",
               "e": "\x1b", " ": " ", "a": "\a", "v": "\v"}


def _scalar(text, where):
    text = text.strip()
    if text == "":
        return None
    if text[0] in "&*!|>%@`" or text.startswith("<<") or text.startswith("---"):
        raise YamlError("%s: unsupported YAML construct: %r" % (where, text))
    if text[0] == "'":
        if len(text) < 2 or text[-1] != "'":
            raise YamlError("%s: bad single-quoted scalar" % where)
        body = text[1:-1]
        if re.search(r"(?<!')'(?!')", body.replace("''", "")):
            raise YamlError("%s: bad single-quoted scalar" % where)
        return body.replace("''", "'")
    if text[0] == '"':
        if len(text) < 2 or text[-1] != '"':
            raise YamlError("%s: bad double-quoted scalar" % where)
        body = text[1:-1]
        out = []
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == "\\":
                i += 1
                if i >= len(body):
                    raise YamlError("%s: bad escape" % where)
                esc = body[i]
                if esc in _DQ_ESCAPES:
                    out.append(_DQ_ESCAPES[esc])
                elif esc in "xuU":
                    n = {"x": 2, "u": 4, "U": 8}[esc]
                    hexpart = body[i + 1:i + 1 + n]
                    if len(hexpart) != n or not re.fullmatch(r"[0-9a-fA-F]+", hexpart):
                        raise YamlError("%s: bad escape" % where)
                    out.append(chr(int(hexpart, 16)))
                    i += n
                else:
                    raise YamlError("%s: bad escape \\%s" % (where, esc))
            elif ch == '"':
                raise YamlError("%s: bad double-quoted scalar" % where)
            else:
                out.append(ch)
            i += 1
        return "".join(out)
    if text[0] == "{":
        return _flow_mapping(text, where)
    if text[0] == "[":
        return _flow_sequence(text, where)
    if text[0] in "]},":
        raise YamlError("%s: unsupported plain scalar %r" % (where, text))
    if ": " in text or text.endswith(":"):
        raise YamlError("%s: ambiguous plain scalar %r" % (where, text))
    return text


def _split_flow(body, where):
    items = []
    cur = []
    quote = None
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch in "{}[]":
            raise YamlError("%s: nested flow collections are not supported" % where)
        elif ch == ",":
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if quote:
        raise YamlError("%s: unterminated quote in flow collection" % where)
    last = "".join(cur).strip()
    if last:
        items.append(last)
    if any(i == "" for i in items):
        raise YamlError("%s: empty flow item" % where)
    return items


def _flow_mapping(text, where):
    if not text.endswith("}"):
        raise YamlError("%s: bad flow mapping" % where)
    out = {}
    for item in _split_flow(text[1:-1], where):
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)\s*:\s+(.+)", item)
        if not m:
            raise YamlError("%s: bad flow mapping item %r" % (where, item))
        if m.group(1) in out:
            raise YamlError("%s: duplicate key %r" % (where, m.group(1)))
        out[m.group(1)] = _scalar(m.group(2), where)
    return out


def _flow_sequence(text, where):
    if not text.endswith("]"):
        raise YamlError("%s: bad flow sequence" % where)
    return [_scalar(i, where) for i in _split_flow(text[1:-1], where)]


class _Lines:
    def __init__(self, text):
        if "\t" in "".join(l[: len(l) - len(l.lstrip())] for l in text.split("\n")):
            raise YamlError("tabs in indentation")
        self.raw = text.split("\n")
        self.i = 0

    def skip_blank(self):
        while self.i < len(self.raw):
            s = self.raw[self.i].strip()
            if s == "" or s.startswith("#"):
                self.i += 1
            else:
                return
        return

    def peek(self):
        self.skip_blank()
        if self.i >= len(self.raw):
            return None
        line = self.raw[self.i]
        return len(line) - len(line.lstrip(" ")), line.strip()


def _block_scalar(lines, indicator, parent_indent, where):
    if indicator not in ("|", "|-"):
        raise YamlError("%s: only `|` and `|-` block scalars are supported" % where)
    body = []
    indent = None
    while lines.i < len(lines.raw):
        line = lines.raw[lines.i]
        if line.strip() == "":
            body.append("")
            lines.i += 1
            continue
        cur = len(line) - len(line.lstrip(" "))
        if indent is None:
            if cur <= parent_indent:
                break
            indent = cur
        if cur < indent:
            break
        body.append(line[indent:])
        lines.i += 1
    while body and body[-1] == "":
        body.pop()
    text = "\n".join(body)
    if indicator == "|" and body:
        text += "\n"
    return text


def _parse_value_after_key(lines, rest, indent, where):
    """`rest` is what follows `key:` on the same line."""
    if rest in ("|", "|-", ">", ">-", "|+", ">+"):
        return _block_scalar(lines, rest, indent, where)
    if rest != "":
        return _scalar(rest, where)
    nxt = lines.peek()
    if nxt is None:
        return None
    nindent, ntext = nxt
    if nindent > indent:
        return _parse_block(lines, nindent)
    if nindent == indent and (ntext == "-" or ntext.startswith("- ")):
        return _parse_sequence(lines, nindent)
    return None


def _parse_block(lines, indent):
    nxt = lines.peek()
    if nxt is None:
        return None
    _, text = nxt
    if text == "-" or text.startswith("- "):
        return _parse_sequence(lines, indent)
    return _parse_mapping(lines, indent)


def _parse_mapping(lines, indent, first_line=None):
    out = {}
    while True:
        if first_line is not None:
            text = first_line
            first_line = None
        else:
            nxt = lines.peek()
            if nxt is None:
                break
            cur, text = nxt
            if cur < indent:
                break
            if cur > indent:
                raise YamlError("line %d: unexpected indentation" % (lines.i + 1))
            if text == "-" or text.startswith("- "):
                break
            lines.i += 1
        where = "line %d" % lines.i
        if text.startswith("---") or text.startswith("..."):
            raise YamlError("%s: documents are not supported" % where)
        text = _strip_comment(text)
        m = _KEY_RE.match(text)
        if not m:
            raise YamlError("%s: expected `key: value`, got %r" % (where, text))
        key = _scalar(m.group("key"), where)
        if key is None or key == "<<":
            raise YamlError("%s: unsupported key" % where)
        if key in out:
            raise YamlError("%s: duplicate key %r" % (where, key))
        rest = text[m.end():].strip()
        out[key] = _parse_value_after_key(lines, rest, indent, where)
    return out


def _parse_sequence(lines, indent):
    out = []
    while True:
        nxt = lines.peek()
        if nxt is None:
            break
        cur, text = nxt
        if cur != indent or not (text == "-" or text.startswith("- ")):
            if cur > indent:
                raise YamlError("line %d: unexpected indentation" % (lines.i + 1))
            break
        lines.i += 1
        where = "line %d" % lines.i
        rest = _strip_comment(text[1:].strip()) if text != "-" else ""
        if rest == "":
            nxt2 = lines.peek()
            if nxt2 is not None and nxt2[0] > indent:
                out.append(_parse_block(lines, nxt2[0]))
            else:
                out.append(None)
            continue
        if not rest.startswith(("{", "[")) and _KEY_RE.match(rest):
            # `- key: value` starts a mapping whose keys sit at indent + 2.
            item_indent = indent + 2 + (len(text[1:]) - len(text[1:].lstrip(" ")) - 1)
            out.append(_parse_mapping(lines, item_indent, first_line=rest))
        else:
            out.append(_scalar(rest, where))
    return out


def loads(text):
    """Parse one workflow file. Returns nested dicts, lists and strings (or None)."""
    lines = _Lines(text)
    nxt = lines.peek()
    if nxt is None:
        return None
    if nxt[0] != 0:
        raise YamlError("the document must start at column 0")
    doc = _parse_block(lines, 0)
    if lines.peek() is not None:
        raise YamlError("line %d: content after the document" % (lines.i + 1))
    return doc


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return loads(f.read())
