"""A small evaluator for the GitHub Actions expressions the trusted workflow files use.

It covers literals (strings, numbers, true, false, null), context property access (`github.event.action`),
`!`, `==`, `!=`, `&&`, `||`, parentheses, and the status functions `always()`, `success()`, `failure()` and
`cancelled()`. Comparison and truthiness follow GitHub's documented rules: values of different types are compared
as numbers (null is 0, booleans are 1 and 0, strings are parsed, objects are NaN), strings compare without case,
and `&&` / `||` return one of their operands. Anything else raises an error, so a test never passes on an
expression this evaluator does not understand.
"""

import math
import re

_TOKEN_RE = re.compile(r"""\s*(?:
    (?P<str>'(?:[^']|'')*')
  | (?P<num>-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?))
  | (?P<op>==|!=|&&|\|\||!|\(|\)|\.)
  | (?P<name>[A-Za-z_][A-Za-z0-9_-]*)
)""", re.X)


class ExprError(ValueError):
    pass


def _tokens(text):
    pos = 0
    out = []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise ExprError("cannot read expression at %r" % text[pos:])
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


def _to_number(v):
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return 0.0
        try:
            if re.fullmatch(r"-?0x[0-9a-fA-F]+", s):
                return float(int(s, 16))
            return float(s)
        except ValueError:
            return math.nan
    return math.nan


def truthy(v):
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return not (v == 0 or math.isnan(v))
    if isinstance(v, str):
        return v != ""
    return True


def loose_equal(a, b):
    if type(a) is type(b) or (isinstance(a, (int, float)) and isinstance(b, (int, float))
                                and not isinstance(a, bool) and not isinstance(b, bool)):
        if isinstance(a, str):
            return a.lower() == b.lower()
        if isinstance(a, (dict, list)):
            return a is b
        if isinstance(a, float) and math.isnan(a):
            return False
        return a == b
    na, nb = _to_number(a), _to_number(b)
    if math.isnan(na) or math.isnan(nb):
        return False
    return na == nb


class _Parser:
    def __init__(self, tokens, contexts, status):
        self.t = tokens
        self.i = 0
        self.ctx = contexts
        self.status = status
        self.used_status = False

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, value=None):
        tok = self.peek()
        if tok[0] is None or (value is not None and tok[1] != value):
            raise ExprError("expected %r, got %r" % (value, tok[1]))
        self.i += 1
        return tok

    def parse(self):
        v = self.or_()
        if self.i != len(self.t):
            raise ExprError("unexpected %r" % (self.peek()[1],))
        return v

    def or_(self):
        v = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            rhs = self.and_()
            v = v if truthy(v) else rhs
        return v

    def and_(self):
        v = self.eq()
        while self.peek() == ("op", "&&"):
            self.take()
            rhs = self.eq()
            v = rhs if truthy(v) else v
        return v

    def eq(self):
        v = self.unary()
        while self.peek() in (("op", "=="), ("op", "!=")):
            op = self.take()[1]
            rhs = self.unary()
            v = loose_equal(v, rhs) if op == "==" else not loose_equal(v, rhs)
        return v

    def unary(self):
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.unary())
        return self.primary()

    def primary(self):
        kind, val = self.peek()
        if kind == "op" and val == "(":
            self.take()
            v = self.or_()
            self.take(")")
            return v
        if kind == "str":
            self.take()
            return val[1:-1].replace("''", "'")
        if kind == "num":
            self.take()
            return _to_number(val)
        if kind == "name":
            self.take()
            low = val.lower()
            if low == "true":
                return True
            if low == "false":
                return False
            if low == "null":
                return None
            if self.peek() == ("op", "("):
                self.take()
                self.take(")")
                if low not in ("always", "success", "failure", "cancelled"):
                    raise ExprError("unsupported function %s()" % val)
                self.used_status = True
                if low == "always":
                    return True
                return self.status == low
            if val not in self.ctx:
                raise ExprError("unknown context %r" % val)
            v = self.ctx[val]
            while self.peek() == ("op", "."):
                self.take()
                k, name = self.take()
                if k != "name":
                    raise ExprError("bad property access")
                v = v.get(name) if isinstance(v, dict) else None
            return v
        raise ExprError("unexpected %r" % (val,))


def evaluate(text, contexts, status="success"):
    """Evaluate a bare expression (no `${{ }}`). `status` is the job status for the status functions."""
    p = _Parser(_tokens(text), contexts, status)
    v = p.parse()
    return v, p.used_status


def evaluate_if(text, contexts, status="success"):
    """Evaluate an `if:` condition as GitHub does: with no status function, `success() &&` is implied."""
    if text is None:
        return status == "success"
    t = text.strip()
    if t.startswith("${{") and t.endswith("}}"):
        t = t[3:-2]
    v, used = evaluate(t, contexts, status)
    if not used and status != "success":
        return False
    return truthy(v)


_INTERP_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def interpolate(text, contexts):
    """Replace every `${{ expr }}` in a string value."""
    if text is None:
        return None

    def rep(m):
        v, _ = evaluate(m.group(1), contexts)
        if v is None:
            return ""
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, float) and v.is_integer():
            return str(int(v))
        if isinstance(v, (dict, list)):
            raise ExprError("cannot interpolate an object")
        return str(v)

    return _INTERP_RE.sub(rep, text)
