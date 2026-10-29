"""A small, strict lint for the bash in the trusted workflows' `run:` blocks (PLAN-177-R7 change 5, shell safety).

File and folder names come from the pull request, so the rules are:
* no unquoted expansion (`$x`, `${x}`, `$(...)`) and no backticks; arithmetic `$(( ))` is allowed;
* lists are NUL-delimited: `find` uses `-print0`, `git ls-files` uses `-z`, `read` uses `-d ''`, `xargs` uses `-0`,
  `sort` and `uniq` use `-z`; `ls`, `mapfile` and `readarray` are not used;
* a path argument that comes from a variable is passed after `--` (mv, cp, rm, cat, head, strings, ...);
* every direct `git` command carries `-c core.attributesFile=/dev/null`;
* no `eval`, `source` or `.`; heredocs are quoted (`<<'PY'`), so their bodies are never expanded.

It is a lint for code we write, not a full shell parser: anything it cannot read is reported, never skipped.
"""

import re

PATH_CMDS = {"mv", "cp", "rm", "cat", "head", "tail", "strings", "realpath", "readlink", "ln", "chmod", "chown",
             "mkdir", "touch", "stat", "du", "wc", "sha256sum", "file"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "case", "esac", "!", "{", "}",
            "time", "in"}
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")


class Script:
    def __init__(self):
        self.segments = []  # list of lists of raw words
        self.problems = []  # (message)


def lint(text, script=None, _depth=0):
    """Return a Script with segments and problems for one bash script."""
    s = script or Script()
    _Lexer(text, s, _depth).run()
    return s


class _Lexer:
    def __init__(self, text, script, depth):
        self.t = text
        self.i = 0
        self.s = script
        self.depth = depth
        self.words = []
        self.word = None  # list of chars, or None between words
        self.pending_heredocs = []
        self.redirect_next = False

    # -- helpers -------------------------------------------------------------------------------------------------
    def problem(self, msg):
        line = self.t.count("\n", 0, self.i) + 1
        self.s.problems.append("line %d: %s" % (line, msg))

    def start_word(self):
        if self.word is None:
            self.word = []

    def end_word(self):
        if self.word is not None:
            w = "".join(self.word)
            if self.redirect_next:
                self.redirect_next = False
            else:
                self.words.append(w)
            self.word = None

    def end_segment(self):
        self.end_word()
        if self.words:
            self.s.segments.append(self.words)
        self.words = []

    def peek(self, n=0):
        j = self.i + n
        return self.t[j] if j < len(self.t) else ""

    # -- main loop -----------------------------------------------------------------------------------------------
    def run(self):
        t = self.t
        while self.i < len(t):
            ch = t[self.i]
            if ch == "\n":
                self.end_segment()
                self.i += 1
                if self.pending_heredocs:
                    self.skip_heredocs()
                continue
            if ch in " \t":
                self.end_word()
                self.i += 1
                continue
            if ch == "#" and self.word is None:
                while self.i < len(t) and t[self.i] != "\n":
                    self.i += 1
                continue
            if ch == "\\":
                self.start_word()
                self.word.append(t[self.i:self.i + 2])
                self.i += 2
                continue
            if ch == "'":
                self.start_word()
                j = t.find("'", self.i + 1)
                if j < 0:
                    self.problem("unterminated single quote")
                    return
                self.word.append(t[self.i:j + 1])
                self.i = j + 1
                continue
            if ch == '"':
                self.start_word()
                self.double_quoted()
                continue
            if ch == "`":
                self.problem("backticks are not allowed; use \"$(...)\"")
                self.i += 1
                continue
            if ch == "$":
                self.start_word()
                self.dollar(quoted=False)
                continue
            if ch in ";&|()":
                two = t[self.i:self.i + 2]
                if ch == "&" and two == "&>":
                    self.end_word()
                    self.redirect_next = True
                    self.i += 2
                    continue
                self.end_segment()
                self.i += 2 if two in ("&&", "||", ";;") else 1
                continue
            if ch in "<>":
                self.redirect()
                continue
            if ch.isdigit() and self.word is None and self.peek(1) in "<>":
                self.i += 1
                self.redirect()
                continue
            self.start_word()
            self.word.append(ch)
            self.i += 1
        self.end_segment()
        if self.pending_heredocs:
            self.problem("unterminated heredoc")

    def redirect(self):
        t = self.t
        self.end_word()
        if t.startswith("<<<", self.i):
            self.i += 3
            self.redirect_next = True
            return
        if t.startswith("<<", self.i):
            self.i += 2
            if self.peek() == "-":
                self.i += 1
            while self.peek() in " \t":
                self.i += 1
            m = re.match(r"'([A-Za-z_][A-Za-z0-9_]*)'|\"([A-Za-z_][A-Za-z0-9_]*)\"|([A-Za-z_][A-Za-z0-9_]*)", t[self.i:])
            if not m:
                self.problem("cannot read heredoc delimiter")
                return
            if m.group(3):
                self.problem("unquoted heredoc <<%s: quote the delimiter" % m.group(3))
            self.pending_heredocs.append(m.group(1) or m.group(2) or m.group(3))
            self.i += m.end()
            return
        if t.startswith("<(", self.i) or t.startswith(">(", self.i):
            self.problem("process substitution is not allowed; write the list to a file first")
            self.i += 2
            return
        self.i += 1
        if self.peek() in (">", "&", "|"):
            self.i += 1
            if self.t[self.i - 1] == "&":
                while self.peek().isdigit() or self.peek() == "-":
                    self.i += 1
                return
        self.redirect_next = True

    def skip_heredocs(self):
        while self.pending_heredocs:
            delim = self.pending_heredocs.pop(0)
            while True:
                if self.i >= len(self.t):
                    self.problem("unterminated heredoc %s" % delim)
                    return
                j = self.t.find("\n", self.i)
                line = self.t[self.i:] if j < 0 else self.t[self.i:j]
                self.i = len(self.t) if j < 0 else j + 1
                if line == delim:
                    break

    def double_quoted(self):
        t = self.t
        start = self.i
        self.i += 1
        while self.i < len(t):
            ch = t[self.i]
            if ch == "\\":
                self.i += 2
                continue
            if ch == '"':
                self.i += 1
                self.word.append(t[start:self.i])
                return
            if ch == "`":
                self.problem("backticks are not allowed; use \"$(...)\"")
                self.i += 1
                continue
            if ch == "$":
                self.dollar(quoted=True)
                continue
            self.i += 1
        self.problem("unterminated double quote")

    def dollar(self, quoted):
        """At a `$`. Consumes the expansion; reports it when unquoted."""
        t = self.t
        start = self.i
        nxt = self.peek(1)
        if t.startswith("$((", self.i):
            self.i += 3
            depth = 0
            while self.i < len(t):
                ch = t[self.i]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    if depth == 0 and self.peek(1) == ")":
                        self.i += 2
                        break
                    depth -= 1
                self.i += 1
            if not quoted:
                self.word.append(t[start:self.i])
            return
        if nxt == "(":
            self.i += 2
            inner_start = self.i
            depth = 0
            quote = None
            while self.i < len(t):
                ch = t[self.i]
                if quote == "'":
                    if ch == "'":
                        quote = None
                elif quote == '"':
                    if ch == "\\":
                        self.i += 1
                    elif ch == '"':
                        quote = None
                else:
                    if ch in "'\"":
                        quote = ch
                    elif ch == "\\":
                        self.i += 1
                    elif ch == "(":
                        depth += 1
                    elif ch == ")":
                        if depth == 0:
                            break
                        depth -= 1
                self.i += 1
            inner = t[inner_start:self.i]
            self.i += 1
            if self.depth > 8:
                self.problem("command substitution nested too deeply")
            else:
                lint(inner, self.s, self.depth + 1)
            if not quoted:
                self.problem("unquoted command substitution $(...): quote it")
                self.word.append(t[start:self.i])
            return
        if nxt == "{":
            j = t.find("}", self.i)
            if j < 0:
                self.problem("unterminated ${")
                self.i += 1
                return
            self.i = j + 1
            if not quoted:
                self.problem("unquoted expansion %s: quote it" % t[start:self.i])
                self.word.append(t[start:self.i])
            return
        m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])", t[self.i:])
        if m:
            self.i += m.end()
            if not quoted:
                self.problem("unquoted expansion %s: quote it" % m.group(0))
                self.word.append(m.group(0))
            return
        if nxt == "'":
            self.problem("$'...' strings are not allowed")
        if not quoted:
            self.word.append("$")
        self.i += 1


def command_words(seg):
    """Drop leading keywords and assignments; return [command, args...]."""
    i = 0
    while i < len(seg) and (seg[i] in KEYWORDS or _ASSIGN_RE.match(seg[i])):
        i += 1
    return seg[i:]


def check_rules(script_text):
    """All shell-safety problems for one run: block."""
    s = lint(script_text)
    problems = list(s.problems)
    for seg in s.segments:
        words = command_words(seg)
        if not words:
            continue
        cmd, args = words[0], words[1:]
        if seg[0] == "for" and any("$(" in w or "`" in w for w in seg[1:]):
            problems.append("`for` over an expansion: write a NUL-delimited list to a file and read it with -d ''")
        if cmd in ("eval", "source", "."):
            problems.append("`%s` is not allowed" % cmd)
        if cmd in ("ls", "mapfile", "readarray"):
            problems.append("`%s` is not allowed (lists must be NUL-delimited)" % cmd)
        if cmd == "find" and "-print0" not in args:
            problems.append("`find` without -print0")
        if cmd == "xargs" and "-0" not in args:
            problems.append("`xargs` without -0")
        if cmd in ("sort", "uniq") and "-z" not in args:
            problems.append("`%s` without -z" % cmd)
        if cmd == "read":
            ok = any(args[k] == "-d" and k + 1 < len(args) and args[k + 1] in ("''", '""') for k in range(len(args)))
            if not ok:
                problems.append("`read` without -d ''")
        if cmd == "git":
            if not any(args[k] == "-c" and k + 1 < len(args) and args[k + 1] == "core.attributesFile=/dev/null"
                       for k in range(len(args))):
                problems.append("`git` without -c core.attributesFile=/dev/null")
        if cmd in ("git", "g"):
            if any(a in ("ls-files", "ls-tree", "diff-tree", "status") for a in args) and "-z" not in args:
                problems.append("a git list without -z")
            if "--name-only" in args and "-z" not in args:
                problems.append("a git list without -z")
        if cmd in PATH_CMDS:
            for k, a in enumerate(args):
                if a == "--":
                    break
                if "$" in a:
                    problems.append("`%s` takes a variable path before `--`" % cmd)
                    break
    for m in re.finditer(r"\$\{\{(.*?)\}\}", script_text, re.S):
        if m.group(1).strip() not in ("github.event.pull_request.head.sha", "github.event.pull_request.base.sha",
                                      "github.event.pull_request.number"):
            problems.append("`${{%s}}` in run: (only commit shas and numbers are allowed; use env:)" % m.group(1))
    return problems, s.segments
