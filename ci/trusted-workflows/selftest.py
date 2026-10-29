#!/usr/bin/env python3
"""Self-test for the trusted workflow starters: PLAN-177-R7 change 5's self-test list (T18) and the rule manifest (T18g).

Run with `python3 -I ci/trusted-workflows/selftest.py` from arbiter-control-plane/. With `--mutations`, it also
proves each rule fires: every mutation below breaks one rule in a copy of a starter, and the self-test must then
fail with that rule's ID. Exit status 0 means every check passed (and every mutation was caught).

T18 rules (change 5, "The starter self-test fails on"):
  T18.1 an unpinned `uses:`
  T18.2 any `inputs:` block, or any `secrets.` expression
  T18.3 a checkout or scanner in `report`, or `id-token` in `scan`
  T18.4 `actions/cache`, a `cache:` input or `download-artifact`
  T18.5 a URL or audience taken from anywhere but a literal
  T18.6 a missing removal step (attributes, `.gitleaksignore`, scanner config files) before scanning
  T18.7 any allowlist in the gitleaks config other than the exact-value block, or any `extend` of the default config
  T18.8 a list built without NUL delimiters, an unquoted path, or a `${{ }}` in `run:` other than a sha or a number
  T18.9 any identity value (PR number, head, base) taken from `needs.scan.outputs`
T18g: the rule manifest differs from the built config.
Further checks that keep the design whole (each with a mutation): T18.x-*.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layout  # noqa: E402
import shlint  # noqa: E402
import wfyaml  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
STARTERS = ("secret-scan.yml", "dependency-check.yml")
SHARED_STEPS = ("setup", "checkout", "verify-head", "dir-check", "inventory", "move-planted", "plain-tree")
PINNED_USES = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
PLANTED = (".gitattributes", ".gitleaksignore", ".gitleaks.toml", "osv-scanner.toml")
SCANNER_CMDS = ('"$WORK/tools/gitleaks"', '"$WORK/tools/osv-scanner"')
DEFAULT_CONFIG_URL = ("https://raw.githubusercontent.com/gitleaks/gitleaks/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/"
                      "config/gitleaks.toml")
REPORT_ENV = {
    "PR_NUMBER": "${{ github.event.pull_request.number }}",
    "PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
    "SCAN_RESULT": "${{ needs.scan.result }}",
    "SCAN_CONCLUSION": "${{ needs.scan.outputs.conclusion }}",
}


def read(path, mode="r"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        return f.read()


def walk(node, path=()):
    """Yield (path, key, value) for every mapping entry and (path, None, value) for every scalar."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield path, k, v
            yield from walk(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, path + (i,))
    else:
        yield path, None, node


def steps_of(doc, job):
    return ((doc.get("jobs") or {}).get(job) or {}).get("steps") or []


def step_by_id(doc, job, sid):
    for s in steps_of(doc, job):
        if s.get("id") == sid:
            return s
    return None


class Findings:
    def __init__(self):
        self.items = []

    def add(self, rule, where, msg):
        self.items.append((rule, where, msg))

    def rules(self):
        return {r for r, _, _ in self.items}


# --------------------------------------------------------------------------------------------------------------------
# Per-starter checks
# --------------------------------------------------------------------------------------------------------------------

def check_starter(name, text, f):
    try:
        doc = wfyaml.loads(text)
    except wfyaml.YamlError as e:
        f.add("T18.0-yaml", name, "cannot read: %s" % e)
        return None
    if not isinstance(doc, dict) or set(doc) - {"name", "on", "permissions", "defaults", "jobs"}:
        f.add("T18.0-yaml", name, "unexpected top-level keys")
        return None
    jobs = doc.get("jobs") or {}
    if set(jobs) != {"scan", "report"}:
        f.add("T18.0-shape", name, "the jobs must be exactly scan and report")
        return doc

    # T18.1 unpinned uses
    for path, key, value in walk(doc):
        if key == "uses":
            if not isinstance(value, str) or not PINNED_USES.match(value):
                f.add("T18.1-unpinned-uses", name, "uses: %r is not owner/repo@<40-hex commit>" % (value,))

    # T18.2 inputs / secrets
    if doc.get("on") != {"workflow_call": None}:
        f.add("T18.2-inputs-secrets", name, "on: must be exactly `workflow_call:` with nothing under it")
    for path, key, value in walk(doc):
        if key in ("inputs", "secrets"):
            f.add("T18.2-inputs-secrets", name, "a `%s:` block at %s" % (key, "/".join(map(str, path))))
        if key is None and isinstance(value, str) and re.search(r"\bsecrets\s*\.", value):
            f.add("T18.2-inputs-secrets", name, "a `secrets.` expression at %s" % "/".join(map(str, path)))
        if key is None and isinstance(value, str) and re.search(r"\$\{\{[^}]*\b(inputs|vars)\s*\.", value):
            f.add("T18.2-inputs-secrets", name, "an `inputs.` or `vars.` expression at %s" % "/".join(map(str, path)))

    scan, report = jobs["scan"], jobs["report"]

    # T18.3 checkout or scanner in report; id-token in scan
    if doc.get("permissions") != {}:
        f.add("T18.3-job-permissions", name, "top-level permissions must be {}")
    if scan.get("permissions") != {"contents": "read"}:
        f.add("T18.3-job-permissions", name, "scan permissions must be exactly { contents: read }")
    for path, key, value in walk(scan):
        if key == "id-token" or (key is None and isinstance(value, str) and "id-token" in value):
            f.add("T18.3-job-permissions", name, "id-token in scan")
    if report.get("permissions") != {"id-token": "write"}:
        f.add("T18.3-job-permissions", name, "report permissions must be exactly { id-token: write }")
    for st in steps_of(doc, "report"):
        if "uses" in st:
            f.add("T18.3-report-checkout-scanner", name, "report uses an action: %s" % st["uses"])
        run = st.get("run") or ""
        _, segs = shlint.check_rules(run)
        for seg in segs:
            words = shlint.command_words(seg)
            if words and words[0] in ("git", "g", "gitleaks", "osv-scanner", "strings", "find", "tar", "python3"):
                f.add("T18.3-report-checkout-scanner", name, "report runs `%s`" % words[0])
            if any(("gitleaks" in w or "osv-scanner" in w or "checkout" in w or "GITHUB_WORKSPACE" in w)
                   and not w.startswith("CHECK=") for w in seg):
                f.add("T18.3-report-checkout-scanner", name, "report touches the checkout or a scanner")
    if report.get("needs") != "scan" or report.get("if") != "always()":
        f.add("T18.3-report-shape", name, "report must have needs: scan and if: always()")

    # T18.4 caches and artifacts
    for path, key, value in walk(doc):
        if key == "cache":
            f.add("T18.4-cache-artifact", name, "a `cache:` input")
        if key == "uses" and isinstance(value, str) and re.search(
                r"(^actions/cache\b|/cache@|download-artifact|upload-artifact)", value):
            f.add("T18.4-cache-artifact", name, "uses %s" % value)

    # T18.5 URL and audience are literals
    report_runs = "\n".join(st.get("run") or "" for st in steps_of(doc, "report"))
    url_lines = re.findall(r"^\s*(?:export\s+|readonly\s+|declare\s+[-a-z]*\s*)?ARBITER_URL\+?=.*$", report_runs, re.M)
    aud_lines = re.findall(r"^\s*(?:export\s+|readonly\s+|declare\s+[-a-z]*\s*)?ARBITER_AUDIENCE\+?=.*$", report_runs,
                           re.M)
    lit_url = re.compile(r"^ARBITER_URL='https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?'( +#.*)?$")
    lit_aud = re.compile(r"^ARBITER_AUDIENCE='[A-Za-z0-9._~:/-]+'( +#.*)?$")
    if len(url_lines) != 1 or not lit_url.match(url_lines[0].strip()):
        f.add("T18.5-url-audience-literal", name, "ARBITER_URL must be set once, to a single-quoted https literal")
    if len(aud_lines) != 1 or not lit_aud.match(aud_lines[0].strip()):
        f.add("T18.5-url-audience-literal", name, "ARBITER_AUDIENCE must be set once, to a single-quoted literal")
    if len(re.findall(r"\bARBITER_URL\b", report_runs)) != 2 or not re.search(
            r'^\s*url="\$ARBITER_URL/api/trusted-check-results/\$GITHUB_REPOSITORY/\$PR_NUMBER"$', report_runs, re.M):
        f.add("T18.5-url-audience-literal", name, "the post URL must be built only from the ARBITER_URL literal")
    if len(re.findall(r"\bARBITER_AUDIENCE\b", report_runs)) != 2 or '--data-urlencode "audience=$ARBITER_AUDIENCE"' \
            not in report_runs:
        f.add("T18.5-url-audience-literal", name, "the token audience must come only from the ARBITER_AUDIENCE literal")
    for scope in (doc, scan, report) + tuple(steps_of(doc, "report")):
        env = scope.get("env") or {}
        if any(k.startswith("ARBITER_") for k in env):
            f.add("T18.5-url-audience-literal", name, "ARBITER_* set through env:")
    if (report.get("env") or {}) != REPORT_ENV:
        f.add("T18.5-report-env", name, "report env must be exactly %s" % REPORT_ENV)

    # T18.6 removal step before scanning
    sids = [s.get("id") for s in steps_of(doc, "scan")]
    move = step_by_id(doc, "scan", "move-planted")
    if move is None:
        f.add("T18.6-removal-step", name, "no move-planted step")
    else:
        mrun = move.get("run") or ""
        for planted in PLANTED:
            if "-name %s" % planted not in mrun:
                f.add("T18.6-removal-step", name, "move-planted does not move %s" % planted)
        if ".git/info/attributes" not in mrun or "mv -- \"$p\"" not in mrun or "-type f" not in mrun:
            f.add("T18.6-removal-step", name, "move-planted does not move every planted file")
        if "checkout-index --all --force" not in mrun or "rm --cached" not in mrun:
            f.add("T18.6-removal-step", name, "move-planted does not drop planted files from the index and rewrite")
        mi = sids.index("move-planted")
        for k, st in enumerate(steps_of(doc, "scan")):
            run = st.get("run") or ""
            _, segs = shlint.check_rules(run)
            invokes = any(shlint.command_words(seg)[:1] and shlint.command_words(seg)[0] in SCANNER_CMDS
                          for seg in segs)
            reads_tree = st.get("id") in ("plain-tree", "binary-text")
            if (invokes or reads_tree) and k < mi:
                f.add("T18.6-removal-step", name, "step %s scans before move-planted" % st.get("id"))
        for before in ("verify-head", "dir-check", "inventory"):
            if before not in sids or sids.index(before) > mi:
                f.add("T18.6-removal-step", name, "%s must come before move-planted" % before)
    dirc = step_by_id(doc, "scan", "dir-check")
    if dirc is None or "! -type f" not in (dirc.get("run") or "") or not all(
            "-name %s" % p in (dirc.get("run") or "") for p in PLANTED):
        f.add("T18.6-dir-check", name, "dir-check must fail on any scanner-file name that is not a regular file")
    inv = step_by_id(doc, "scan", "inventory")
    for lock in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "Pipfile.lock",
                 "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock", "pom.xml", "gradle.lockfile"):
        if inv is None or "-name %s " % lock not in (inv.get("run") or ""):
            f.add("T18.6-inventory", name, "the inventory does not claim %s" % lock)

    # T18.8 shell safety in every run block
    for job in ("scan", "report"):
        for st in steps_of(doc, job):
            run = st.get("run")
            if run is None:
                continue
            problems, _ = shlint.check_rules(run)
            for p in problems:
                f.add("T18.8-shell-safety", name, "%s/%s: %s" % (job, st.get("id") or st.get("name"), p))
            first = next((l for l in run.splitlines() if l.strip() and not l.strip().startswith("#")), "")
            if first.strip() not in ("set -euo pipefail", "set -uo pipefail"):
                f.add("T18.8-shell-safety", name, "%s/%s must start with set -euo pipefail" % (job, st.get("id")))
    for path, key, value in walk(doc):
        if key in ("shell", "working-directory") and path[-2:] != ("defaults", "run"):
            f.add("T18.8-shell-safety", name, "a step-level %s:" % key)
    if doc.get("defaults") != {"run": {"shell": "bash"}}:
        f.add("T18.8-shell-safety", name, "defaults must be run: shell: bash")

    # T18.9 identity values only from github.event
    for path, key, value in walk(doc):
        if key is None and isinstance(value, str):
            for m in re.finditer(r"needs\s*\.\s*scan\s*\.\s*outputs\s*\.\s*([A-Za-z0-9_-]+)", value):
                if m.group(1) != "conclusion":
                    f.add("T18.9-identity-from-scan", name, "needs.scan.outputs.%s" % m.group(1))
            if re.search(r"needs\s*\.\s*scan\s*\.\s*outputs\s*\[", value):
                f.add("T18.9-identity-from-scan", name, "needs.scan.outputs[...]")
    if scan.get("outputs") != {"conclusion": "${{ steps.result.outputs.conclusion }}"}:
        f.add("T18.9-identity-from-scan", name, "scan must output only conclusion, from the result step")

    # Further design checks.
    for jn in ("scan", "report"):
        if jobs[jn].get("runs-on") != "ubuntu-latest":
            f.add("T18.x-runner", name, "%s must run on GitHub-hosted ubuntu-latest" % jn)
    co = step_by_id(doc, "scan", "checkout")
    want_with = {"ref": "refs/pull/${{ github.event.pull_request.number }}/head", "path": "src", "fetch-depth": "0",
                 "persist-credentials": "false", "lfs": "false", "submodules": "false",
                 "allow-unsafe-pr-checkout": "true"}
    if co is None or not str(co.get("uses", "")).startswith("actions/checkout@") or co.get("with") != want_with:
        f.add("T18.x-checkout", name, "the checkout must fetch refs/pull/<n>/head into src without credentials")
    if sids[:2] != ["setup", "checkout"] or "verify-head" not in sids or sids.index("verify-head") != 2:
        f.add("T18.x-checkout", name, "setup, checkout, verify-head must be the first three steps")
    if (scan.get("env") or {}) != {"PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
                                   "PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}"}:
        f.add("T18.x-scan-env", name, "scan env must be the event's head and base shas only")
    for st in steps_of(doc, "scan") + steps_of(doc, "report"):
        if st.get("env") or st.get("with") and st.get("id") != "checkout" or st.get("continue-on-error"):
            f.add("T18.x-step-keys", name, "step %s has env, with or continue-on-error" % st.get("id"))
        if set(st) - {"name", "id", "if", "run", "uses", "with", "timeout-minutes"}:
            f.add("T18.x-step-keys", name, "step %s has unexpected keys" % st.get("id"))
    result = step_by_id(doc, "scan", "result")
    if result is None or result.get("if") != "always()" or sids[-1] != "result":
        f.add("T18.x-conclusion", name, "the last scan step must be `result`, with if: always()")
    else:
        written = set()
        for st in steps_of(doc, "scan")[:-1]:
            written |= set(re.findall(r'"\$WORK/status/([a-z0-9-]+)\.status"', st.get("run") or ""))
        m = re.search(r"^for s in ([a-z0-9 -]+); do$", result.get("run") or "", re.M)
        listed = set(m.group(1).split()) if m else set()
        if not written or written != listed:
            f.add("T18.x-conclusion", name, "the result step must read every status the steps write")
        if "conclusion='failure'" not in result["run"] or "!= '0'" not in result["run"]:
            f.add("T18.x-conclusion", name, "the result step must fail anything but status 0")
    for st in steps_of(doc, "scan"):
        _, segs = shlint.check_rules(st.get("run") or "")
        for seg in segs:
            w = shlint.command_words(seg)
            if w and w[0] in ("npm", "npx", "yarn", "pnpm", "pip", "pip3", "make", "go", "cargo", "mvn", "gradle",
                              "bundle", "composer", "node", "ruby", "perl", "sh", "bash", "docker"):
                f.add("T18.x-no-pr-code", name, "scan runs `%s`" % w[0])
            if w and (w[0].startswith('"$SRC') or w[0].startswith("./") or w[0].startswith('"$GITHUB_WORKSPACE')):
                f.add("T18.x-no-pr-code", name, "scan runs a file from the checkout")
            if w and w[0] == "python3" and w[1:3] != ["-I", "-"]:
                f.add("T18.x-no-pr-code", name, "python3 must run as `python3 -I -` with an inline script")
            if w and w[0] == "curl" and "--proto" not in w:
                f.add("T18.x-downloads", name, "a download without --proto '=https'")
    for st in steps_of(doc, "scan"):
        run = st.get("run") or ""
        for m in re.finditer(r"curl [^\n]*-o (\S+) '(https://[^']+)'", run):
            if "sha256sum --check" not in run:
                f.add("T18.x-downloads", name, "a download in %s is not checked against a pinned sha256" % st.get("id"))
    return doc


def check_gitleaks_flags(name, doc, f):
    """secret-scan.yml: the three gitleaks runs carry the settings change 5 fixes."""
    runs = {sid: (step_by_id(doc, "scan", sid) or {}).get("run") or ""
            for sid in ("gitleaks-range", "gitleaks-tree", "gitleaks-scratch")}
    common = ('--config "$WORK/cfg/gitleaks.toml"', '--gitleaks-ignore-path "$WORK/cfg/empty-gitleaksignore"',
              "--ignore-gitleaks-allow", "--max-archive-depth 2", "--redact", "--report-path ")
    # The tree scans match plain-tree's 5 MB limit. The range scan reads patches, and a rewritten 5 MB file's patch
    # is about 10 MB, so its limit is 100: it must never skip what plain-tree's history pass allows (Gate 2 F1).
    size = {"gitleaks-range": "--max-target-megabytes 100 ", "gitleaks-tree": "--max-target-megabytes 5 ",
            "gitleaks-scratch": "--max-target-megabytes 5 "}
    for sid, run in runs.items():
        for flag in common + (size[sid],):
            if flag not in run:
                f.add("T18.x-gitleaks-flags", name, "%s lacks %s" % (sid, flag.strip()))
        if run.count("--max-target-megabytes") != 1:
            f.add("T18.x-gitleaks-flags", name, "%s sets --max-target-megabytes more than once" % sid)
    pt = (step_by_id(doc, "scan", "plain-tree") or {}).get("run") or ""
    for needle in ('b"rev-list", b"--objects", b"--no-object-names", base + b".." + head',
                   'count["files over 5 MB in history"] += 1', 'visit(data, links.get(oid) or names.get(oid, b""), 0)',
                   'elif data.startswith(b"version https://git-lfs.github.com/spec/"):\n            count["LFS pointers"] += 1',
                   'if oid in links and b"\\0" in data:\n            count["symlinks that are not links"] += 1',
                   'if oid in links and int(size) > LINK_LIMIT:', 'elif mode == b"120000":',
                   "\n    history()\n"):
        if needle not in pt:
            f.add("T18.x-history", name, "plain-tree must hold every blob the range adds to the head's limits")
            break
    if '"$WORK/tools/gitleaks" git "$SRC" --log-opts="--no-ext-diff --no-textconv --text $PR_BASE_SHA..$PR_HEAD_SHA"' \
            not in runs["gitleaks-range"]:
        f.add("T18.x-gitleaks-flags", name, "the range scan must be base.sha..head.sha with safe git flags")
    # gitleaks' git must not read .gitattributes (the setting goes through a variable: written inline, its name reads
    # to gitleaks as a key, a finding in the ordinary form's own file; REVIEW-PR56 F5).
    rr = runs["gitleaks-range"]
    attr = "\nATTRIBUTES_SETTING=core.attributesFile\n"
    exp = '\nexport GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="$ATTRIBUTES_SETTING" GIT_CONFIG_VALUE_0=/dev/null\n'
    if not (0 <= rr.find(attr) < rr.find(exp) < rr.find('"$WORK/tools/gitleaks" git ')) \
            or rr.count("ATTRIBUTES_SETTING=") != 1 or rr.count("GIT_CONFIG_") != 3:
        f.add("T18.x-gitleaks-flags", name, "the range scan must set core.attributesFile to /dev/null for gitleaks' git")
    if '"$WORK/tools/gitleaks" dir "$SRC"' not in runs["gitleaks-tree"]:
        f.add("T18.x-gitleaks-flags", name, "the tree scan must scan the whole checkout without git")
    if '"$WORK/tools/gitleaks" dir "$WORK/scratch"' not in runs["gitleaks-scratch"]:
        f.add("T18.x-gitleaks-flags", name, "the scratch folder must be scanned")
    bt = step_by_id(doc, "scan", "binary-text")
    if bt is None or '[b"strings", b"-a", b"-n", b"8", b"--", p]' not in (bt.get("run") or ""):
        f.add("T18.x-binary-text", name, "binary files must be written as `strings -a -n 8` text")


def check_osv_flags(name, doc, f):
    lock = (step_by_id(doc, "scan", "osv-lockfiles") or {}).get("run") or ""
    tree = (step_by_id(doc, "scan", "osv-tree") or {}).get("run") or ""
    for sid, run in (("osv-lockfiles", lock), ("osv-tree", tree)):
        for flag in ('--config "$WORK/cfg/osv-scanner.toml"', "--no-ignore", "--all-vulns", "--no-call-analysis=all",
                     "--output-file "):
            if flag not in run:
                f.add("T18.x-osv-flags", name, "%s lacks %s" % (sid, flag))
    if 'args+=("--lockfile=$base:$SRC/$rel")' not in lock or '< "$WORK/out/lockfiles.nul"' not in lock:
        f.add("T18.x-osv-flags", name, "every inventoried lockfile must be passed as --lockfile=<type>:<absolute path>")
    if '--recursive "$SRC"' not in tree:
        f.add("T18.x-osv-flags", name, "the tree run must be recursive over the checkout")


# --------------------------------------------------------------------------------------------------------------------
# The gitleaks config build (T18.7) and the rule manifest (T18g)
# --------------------------------------------------------------------------------------------------------------------

CURL_SHIM = r"""#!/usr/bin/env bash
# Test stand-in for curl: serves the pinned default config from the trusted repo's copy.
out=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
if [ "$url" = "$SELFTEST_DEFAULT_URL" ] && [ -n "$out" ]; then
  cat -- "$SELFTEST_DEFAULT_COPY" > "$out"
  exit 0
fi
echo "curl shim: unexpected URL" >&2
exit 22
"""


def build_config(doc, default_bytes, repository="example-org/example-repo"):
    """Run secret-scan.yml's build-config step against the given default config. Returns (rc, output, toml_text)."""
    st = step_by_id(doc, "scan", "build-config")
    if st is None:
        return 1, "no build-config step", None
    tmp = tempfile.mkdtemp(prefix="trusted-selftest-")
    try:
        work = os.path.join(tmp, "runner", "arbiter-trusted")
        os.makedirs(os.path.join(work, "cfg"))
        os.makedirs(os.path.join(work, "status"))
        bindir = os.path.join(tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "curl"), "w") as fh:
            fh.write(CURL_SHIM)
        os.chmod(os.path.join(bindir, "curl"), 0o755)
        copy = os.path.join(tmp, "default.toml")
        with open(copy, "wb") as fh:
            fh.write(default_bytes)
        script = os.path.join(tmp, "step.sh")
        with open(script, "w") as fh:
            fh.write(st["run"])
        env = {"PATH": bindir + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
               "RUNNER_TEMP": os.path.join(tmp, "runner"), "GITHUB_REPOSITORY": repository,
               "SELFTEST_DEFAULT_URL": DEFAULT_CONFIG_URL, "SELFTEST_DEFAULT_COPY": copy,
               "HOME": tmp, "LANG": "C.UTF-8"}
        p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", script], env=env, cwd=tmp,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        out_path = os.path.join(work, "cfg", "gitleaks.toml")
        toml_text = read(out_path) if os.path.exists(out_path) else None
        return p.returncode, p.stdout.decode("utf-8", "replace"), toml_text
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def parse_manifest(text):
    meta, ids = {}, []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = re.match(r"^(gitleaks|count|ids-sha256): (\S+)$", line)
        if m:
            meta[m.group(1)] = m.group(2)
        else:
            ids.append(line.strip())
    return meta, ids


def check_gitleaks_config(name, doc, text, default_bytes, manifest_text, f):
    import tomllib
    run = (step_by_id(doc, "scan", "build-config") or {}).get("run") or ""
    pins = dict(re.findall(r"^(DEFAULT_CONFIG_SHA256|RULE_COUNT|RULE_IDS_SHA256)='([^']*)'$", run, re.M))
    if hashlib.sha256(default_bytes).hexdigest() != pins.get("DEFAULT_CONFIG_SHA256"):
        f.add("T18g-default-config-pin", name, "gitleaks/gitleaks.toml does not match DEFAULT_CONFIG_SHA256")
    if DEFAULT_CONFIG_URL not in run:
        f.add("T18g-default-config-pin", name, "the default config must be fetched from the pinned commit")
    if re.search(r"\bextend\b", text.split("name: Build the gitleaks config")[0]) or re.search(
            r"^\s*\[extend\]|\buseDefault\b", run, re.M):
        f.add("T18.7-allowlist-extend", name, "the workflow extends a config")
    meta, ids = parse_manifest(manifest_text)
    listing = "".join(i + "\n" for i in sorted(ids)).encode()
    if (meta.get("count") != str(len(ids)) or meta.get("ids-sha256") != hashlib.sha256(listing).hexdigest()
            or ids != sorted(ids) or len(set(ids)) != len(ids)):
        f.add("T18g-manifest", name, "the manifest's count or ids-sha256 does not match its ID list")
    if pins.get("RULE_COUNT") != meta.get("count") or pins.get("RULE_IDS_SHA256") != meta.get("ids-sha256"):
        f.add("T18g-manifest", name, "secret-scan.yml's RULE_COUNT / RULE_IDS_SHA256 differ from the manifest")
    if "gitleaks_%s_linux_x64" % meta.get("gitleaks") not in text or "at gitleaks v%s" % meta.get("gitleaks") not in run:
        f.add("T18g-manifest", name, "the manifest's gitleaks version differs from the pinned binary or config")

    # Exceptions are listed per repository; the example's, or the trusted repository's own (Gate 2 F3).
    branches = {m.group(1): re.findall(r"^\s*add_exception '([^']+)' '([^']*)'$", m.group(2), re.M)
                for m in re.finditer(r"^\s*([A-Za-z0-9-]+/[A-Za-z0-9._-]+)\)\n((?:\s*add_exception [^\n]*\n)+)\s*;;$",
                                     run, re.M)}
    if len(re.findall(r"^\s*add_exception '", run, re.M)) != sum(len(v) for v in branches.values()):
        f.add("T18.7-allowlist-extend", name, "every exception must sit in a per-repository case branch")
    exc_repo = next(iter(branches), "example-org/example-repo")
    rc, out, built = build_config(doc, default_bytes, repository=exc_repo)
    if rc != 0 or built is None:
        last = (out.strip().splitlines() or [""])[-1]
        rule = "T18.7-allowlist-extend" if ("allowlist" in last or "extend" in last) else "T18g-manifest"
        f.add(rule, name, "the build-config step failed: %s" % last)
        return
    try:
        cfg = tomllib.loads(built)
    except tomllib.TOMLDecodeError as e:
        f.add("T18.7-allowlist-extend", name, "the built config is not TOML: %s" % e)
        return
    built_ids = [r.get("id") for r in cfg.get("rules", [])]
    if sorted(built_ids) != sorted(ids) or len(built_ids) != len(ids):
        f.add("T18g-manifest", name, "the built config's rule IDs differ from the reviewed manifest")
    if "extend" in cfg:
        f.add("T18.7-allowlist-extend", name, "the built config uses extend")
    if "allowlist" in cfg or "allowlists" in cfg:
        f.add("T18.7-allowlist-extend", name, "the built config has a global allowlist")
    expected = {}
    for rule_id, match in branches.get(exc_repo, []):
        expected.setdefault(rule_id, []).append(match)
    for rule in cfg.get("rules", []):
        if "allowlist" in rule:
            f.add("T18.7-allowlist-extend", name, "rule %s has an [rules.allowlist]" % rule.get("id"))
        als = rule.get("allowlists", [])
        if len(als) != len(expected.get(rule.get("id"), [])):
            f.add("T18.7-allowlist-extend", name, "rule %s has an allowlist that is not an exact-value exception"
                  % rule.get("id"))
        for al in als:
            regs = al.get("regexes") or []
            if (set(al) != {"description", "regexTarget", "regexes"} or al.get("regexTarget") != "match"
                    or len(regs) != 1 or not regs[0].startswith("^") or not regs[0].endswith("$")):
                f.add("T18.7-allowlist-extend", name, "rule %s has an allowlist that is not an exact-value exception"
                      % rule.get("id"))
            elif _go_literal(regs[0]) not in expected.get(rule.get("id"), []):
                f.add("T18.7-allowlist-extend", name, "rule %s has an exception the workflow does not list"
                      % rule.get("id"))
    uc4 = [r for r in cfg.get("rules", []) if r.get("id") == "arbiter-uc4-test-secret"]
    if len(uc4) != 1:
        f.add("T18g-manifest", name, "the UC4 test rule is missing")
    # The exception block is per repository: another repository gets no exception at all.
    rc2, out2, built2 = build_config(doc, default_bytes, repository="other-org/other-repo")
    if rc2 != 0 or built2 is None or any(r.get("allowlists") for r in tomllib.loads(built2).get("rules", [])):
        f.add("T18.7-allowlist-extend", name, "another repository must get no exception")


def _go_literal(rx):
    """Undo the build's escaping of an anchored literal regex (for comparing with the listed match text)."""
    body = rx[1:-1]
    out, i = [], 0
    while i < len(body):
        if body[i] == "\\":
            if body.startswith("\\x{", i):
                j = body.index("}", i)
                out.append(chr(int(body[i + 3:j], 16)))
                i = j + 1
                continue
            out.append(body[i + 1])
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)


def check_shared(docs, f):
    a, b = docs.get("secret-scan.yml"), docs.get("dependency-check.yml")
    if a is None or b is None:
        return
    for sid in SHARED_STEPS:
        sa, sb = step_by_id(a, "scan", sid), step_by_id(b, "scan", sid)
        if sa is None or sb is None or sa != sb:
            f.add("T18.x-shared-steps", "both", "step %s differs between the starters" % sid)
    ra = (steps_of(a, "report") or [{}])[0].get("run", "").replace("CHECK='gitleaks'", "CHECK='<check>'")
    rb = (steps_of(b, "report") or [{}])[0].get("run", "").replace("CHECK='dependency-check'", "CHECK='<check>'")
    if ra != rb or "CHECK='<check>'" not in ra:
        f.add("T18.x-shared-steps", "both", "the report steps differ other than the check name")
    for sid in ("checkout",):
        pass


def run_checks(texts, default_bytes, manifest_text):
    f = Findings()
    docs = {}
    for name in STARTERS:
        doc = check_starter(name, texts[name], f)
        docs[name] = doc
        if doc is None:
            continue
        if name == "secret-scan.yml":
            check_gitleaks_flags(name, doc, f)
            check_gitleaks_config(name, doc, texts[name], default_bytes, manifest_text, f)
        else:
            check_osv_flags(name, doc, f)
    check_shared(docs, f)
    return f


def load_inputs():
    texts = {n: read(layout.workflow(n)) for n in STARTERS}
    default_bytes = read(os.path.join(layout.GITLEAKS, "gitleaks.toml"), "rb")
    manifest = read(os.path.join(layout.GITLEAKS, "rules-manifest.txt"))
    return texts, default_bytes, manifest


# --------------------------------------------------------------------------------------------------------------------
# Mutations: each breaks one rule; the self-test must then fail with that rule.
# --------------------------------------------------------------------------------------------------------------------

def _sub(old, new, count=1):
    def apply(text):
        if old not in text:
            raise AssertionError("mutation anchor not found: %r" % old[:80])
        return text.replace(old, new, count)
    return apply


PROBE_EXCEPTION = ("            example-org/example-repo)\n"
                   "              add_exception 'generic-api-key' 'client_secret = \"Fake7Qm2Zx9Lp4Rt8Wv1Ny6Kb3Hs5Jd0\"'\n"
                   "              ;;\n")
CASE_ANCHOR = '          case "$GITHUB_REPOSITORY" in\n'


def with_exception(text):
    """A trusted repository may delete every exception. The mutations of the config builder are then checked
    against the example exception, put back, so they still have an exception to change (Gate 2 F3)."""
    if re.search(r"^\s*add_exception '", text, re.M) or CASE_ANCHOR not in text:
        return text
    return text.replace(CASE_ANCHOR, CASE_ANCHOR + PROBE_EXCEPTION, 1)


def _sub_re(pattern, repl):
    """Like _sub, for an anchor whose value a trusted repository sets (its URL and audience)."""
    def apply(text):
        out, n = re.subn(pattern, lambda m: repl, text, count=1, flags=re.M)
        if n != 1:
            raise AssertionError("mutation anchor not found: %r" % pattern)
        return out
    return apply


def _drop_step(step_name):
    def apply(text):
        start = text.index("      - name: %s\n" % step_name)
        nxt = text.find("\n      - name: ", start + 1)
        nxt2 = text.find("\n      # ", start + 1)
        ends = [x for x in (nxt, nxt2) if x > 0]
        end = min(ends) + 1
        return text[:start] + text[end:]
    return apply


def _both(*mutations):
    def apply(text):
        for m in mutations:
            text = m(text)
        return text
    return apply


# The build step guards its own output; these mutations remove that guard too, so the self-test's own check of the
# built config is what must catch the change.
_NO_BUILD_GUARD = _sub('''          if "allowlist" in check or "allowlists" in check or "extend" in check:
              fail("the built config has a global allowlist")
          for rule in check["rules"]:
              for al in rule.get("allowlists", []):
                  if set(al) != {"description", "regexTarget", "regexes"} or al["regexTarget"] != "match":
                      fail("the built config has an allowlist other than an exact-value exception")
''', "")


def _move_step_after(step_name, after_name):
    def apply(text):
        start = text.index("      - name: %s\n" % step_name)
        end = text.index("\n      - name: ", start + 1) + 1
        block = text[start:end]
        rest = text[:start] + text[end:]
        a = rest.index("      - name: %s\n" % after_name)
        a_end = rest.index("\n      - name: ", a + 1) + 1
        return rest[:a_end] + block + rest[a_end:]
    return apply


REPORT_ANCHOR = "      - name: Send the result to Arbiter\n"
FAKE_SHA = "1" * 40  # a well-formed pin for mutations only; never a real commit
SS, DC = "secret-scan.yml", "dependency-check.yml"
MUTATIONS = [
    # T18.1
    ("unpinned checkout tag", SS, _sub("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7"),
     "T18.1-unpinned-uses"),
    ("local action", DC, _sub(REPORT_ANCHOR, "      - uses: ./.github/actions/x\n" + REPORT_ANCHOR), "T18.1-unpinned-uses"),
    # T18.2
    ("inputs block", SS, _sub("  workflow_call:\n", "  workflow_call:\n    inputs:\n      x:\n        type: string\n"),
     "T18.2-inputs-secrets"),
    ("secrets expression", DC, _sub("      SCAN_RESULT: ${{ needs.scan.result }}\n",
                                    "      SCAN_RESULT: ${{ needs.scan.result }}\n      T: ${{ secrets.ARBITER_TOKEN }}\n"),
     "T18.2-inputs-secrets"),
    ("secrets declared", SS, _sub("  workflow_call:\n", "  workflow_call:\n    secrets:\n      X:\n        required: false\n"),
     "T18.2-inputs-secrets"),
    # T18.3
    ("checkout in report", SS, _sub(REPORT_ANCHOR, "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
                                    + REPORT_ANCHOR), "T18.3-report-checkout-scanner"),
    ("scanner in report", DC, _sub("          CHECK='dependency-check'\n",
                                   "          CHECK='dependency-check'\n          osv-scanner --version\n"),
     "T18.3-report-checkout-scanner"),
    ("id-token in scan", SS, _sub("    permissions:\n      contents: read\n",
                                  "    permissions:\n      contents: read\n      id-token: write\n"),
     "T18.3-job-permissions"),
    # T18.4
    ("actions/cache", SS, _sub(REPORT_ANCHOR, "      - uses: actions/cache@" + FAKE_SHA + "\n"
                               + REPORT_ANCHOR), "T18.4-cache-artifact"),
    ("cache input", DC, _sub("          allow-unsafe-pr-checkout: true\n",
                             "          allow-unsafe-pr-checkout: true\n          cache: npm\n"), "T18.4-cache-artifact"),
    ("download-artifact", SS, _sub(REPORT_ANCHOR, "      - uses: actions/download-artifact@" + FAKE_SHA + "\n"
                                   + REPORT_ANCHOR), "T18.4-cache-artifact"),
    # T18.5
    ("URL from vars", SS, _sub_re(r"ARBITER_URL='[^'\n]+'", 'ARBITER_URL="${{ vars.ARBITER_URL }}"'),
     "T18.5-url-audience-literal"),
    ("URL from env", DC, _sub_re(r"ARBITER_URL='[^'\n]+'", 'ARBITER_URL="$ARBITER_BASE"'),
     "T18.5-url-audience-literal"),
    ("audience from the event", SS, _sub_re(r"ARBITER_AUDIENCE='[^'\n]+'",
                                         'ARBITER_AUDIENCE="$GITHUB_REPOSITORY_OWNER"'), "T18.5-url-audience-literal"),
    ("URL overridden later", DC, _sub('          url="$ARBITER_URL/', '          ARBITER_URL="$1"\n          url="$ARBITER_URL/'),
     "T18.5-url-audience-literal"),
    # T18.6
    ("no removal step", SS, _drop_step("Move planted scanner files out"), "T18.6-removal-step"),
    (".gitleaksignore not moved", DC, _sub("-type f \\( -name .gitattributes -o -name .gitleaksignore -o ",
                                           "-type f \\( -name .gitattributes -o "), "T18.6-removal-step"),
    ("attributes not moved", SS, _sub("-type f \\( -name .gitattributes -o -name .gitleaksignore",
                                      "-type f \\( -name .gitleaksignore"), "T18.6-removal-step"),
    ("removal after a scan", SS, _move_step_after("Move planted scanner files out", "Scan the commit range with gitleaks"),
     "T18.6-removal-step"),
    ("osv-scanner.toml not moved", DC, _sub(" -o -name .gitleaks.toml -o -name osv-scanner.toml \\) -print0 > \"$WORK/out/planted.nul\"",
                                            " -o -name .gitleaks.toml \\) -print0 > \"$WORK/out/planted.nul\""),
     "T18.6-removal-step"),
    # T18.7
    ("per-rule allowlists kept", SS, _both(_NO_BUILD_GUARD, _sub('              rule.pop("allowlists", None)\n', "")),
     "T18.7-allowlist-extend"),
    ("global allowlist added", SS, _both(_NO_BUILD_GUARD, _sub("          text = \"\\n\".join(lines) + \"\\n\"\n",
                                                               "          lines.append('[allowlist]\\npaths = [\"^vendor/\"]')\n"
                                                               "          text = \"\\n\".join(lines) + \"\\n\"\n")),
     "T18.7-allowlist-extend"),
    ("global allowlist kept", SS, _sub('          cfg.pop("allowlist", None)\n', ""), "T18g-manifest"),
    ("extend added", SS, _both(_NO_BUILD_GUARD, _sub("          text = \"\\n\".join(lines) + \"\\n\"\n",
                              "          lines.insert(0, '[extend]\\nuseDefault = true')\n"
                              "          text = \"\\n\".join(lines) + \"\\n\"\n")), "T18.7-allowlist-extend"),
    ("path exception", SS, _both(_NO_BUILD_GUARD, _sub('"regexTarget": "match",',
                                                       '"regexTarget": "match", "paths": ["^vendor/"],')),
     "T18.7-allowlist-extend"),
    ("unanchored exception", SS, _both(_NO_BUILD_GUARD, _sub('"regexes": ["^" + rx_escape(match) + "$"],',
                                                             '"regexes": [rx_escape(match)],')),
     "T18.7-allowlist-extend"),
    ("guard only removed", SS, _NO_BUILD_GUARD, None),
    # T18.8
    ("find without -print0", SS, _sub(" ! -type f -print0 > ", " ! -type f -print > "), "T18.8-shell-safety"),
    ("ls-files without -z", DC, _sub('g ls-files -z > "$WORK/out/tracked.nul"', 'g ls-files > "$WORK/out/tracked.nul"'),
     "T18.8-shell-safety"),
    ("read without -d", SS, _sub("          while IFS= read -r -d '' p; do\n            n=$((n + 1))\n            mv",
                                 "          while IFS= read -r p; do\n            n=$((n + 1))\n            mv"),
     "T18.8-shell-safety"),
    ("unquoted path", DC, _sub('mv -- "$p" "$WORK/scratch/moved-$n.txt"', 'mv -- $p "$WORK/scratch/moved-$n.txt"'),
     "T18.8-shell-safety"),
    ("path before --", SS, _sub('mv -- "$p" "$WORK/scratch/moved-$n.txt"', 'mv "$p" "$WORK/scratch/moved-$n.txt"'),
     "T18.8-shell-safety"),
    ("expression in run", SS, _sub("          CHECK='gitleaks'\n",
                                   "          CHECK='gitleaks'\n          echo \"${{ github.event.pull_request.title }}\"\n"),
     "T18.8-shell-safety"),
    ("for over a command", DC, _sub("          bad=0\n", "          bad=0\n          for p in \"$(g ls-files -z)\"; do :; done\n"),
     "T18.8-shell-safety"),
    ("git without attributesFile", SS, _sub('g() { git -c core.attributesFile=/dev/null --literal-pathspecs -C "$SRC" "$@"; }\n'
                                            '          g ls-files -s -z',
                                            'g() { git --literal-pathspecs -C "$SRC" "$@"; }\n          g ls-files -s -z'),
     "T18.8-shell-safety"),
    # T18.9
    ("head from scan outputs", SS, _sub("      PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}\n      SCAN_RESULT",
                                        "      PR_HEAD_SHA: ${{ needs.scan.outputs.head_sha }}\n      SCAN_RESULT"),
     "T18.9-identity-from-scan"),
    ("number from scan outputs", DC, _sub("      PR_NUMBER: ${{ github.event.pull_request.number }}",
                                          "      PR_NUMBER: ${{ needs.scan.outputs.pr_number }}"), "T18.9-identity-from-scan"),
    ("scan exports the head", SS, _sub("      conclusion: ${{ steps.result.outputs.conclusion }}\n",
                                       "      conclusion: ${{ steps.result.outputs.conclusion }}\n"
                                       "      head: ${{ github.event.pull_request.head.sha }}\n"), "T18.9-identity-from-scan"),
    # Further checks
    ("self-hosted runner", SS, _sub("    runs-on: ubuntu-latest\n    timeout-minutes: 45\n",
                                    "    runs-on: self-hosted\n    timeout-minutes: 45\n"), "T18.x-runner"),
    ("credentials kept", DC, _sub("          persist-credentials: false\n", "          persist-credentials: true\n"),
     "T18.x-checkout"),
    ("status not read", SS, _sub("gitleaks-scratch gitleaks-scratch-log; do", "gitleaks-scratch; do"), "T18.x-conclusion"),
    ("continue-on-error", DC, _sub("        id: osv-tree\n", "        id: osv-tree\n        continue-on-error: true\n"),
     "T18.x-step-keys"),
    ("runs PR code", SS, _sub("          cd -- \"$WORK\"\n          python3 -I - \"$SRC\" \"$WORK/scratch\" <<'PY'\n          import os, stat, subprocess",
                              "          cd -- \"$WORK\"\n          npm install\n          python3 -I - \"$SRC\" \"$WORK/scratch\" <<'PY'\n          import os, stat, subprocess"),
     "T18.x-no-pr-code"),
    ("download not checked", DC, _sub("          printf '%s  %s\\n' \"$OSV_SCANNER_SHA256\" osv-scanner | sha256sum --check --quiet --strict -\n", ""),
     "T18.x-downloads"),
    ("tree scan dropped", SS, _drop_step("Scan the tree with gitleaks"), "T18.x-gitleaks-flags"),
    ("attributes export dropped", SS, _sub('          export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="$ATTRIBUTES_SETTING" GIT_CONFIG_VALUE_0=/dev/null\n', ""),
     "T18.x-gitleaks-flags"),
    ("attributes setting emptied", SS, _sub("          ATTRIBUTES_SETTING=core.attributesFile\n", "          ATTRIBUTES_SETTING=\n"),
     "T18.x-gitleaks-flags"),
    ("gitleaks:allow honoured", SS, _sub("--ignore-gitleaks-allow --max-target-megabytes 5 --max-archive-depth 2 --no-banner --no-color --redact --log-level info --report-format json --report-path \"$WORK/out/gitleaks-tree.json\"",
                                         "--max-target-megabytes 5 --max-archive-depth 2 --no-banner --no-color --redact --log-level info --report-format json --report-path \"$WORK/out/gitleaks-tree.json\""),
     "T18.x-gitleaks-flags"),
    ("lockfile type from the path", DC, _sub('args+=("--lockfile=$base:$SRC/$rel")', 'args+=("--lockfile=$SRC/$rel")'),
     "T18.x-osv-flags"),
    ("range scan limit back to 5 MB", SS, _sub("--ignore-gitleaks-allow --max-target-megabytes 100 ",
                                               "--ignore-gitleaks-allow --max-target-megabytes 5 "), "T18.x-gitleaks-flags"),
    ("range scan limit dropped", SS, _sub("--ignore-gitleaks-allow --max-target-megabytes 100 ",
                                          "--ignore-gitleaks-allow "), "T18.x-gitleaks-flags"),
    ("history pass not run", SS, _sub("              history()\n", ""), "T18.x-history"),
    ("history pass skips archives", SS, _sub("                  visit(data, links.get(oid) or names.get(oid, b\"\"), 0)\n",
                                             "                  pass\n"), "T18.x-history"),
    ("history pass skips LFS pointers", SS, _sub('                  elif data.startswith(b"version https://git-lfs.github.com/spec/"):\n'
                                                 '                      count["LFS pointers"] += 1\n', ""), "T18.x-history"),
    ("symlink content not read", SS, _sub('                      elif mode == b"120000":\n'
                                          '                          links[oid] = os.path.basename(path)\n', ""), "T18.x-history"),
    ("long symlink content allowed", SS, _sub('              if oid in links and int(size) > LINK_LIMIT:\n',
                                              '              if False:\n'), "T18.x-history"),
    ("binary symlink content allowed", SS, _sub('                  if oid in links and b"\\0" in data:\n'
                                                '                      count["symlinks that are not links"] += 1\n'
                                                '                  elif data', "                  if data"), "T18.x-history"),
    ("history pass skips oversize blobs", SS, _sub('                      count["files over 5 MB in history"] += 1\n',
                                                   "                      pass\n"), "T18.x-history"),
    ("drifted shared step", DC, _sub("          echo \"dir-check: 0 paths\"\n", "          echo \"dir-check: none\"\n"),
     "T18.x-shared-steps"),
]

MANIFEST_MUTATIONS = [
    # T18g: the manifest differs from the built config (a rule missing).
    ("manifest misses a rule", lambda m: m.replace("\ngithub-pat\n", "\n", 1), "T18g-manifest"),
    ("manifest count and hash updated, rule still missing",
     lambda m: _rehash_manifest(m.replace("\ngithub-pat\n", "\n", 1)), "T18g-manifest"),
]


def _rehash_manifest(m):
    meta, ids = parse_manifest(m)
    listing = "".join(i + "\n" for i in sorted(ids)).encode()
    m = re.sub(r"^count: \d+$", "count: %d" % len(ids), m, flags=re.M)
    return re.sub(r"^ids-sha256: \S+$", "ids-sha256: " + hashlib.sha256(listing).hexdigest(), m, flags=re.M)


def _drop_default_rule(default_bytes, texts):
    """T18g: the default config loses a rule (and its pin is updated), as a careless version bump would."""
    text = default_bytes.decode()
    start = text.index('[[rules]]\nid = "github-pat"')
    end = text.index("[[rules]]", start + 1)
    new = (text[:start] + text[end:]).encode()
    sha = hashlib.sha256(new).hexdigest()
    t = dict(texts)
    t[SS] = re.sub(r"DEFAULT_CONFIG_SHA256='[0-9a-f]{64}'", "DEFAULT_CONFIG_SHA256='%s'" % sha, t[SS])
    return new, t


def yaml_crosscheck():
    """Where Ruby is present (it is on GitHub's ubuntu runners), compare this reader with a full YAML parser."""
    import json
    if shutil.which("ruby") is None:
        print("SKIP: YAML cross-check (no ruby on this host)")
        return True
    ok = True
    for name in STARTERS + ("caller.yml",):
        path = layout.workflow(name)
        p = subprocess.run(["ruby", "-ryaml", "-rjson", "-e",
                            'd = YAML.safe_load(File.read(ARGV[0])); d["on"] = d.delete(true) if d.key?(true); '
                            'print JSON.generate(d)', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            print("FAIL: ruby could not read %s" % name)
            ok = False
            continue

        def norm(x):
            if isinstance(x, dict):
                return {str(k): norm(v) for k, v in x.items()}
            if isinstance(x, list):
                return [norm(v) for v in x]
            if isinstance(x, bool):
                return str(x).lower()
            return None if x is None else str(x)

        same = norm(wfyaml.load(path)) == norm(json.loads(p.stdout))
        ok &= same
        print("%s: YAML cross-check with Ruby's parser on %s" % ("PASS" if same else "FAIL", name))
    return ok


def main():
    texts, default_bytes, manifest = load_inputs()
    f = run_checks(texts, default_bytes, manifest)
    ok = yaml_crosscheck()
    if f.items:
        ok = False
        print("FAIL: the starters break the self-test:")
        for rule, where, msg in f.items:
            print("  [%s] %s: %s" % (rule, where, msg))
    else:
        print("PASS: self-test (T18 rules and T18g manifest) on %s" % ", ".join(STARTERS))
    if "--mutations" in sys.argv:
        caught = 0
        total = 0
        for desc, target, mutate, rule in MUTATIONS:
            total += 1
            t = dict(texts)
            t[SS] = with_exception(t[SS])
            try:
                t[target] = mutate(t[target])
            except (AssertionError, ValueError) as e:
                print("  MUTATION ERROR %-32s %s" % (desc, e))
                ok = False
                continue
            got = run_checks(t, default_bytes, manifest).rules()
            if rule is None:
                # A control: this change alone must not trip the T18.7 check, so the mutations above are caught by
                # what they add, not by the guard's removal.
                if "T18.7-allowlist-extend" not in got:
                    caught += 1
                    print("  control %-40s -> T18.7 not tripped" % desc)
                else:
                    ok = False
                    print("  CONTROL FAILED %-33s %s" % (desc, sorted(got)))
                continue
            if rule in got:
                caught += 1
                print("  caught  %-40s -> %s" % (desc, rule))
            else:
                ok = False
                print("  MISSED  %-40s expected %s, got %s" % (desc, rule, sorted(got)))
        for desc, mutate, rule in MANIFEST_MUTATIONS:
            total += 1
            got = run_checks(texts, default_bytes, mutate(manifest)).rules()
            if rule in got:
                caught += 1
                print("  caught  %-40s -> %s" % (desc, rule))
            else:
                ok = False
                print("  MISSED  %-40s expected %s, got %s" % (desc, rule, sorted(got)))
        total += 1
        new_default, t = _drop_default_rule(default_bytes, texts)
        got = run_checks(t, new_default, manifest)
        if "T18g-manifest" in got.rules() and any("build-config step failed" in m for _, _, m in got.items):
            caught += 1
            print("  caught  %-40s -> T18g-manifest (the build step refuses it too)" % "default config loses a rule")
        else:
            ok = False
            print("  MISSED  default config loses a rule: %s" % sorted(got.rules()))
        print("%s: %d of %d mutations caught" % ("PASS" if caught == total else "FAIL", caught, total))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
