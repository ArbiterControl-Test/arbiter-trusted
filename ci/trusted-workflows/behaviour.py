#!/usr/bin/env python3
"""Behaviour tests for the trusted workflow starters (PLAN-177-R7 T18b, T18d, T18e, T18f, T18h, T18j, plus V2-style
extras that cost nothing more to run here).

The runner takes the `scan` job's steps from each starter as written and runs them in order, the way a GitHub-hosted
runner does: `bash --noprofile --norc -eo pipefail` for each `run:` step, `if:` and `timeout-minutes` honoured, step
outputs read from GITHUB_OUTPUT, the job's `conclusion` output computed from them. `actions/checkout` is emulated:
it fetches `refs/pull/7/head` (and the branches) from a bare fixture repository and checks it out with git, so the
pull request's `.gitattributes` apply exactly as in a real checkout. Fixture repositories are built with git in a
temporary folder; their test secrets are generated per run in real formats and never written to a log.

Scanner binaries come from the starters' own install steps: the pinned URL is downloaded once (for real), and every
scenario then runs the install step against that copy, so its sha256 check runs every time. On a host that is not
linux x86_64 (the workflows target ubuntu-latest), pass `--tools-dir DIR` with gitleaks and osv-scanner for this
host, verified by you against the same release's checksums; they replace the x64 binaries after the install step.

Each scenario checks the conclusion `report` would post, and why: which status files are 0, non-zero or missing.

Run with `python3 -I ci/trusted-workflows/behaviour.py [--tools-dir DIR] [--only TEXT] [--keep DIR] [--jobs N]`
from arbiter-control-plane/. Needs git, bash, curl, python3 >= 3.11, strings (binutils), jq and network access
(GitHub downloads; OSV-Scanner queries api.osv.dev).
"""

import argparse
import concurrent.futures
import io
import json
import os
import platform
import re
import secrets
import shutil
import signal
import string
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghexpr  # noqa: E402
import layout  # noqa: E402
import wfyaml  # noqa: E402

PR_NUMBER = 7
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "fixture",
           "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "fixture",
           "GIT_COMMITTER_EMAIL": "fixture@example.invalid", "GIT_TERMINAL_PROMPT": "0"}


# ----------------------------------------------------------------------------------------------------------------
# Test secrets: fake, generated per run, in real formats.
# ----------------------------------------------------------------------------------------------------------------

def _rand(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def aws_key():
    return "AKIA" + _rand("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)


def github_token():
    return "ghp_" + _rand(string.ascii_letters + string.digits, 36)


def uc4_secret():
    return "ARBITER-UC4-TEST-" + _rand("0123456789abcdef", 32)


def package_lock(name, version):
    return json.dumps({
        "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"name": "fixture", "version": "1.0.0", "dependencies": {name: version}},
                     "node_modules/" + name: {"version": version,
                                              "resolved": "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (name, name, version),
                                              "license": "MIT"}}}, indent=2) + "\n"


CLEAN_LOCK = package_lock("is-number", "7.0.0")
VULN_LOCK = package_lock("lodash", "4.17.15")


# ----------------------------------------------------------------------------------------------------------------
# Fixture repositories
# ----------------------------------------------------------------------------------------------------------------

def git(cwd, *args, env=None, input_bytes=None):
    e = dict(os.environ)
    e.update(GIT_ENV)
    if env:
        e.update(env)
    p = subprocess.run(["git", *args], cwd=cwd, env=e, input=input_bytes, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (args[0], p.stderr.decode("utf-8", "replace")[-400:]))
    return p.stdout.decode("utf-8", "replace").strip()


class Fixture:
    def __init__(self, root):
        self.root = root
        self.dir = os.path.join(root, "work")
        os.makedirs(self.dir)
        git(self.dir, "init", "-q", "-b", "main")
        self.put("README.md", "fixture repository\n")
        self.base = None
        self.secrets = []
        self.commits = []
        self.gitlinks = []
        self.raw_links = []

    def secret(self, value):
        self.secrets.append(value)
        return value

    def put(self, path, data, mode=0o644):
        full = os.path.join(self.dir.encode(), path.encode() if isinstance(path, str) else path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data.encode() if isinstance(data, str) else data)
        os.chmod(full, mode)

    def link(self, path, target):
        full = os.path.join(self.dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        os.symlink(target, full)

    def delete(self, path):
        os.remove(os.path.join(self.dir.encode(), path.encode() if isinstance(path, str) else path))

    def gitlink(self, path, sha="1" * 40):
        self.gitlinks.append((path, sha))

    def raw_link(self, path, data):
        """A symlink whose stored content is any bytes, as `git update-index --cacheinfo 120000` allows."""
        oid = git(self.dir, "hash-object", "-w", "--stdin", input_bytes=data)
        self.raw_links.append((path, oid))

    def commit(self, msg):
        git(self.dir, "add", "-A")
        for path, sha in self.gitlinks:
            git(self.dir, "update-index", "--add", "--cacheinfo", "160000,%s,%s" % (sha, path))
        for path, oid in self.raw_links:
            git(self.dir, "update-index", "--add", "--cacheinfo", "120000,%s,%s" % (oid, path))
        git(self.dir, "commit", "-q", "--allow-empty", "--no-verify", "-m", msg)
        sha = git(self.dir, "rev-parse", "HEAD")
        self.commits.append(sha)
        return sha

    def start_pr(self):
        """Ends the base (main) and starts the pull request branch."""
        if self.base is None:
            self.base = self.commit("base")
            git(self.dir, "checkout", "-q", "-b", "feature")

    def finish(self):
        self.start_pr()
        head = self.commit("pr")
        bare = os.path.join(self.root, "origin.git")
        git(self.root, "clone", "-q", "--bare", self.dir, bare)
        git(bare, "update-ref", "refs/pull/%d/head" % PR_NUMBER, head)
        return bare, self.base, head


# ----------------------------------------------------------------------------------------------------------------
# The job runner
# ----------------------------------------------------------------------------------------------------------------

CURL_SHIM = r"""#!/usr/bin/env bash
# Test stand-in for curl in the scan job: serves the pinned downloads from the runner's cache of the real URLs.
out=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
key="$(printf '%s' "$url" | sha256sum | cut -c1-64)"
if [ -n "$out" ] && [ -f "$BEHAVIOUR_CACHE/$key" ]; then
  cat -- "$BEHAVIOUR_CACHE/$key" > "$out"
  exit 0
fi
echo "curl shim: no cached copy of a pinned URL" >&2
exit 22
"""

FAKE_TOOLS = {
    "crash": "#!/usr/bin/env bash\necho 'panic: simulated scanner crash' >&2\nexit 2\n",
    "hang": "#!/usr/bin/env bash\nsleep 600\n",
}


class Runner:
    def __init__(self, cache_dir, tools_dir):
        self.cache = cache_dir
        self.tools_dir = tools_dir
        self.workflows = {n: wfyaml.load(layout.workflow(n)) for n in ("secret-scan.yml", "dependency-check.yml")}

    def prepare(self):
        """Download every pinned URL the scan jobs fetch, once, with the real curl."""
        urls = set()
        for doc in self.workflows.values():
            for st in doc["jobs"]["scan"]["steps"]:
                urls.update(re.findall(r"'(https://[^']+)'", st.get("run") or ""))
        for url in sorted(urls):
            key = subprocess.run(["sha256sum"], input=url.encode(), stdout=subprocess.PIPE, check=True).stdout[:64].decode()
            dest = os.path.join(self.cache, key)
            if not os.path.exists(dest):
                subprocess.run(["curl", "-fsSL", "--proto", "=https", "--max-time", "300", "-o", dest, url], check=True)
            print("cached pinned download: %s" % url)

    def run_job(self, workflow, bare, base, head, repository, tmp, tool_override=None, drop_steps=(),
                step_timeouts=None, doc=None):
        doc = doc or self.workflows[workflow]
        job = doc["jobs"]["scan"]
        runner_temp = os.path.join(tmp, "runner-temp")
        workspace = os.path.join(tmp, "workspace")
        home = os.path.join(tmp, "home")
        shim = os.path.join(tmp, "shim")
        for d in (runner_temp, workspace, home, shim):
            os.makedirs(d)
        with open(os.path.join(home, ".gitconfig"), "w") as fh:
            fh.write("[safe]\n\tdirectory = *\n")
        with open(os.path.join(shim, "curl"), "w") as fh:
            fh.write(CURL_SHIM)
        os.chmod(os.path.join(shim, "curl"), 0o755)
        event = {"action": "synchronize", "number": PR_NUMBER,
                 "pull_request": {"number": PR_NUMBER, "head": {"sha": head, "ref": "feature"},
                                  "base": {"sha": base, "ref": "main"}},
                 "repository": {"full_name": repository}}
        event_path = os.path.join(tmp, "event.json")
        with open(event_path, "w") as fh:
            json.dump(event, fh)
        ctx = {"github": {"event": event, "event_name": "pull_request_target", "repository": repository,
                          "workspace": workspace},
               "runner": {"temp": runner_temp, "os": "Linux"}, "steps": {}, "env": {}}
        base_env = {
            "PATH": shim + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "LANG": "C.UTF-8",
            "CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_TEMP": runner_temp, "GITHUB_WORKSPACE": workspace,
            "GITHUB_REPOSITORY": repository, "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_EVENT_PATH": event_path, "BEHAVIOUR_CACHE": self.cache,
        }
        for k, v in (job.get("env") or {}).items():
            base_env[k] = ghexpr.interpolate(v, ctx)
        status = "success"
        logs = []
        for idx, st in enumerate(job["steps"]):
            sid = st.get("id") or "step%d" % idx
            if sid in drop_steps:
                continue
            if not ghexpr.evaluate_if(st.get("if"), ctx, status):
                ctx["steps"][sid] = {"outputs": {}, "outcome": "skipped", "conclusion": "skipped"}
                logs.append((sid, "skipped", ""))
                continue
            if "uses" in st:
                ok, out = self.checkout(st, ctx, workspace, bare, base_env)
            else:
                ok, out = self.run_step(st, ctx, base_env, tmp, sid, step_timeouts or {})
            if sid == "install" and ok:
                self.place_tools(runner_temp, tool_override)
            logs.append((sid, "success" if ok else "failure", out))
            if not ok:
                status = "failure"
        outputs = {k: ghexpr.interpolate(v, ctx) for k, v in (job.get("outputs") or {}).items()}
        work = os.path.join(runner_temp, "arbiter-trusted")
        statuses = {}
        sdir = os.path.join(work, "status")
        if os.path.isdir(sdir):
            for fn in os.listdir(sdir):
                with open(os.path.join(sdir, fn)) as fh:
                    statuses[fn[:-len(".status")]] = fh.read().strip()
        return {"job_result": status, "conclusion": outputs.get("conclusion", ""), "statuses": statuses,
                "logs": logs, "work": work, "workspace": workspace}

    def place_tools(self, runner_temp, override):
        tools = os.path.join(runner_temp, "arbiter-trusted", "tools")
        if self.tools_dir:
            for name in os.listdir(tools):
                src = os.path.join(self.tools_dir, name)
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(tools, name))
        for name, kind in (override or {}).items():
            with open(os.path.join(tools, name), "w") as fh:
                fh.write(FAKE_TOOLS[kind])
            os.chmod(os.path.join(tools, name), 0o755)

    def checkout(self, st, ctx, workspace, bare, env):
        w = {k: ghexpr.interpolate(v, ctx) for k, v in (st.get("with") or {}).items()}
        if not st["uses"].startswith("actions/checkout@") or w.get("persist-credentials") != "false":
            return False, "unexpected action"
        path = os.path.join(workspace, w.get("path", "."))
        ref = w["ref"]
        e = {"HOME": env["HOME"], "PATH": env["PATH"], "GIT_TERMINAL_PROMPT": "0"}
        try:
            os.makedirs(path, exist_ok=True)
            git(path, "init", "-q", env=e)
            git(path, "remote", "add", "origin", bare, env=e)
            refspecs = ["+%s:refs/remotes/pull/%d/head" % (ref, PR_NUMBER)]
            if w.get("fetch-depth") == "0":
                refspecs.insert(0, "+refs/heads/*:refs/remotes/origin/*")
            git(path, "fetch", "-q", "--no-tags", "origin", *refspecs, env=e)
            git(path, "checkout", "-q", "--force", "refs/remotes/pull/%d/head" % PR_NUMBER, env=e)
        except RuntimeError as ex:
            return False, str(ex)
        return True, "checked out %s" % ref

    def run_step(self, st, ctx, base_env, tmp, sid, step_timeouts):
        script = os.path.join(tmp, "step-%s.sh" % sid)
        with open(script, "w") as fh:
            fh.write(st["run"])
        out_file = os.path.join(tmp, "output-%s" % sid)
        open(out_file, "w").close()
        env = dict(base_env)
        env["GITHUB_OUTPUT"] = out_file
        timeout = step_timeouts.get(sid, float(st.get("timeout-minutes") or 360) * 60)
        p = subprocess.Popen(["bash", "--noprofile", "--norc", "-eo", "pipefail", script], cwd=env["GITHUB_WORKSPACE"],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            out, _ = p.communicate(timeout=timeout)
            ok = p.returncode == 0
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            out, _ = p.communicate()
            out += b"\n[runner] the step timed out\n"
            ok = False
        outputs = {}
        with open(out_file) as fh:
            lines = fh.read().split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r"^([A-Za-z0-9_-]+)<<(.+)$", line)
            if m:
                j = lines.index(m.group(2), i + 1)
                outputs[m.group(1)] = "\n".join(lines[i + 1:j])
                i = j + 1
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                outputs[k] = v
            i += 1
        ctx["steps"][sid] = {"outputs": outputs, "outcome": "success" if ok else "failure",
                             "conclusion": "success" if ok else "failure"}
        return ok, out.decode("utf-8", "replace")


# ----------------------------------------------------------------------------------------------------------------
# Scenarios
# ----------------------------------------------------------------------------------------------------------------

SS, DC = "secret-scan.yml", "dependency-check.yml"


def first_exception():
    """The first exact-value exception in secret-scan.yml, as (repository, match text): the example, or the trusted
    repository's own. None once every exception is deleted; the T18d scenarios are then skipped."""
    run = next(s["run"] for s in wfyaml.load(layout.workflow(SS))["jobs"]["scan"]["steps"]
               if s.get("id") == "build-config")
    m = re.search(r"^\s*([A-Za-z0-9-]+/[A-Za-z0-9._-]+)\)\n\s*add_exception '[^']+' '([^']+)'$", run, re.M)
    return (m.group(1), m.group(2)) if m else None


EXAMPLE = first_exception()
EXAMPLE_REPO = EXAMPLE[0] if EXAMPLE else "example-org/example-repo"


def exception_match():
    return EXAMPLE[1]


class Scenario:
    def __init__(self, row, name, workflow, build, want, why, repository="acme/payments-api", tool_override=None,
                 drop_steps=(), step_timeouts=None, extra=None):
        self.row, self.name, self.workflow, self.build, self.want, self.why = row, name, workflow, build, want, why
        self.repository, self.tool_override, self.drop_steps = repository, tool_override, drop_steps
        self.step_timeouts, self.extra = step_timeouts, extra


def s_secret_in_tree(kind):
    def build(f):
        f.start_pr()
        f.put("config/app.env", "TOKEN=%s\n" % f.secret({"aws": aws_key, "ghp": github_token, "uc4": uc4_secret}[kind]()))
    return build


def s_secret_history_only(kind):
    def build(f):
        f.start_pr()
        f.put("notes.txt", "key %s\n" % f.secret({"aws": aws_key, "ghp": github_token, "uc4": uc4_secret}[kind]()))
        f.commit("add")
        f.delete("notes.txt")
    return build


def s_clean(f):
    f.start_pr()
    f.put("src/app.py", "print('hello')\n")
    f.put("img/logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256)))


# The ordinary form's workflow lives in the scanned repository (ARB-319). Its own text must not be a finding.
ORDINARY = os.path.join(layout.ROOT, "starter", "ordinary-scan", "arbiter-secret-scan.yml")


def s_ordinary_workflow(f):
    f.start_pr()
    with open(ORDINARY, "rb") as fh:
        f.put(".github/workflows/arbiter-secret-scan.yml", fh.read())


def s_workflow_with_exception(f):
    """secret-scan.yml, which holds the example exception, in the scanned tree: the exception line holds the text it
    excepts, so in the repository it names it excepts itself (REVIEW-PR56 F4)."""
    f.start_pr()
    with open(layout.workflow(SS), "rb") as fh:
        f.put(".github/workflows/arbiter-secret-scan.yml", fh.read())


def s_clean_deps(f):
    f.start_pr()
    f.put("web/package-lock.json", CLEAN_LOCK)


def s_three_lockfiles(f):
    f.start_pr()
    f.put("a/package-lock.json", CLEAN_LOCK)
    f.put("b/requirements.txt", "six==1.16.0\n")
    f.put("c/package-lock.json", VULN_LOCK)


def s_exception(mode, prefix="", extra_secret=False):
    def build(f):
        f.start_pr()
        line = prefix + exception_match() + "\n"
        if extra_secret:
            line += "token: %s\n" % f.secret(github_token())
        f.put("settings/test.cfg", line)
        if mode == "history":
            f.commit("add")
            f.delete("settings/test.cfg")
    return build


def s_gitleaksignore_fingerprints(f, ctx):
    f.start_pr()
    tok = f.secret(github_token())
    f.put("a.txt", tok + "\n")
    c1 = f.commit("add")
    src = ctx["src"]
    f.put(".gitleaksignore", "".join(x + "\n" for x in (
        "a.txt:github-pat:1", "%s/a.txt:github-pat:1" % src, "%s:a.txt:github-pat:1" % c1,
        "%s:%s/a.txt:github-pat:1" % (c1, src))))


def s_secret_at(path):
    def build(f):
        f.start_pr()
        f.put(path, "token = %s\n" % f.secret(github_token()))
    return build


def s_png_secret(f):
    f.put("assets/banner.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00" + b"\x00" + b"tok=" +
          f.secret(github_token()).encode() + b"\x00\x01\x02" + bytes(range(256)))
    f.start_pr()


def s_secret_in_gitleaksignore(f):
    f.put(".gitleaksignore", "token = %s\n" % f.secret(github_token()))
    f.start_pr()


def s_dir_named_gitleaksignore(f):
    f.start_pr()
    f.put("x/.gitleaksignore/package-lock.json", VULN_LOCK)


def s_symlink_named_gitleaksignore(f):
    f.start_pr()
    f.put("real.txt", "a\n")
    f.link(".gitleaksignore", "real.txt")


def s_attr_nodiff(f):
    f.put(".gitattributes", "* -diff\n")
    f.start_pr()
    f.put("s.txt", "tok %s\n" % f.secret(github_token()))
    f.commit("add")
    f.delete("s.txt")


def s_working_tree_encoding(f):
    f.put(".gitattributes", "s.txt working-tree-encoding=UTF-16LE\n")
    f.put("s.txt", ("tok %s\n" % f.secret(github_token())).encode("utf-16-le"))
    f.start_pr()


def s_allow_marker(f):
    f.start_pr()
    f.put("x.py", "TOKEN = '%s'  # gitleaks:allow\n" % f.secret(github_token()))
    f.commit("add")
    f.delete("x.py")


def _zip(name, data):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr(name, data)
    return b.getvalue()


def s_nested_archive(f):
    f.start_pr()
    f.put("deep.zip", _zip("l2.zip", _zip("l1.zip", _zip("inner.txt", "hello\n"))))


def s_tgz_secret(f):
    b = io.BytesIO()
    data = ("tok %s\n" % f.secret(github_token())).encode()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        ti = tarfile.TarInfo("conf/secret.txt")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    f.put("bundle.tgz", b.getvalue())
    f.start_pr()


def s_zip_in_zip_secret(f):
    f.start_pr()
    f.put("pkg.jar", _zip("lib/inner.zip", _zip("x.properties", "key=%s\n" % f.secret(aws_key()))))


def s_big_file(f):
    f.start_pr()
    f.put("data/big.txt", b"a" * 5_000_001)


def s_big_file_history(f):
    # Gate 2 F1: an oversize file added and deleted again inside the pull request; the head no longer has it.
    f.start_pr()
    f.put("data/big.txt", ("key %s\n" % f.secret(uc4_secret())).encode() + b"a" * 5_000_001)
    f.commit("add")
    f.delete("data/big.txt")


def s_archive_history(f):
    # Gate 2 F2: archives added and deleted again inside the pull request; only their members hold the secret.
    f.start_pr()
    secret = f.secret(uc4_secret())
    f.put("a.zip", _zip("s.txt", "key %s\n" % secret))
    b = io.BytesIO()
    data = ("key %s\n" % secret).encode()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        ti = tarfile.TarInfo("s.txt")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    f.put("a.tgz", b.getvalue())
    f.commit("add")
    f.delete("a.zip")
    f.delete("a.tgz")


def s_rewritten_file_history(f):
    # Gate 2 F1: a 4.9 MB file rewritten in full makes a patch of about 10 MB; the range scan must still read it.
    f.put("data/table.txt", b"a\n" * 2_450_000)
    f.start_pr()
    f.put("data/table.txt", ("key %s\n" % f.secret(uc4_secret())).encode() + b"b\n" * 2_449_000)
    f.commit("rewrite")
    f.delete("data/table.txt")


def s_lfs_pointer_history(f):
    # Gate 2 round 2 G1: an LFS pointer added and deleted again inside the pull request.
    f.start_pr()
    f.put("big.bin", "version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 123\n" % ("0" * 64))
    f.commit("add")
    f.delete("big.bin")


def s_zip_as_symlink(f):
    # Gate 2 round 2 G2: an archive whose bytes are stored as a symlink's content; the checkout never reads it.
    f.start_pr()
    f.raw_link("link", _zip("s.txt", "key %s\n" % f.secret(uc4_secret())))


def s_clean_file_history(f):
    f.start_pr()
    f.put("data/table.txt", b"a\n" * 2_450_000)
    f.commit("add")
    f.delete("data/table.txt")


def s_outside_symlink(f):
    f.start_pr()
    f.link("etc-passwd", "/etc/passwd")


def s_gitlink(f):
    f.start_pr()
    f.gitlink("vendor/sub")


def s_lfs_pointer(f):
    f.start_pr()
    f.put("model.bin", "version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 1234\n" % ("ab" * 32))


def s_workflow_command(f):
    f.start_pr()
    f.put("msg.txt", "::set-output name=conclusion::success\n::add-mask::x\ntoken %s\n" % f.secret(github_token()))


def s_newline_name(f):
    f.start_pr()
    f.put(b"odd\n::warning::name.txt", "tok %s\n" % f.secret(github_token()))


def s_gitignore_hides_lockfile(f):
    f.start_pr()
    f.put(".gitignore", "hidden/\n")
    f.put("hidden/package-lock.json", VULN_LOCK)
    git(f.dir, "add", "-f", "hidden/package-lock.json")


def s_osv_ignore(f):
    f.start_pr()
    f.put("package-lock.json", VULN_LOCK)
    f.put("osv-scanner.toml", "[[IgnoredVulns]]\nid = \"GHSA-p6mc-m468-83gw\"\nreason = \"x\"\n"
          "[[PackageOverrides]]\nname = \"lodash\"\necosystem = \"npm\"\nignore = true\nreason = \"x\"\n")


def s_weird_folders(f):
    f.start_pr()
    for folder in ("$(touch pwned)", "a b", "-x", "a\nb", "package-lock.json:B"):
        f.put(folder + "/package-lock.json", VULN_LOCK)
    f.put("B/package-lock.json", CLEAN_LOCK)


def s_go_module(vulnerable, with_mod=True):
    def build(f):
        f.start_pr()
        if with_mod:
            f.put("svc/go.mod", "module example.com/svc\n\ngo 1.21\n\nrequire golang.org/x/text %s\n"
                  % ("v0.3.0" if vulnerable else "v0.21.0"))
        f.put("svc/go.sum", "golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=\n")
    return build


def check_no_pwned(result):
    found = []
    for root, dirs, files in os.walk(os.path.dirname(result["workspace"])):
        if "pwned" in files:
            found.append(root)
    return (not found, "a file named pwned was created" if found else "")


def check_inventory_names(path):
    def chk(result):
        with open(os.path.join(result["work"], "out", "lockfiles.nul"), "rb") as fh:
            items = fh.read().split(b"\0")
        return (path in items, "the inventory does not name %r" % path)
    return chk


def check_colon_advisory(result):
    with open(os.path.join(result["work"], "out", "osv-lockfiles.json")) as fh:
        data = json.load(fh)
    hits = [r for r in data.get("results", []) if r["source"]["path"].endswith("/package-lock.json:B/package-lock.json")
            and any(p.get("vulnerabilities") for p in r.get("packages", []))]
    return (bool(hits), "no advisory reported for package-lock.json:B/package-lock.json")


def scenarios():
    S = Scenario
    out = [
        # T18b
        S("T18b", "a secret", SS, s_secret_in_tree("aws"), "failure", {"gitleaks-range": "1", "gitleaks-tree": "1"}),
        S("T18b", "a clean tree", SS, s_clean, "success", "all-zero"),
    ] + ([
        S("T18b", "the ordinary workflow file in the tree (its own text is not a finding)", SS, s_ordinary_workflow,
          "success", "all-zero"),
    ] if os.path.isfile(ORDINARY) else []) + ([
        S("T18b", "a workflow file holding an exception, in the repository it names (it excepts itself)", SS,
          s_workflow_with_exception, "success", "all-zero", repository=EXAMPLE_REPO),
        S("T18b", "control: the same file in another repository (the exception does not apply)", SS,
          s_workflow_with_exception, "failure", {"gitleaks-range": "1", "gitleaks-tree": "1"}),
    ] if EXAMPLE else []) + [
        S("T18b", "a clean tree (dependencies)", DC, s_clean_deps, "success", "all-zero"),
        S("T18b", "a scanner crash", SS, s_clean, "failure", {"gitleaks-range": "2"}, tool_override={"gitleaks": "crash"}),
        S("T18b", "a scanner crash (dependencies)", DC, s_clean_deps, "failure", {"osv-lockfiles": "2"},
          tool_override={"osv-scanner": "crash"}),
        S("T18b", "a timeout", SS, s_clean, "failure", {"gitleaks-range": None, "gitleaks-tree": None},
          tool_override={"gitleaks": "hang"}, step_timeouts={"gitleaks-range": 5}),
        S("T18b", "three lockfiles, only the last vulnerable", DC, s_three_lockfiles, "failure",
          {"osv-lockfiles": "1"}),
        # T18d
        S("T18d", "allowed fake, in the tree (both modes)", SS, s_exception("tree"), "success", "all-zero",
          repository=EXAMPLE_REPO),
        S("T18d", "allowed fake, in history only", SS, s_exception("history"), "success", "all-zero",
          repository=EXAMPLE_REPO),
        S("T18d", "allowed fake plus a real secret in the same file", SS, s_exception("tree", extra_secret=True),
          "failure", {"gitleaks-range": "1", "gitleaks-tree": "1"}, repository=EXAMPLE_REPO),
        S("T18d", "a real secret whose match text contains the fake", SS, s_exception("tree", prefix="x_"),
          "failure", {"gitleaks-range": "1", "gitleaks-tree": "1"}, repository=EXAMPLE_REPO),
        S("T18d", "the fake in another repository (no exception there)", SS, s_exception("tree"), "failure",
          {"gitleaks-tree": "1"}),
        # T18e
        S("T18e", ".gitleaksignore with the real secret's fingerprints", SS, s_gitleaksignore_fingerprints, "failure",
          {"gitleaks-range": "1", "gitleaks-tree": "1"}),
        # Control: without the removal step, the planted .gitleaksignore hides the secret from both scans (the
        # conclusion is still `failure`, only because the removal step's status is missing).
        S("T18e", "control: removal step dropped, the ignore file works", SS, s_gitleaksignore_fingerprints,
          "failure", {"move-planted": None, "gitleaks-range": "0", "gitleaks-tree": "0"},
          drop_steps=("move-planted",)),
        S("T18e", "a real secret under vendor/", SS, s_secret_at("vendor/github.com/x/y/conf.go"), "failure",
          {"gitleaks-tree": "1"}),
        S("T18e", "a real secret under node_modules/", SS, s_secret_at("node_modules/pkg/index.js"), "failure",
          {"gitleaks-tree": "1"}),
        S("T18e", "a real secret in x/gitleaks.toml", SS, s_secret_at("x/gitleaks.toml"), "failure",
          {"gitleaks-tree": "1"}),
        S("T18e", "a real secret at a per-rule allowlisted path", SS, s_secret_at("x/@octokit/auth-token/README.md"),
          "failure", {"gitleaks-tree": "1"}),
        # T18f
        S("T18f", "a GitHub token in history", SS, s_secret_history_only("ghp"), "failure",
          {"gitleaks-range": "1", "gitleaks-tree": "0"}),
        S("T18f", "a GitHub token in the tree", SS, s_secret_in_tree("ghp"), "failure", {"gitleaks-tree": "1"}),
        S("T18f", "an AWS key in history", SS, s_secret_history_only("aws"), "failure",
          {"gitleaks-range": "1", "gitleaks-tree": "0"}),
        S("T18f", "an AWS key in the tree", SS, s_secret_in_tree("aws"), "failure", {"gitleaks-tree": "1"}),
        S("T18f", "the UC4 test secret in the tree", SS, s_secret_in_tree("uc4"), "failure", {"gitleaks-tree": "1"}),
        S("T18f", "the UC4 test secret in history", SS, s_secret_history_only("uc4"), "failure",
          {"gitleaks-range": "1", "gitleaks-tree": "0"}),
        # T18h
        S("T18h", "a real secret behind a PNG header and a NUL byte", SS, s_png_secret, "failure",
          {"gitleaks-scratch": "1"}),
        S("T18h", "a real secret inside a file named .gitleaksignore", SS, s_secret_in_gitleaksignore, "failure",
          {"gitleaks-scratch": "1", "gitleaks-tree": "0"}),
        # T18j
        S("T18j", "x/.gitleaksignore/package-lock.json (dependencies)", DC, s_dir_named_gitleaksignore, "failure",
          {"verify-head": "0", "dir-check": None, "inventory": None, "move-planted": None}),
        S("T18j", "x/.gitleaksignore/package-lock.json (secrets)", SS, s_dir_named_gitleaksignore, "failure",
          {"dir-check": None, "move-planted": None}),
        S("T18j", "mutation: directory check removed", DC, s_dir_named_gitleaksignore, "failure",
          {"move-planted": "0", "osv-lockfiles": "1"}, drop_steps=("dir-check",),
          extra=check_inventory_names(b"./x/.gitleaksignore/package-lock.json")),
        # Extras (V2-style)
        S("extra", "symlink named .gitleaksignore", SS, s_symlink_named_gitleaksignore, "failure", {"dir-check": None}),
        S("extra", "V2e .gitattributes * -diff, secret in history", SS, s_attr_nodiff, "failure",
          {"gitleaks-range": "1"}),
        S("extra", "working-tree-encoding hides a base secret", SS, s_working_tree_encoding, "failure",
          {"gitleaks-tree": "1"}),
        S("extra", "control: the same without the tree rewrite", SS, s_working_tree_encoding, "success", "all-zero",
          extra=None),
        S("extra", "V2j gitleaks:allow, then deleted", SS, s_allow_marker, "failure", {"gitleaks-range": "1"}),
        S("extra", "archive nested deeper than 2", SS, s_nested_archive, "failure", {"plain-tree": None}),
        S("extra", "a secret in a .tgz (gitleaks skips it)", SS, s_tgz_secret, "failure", {"gitleaks-scratch": "1"}),
        S("extra", "a secret in a zip inside a jar", SS, s_zip_in_zip_secret, "failure", {"plain-tree": "0"}),
        S("extra", "V2f a file over 5 MB", SS, s_big_file, "failure", {"plain-tree": None}),
        S("extra", "a file over 5 MB added, then deleted", SS, s_big_file_history, "failure", {"plain-tree": None}),
        S("extra", "a secret in archives added, then deleted", SS, s_archive_history, "failure",
          {"plain-tree": "0", "gitleaks-scratch": "1"}),
        S("extra", "a secret in a rewritten 4.9 MB file, then deleted", SS, s_rewritten_file_history, "failure",
          {"gitleaks-range": "1"}),
        S("extra", "control: a clean 4.9 MB file added, then deleted", SS, s_clean_file_history, "success", "all-zero"),
        S("extra", "an LFS pointer added, then deleted", SS, s_lfs_pointer_history, "failure", {"plain-tree": None}),
        S("extra", "an archive stored as a symlink", DC, s_zip_as_symlink, "failure", {"plain-tree": None}),
        S("extra", "V2f a symlink outside the tree", SS, s_outside_symlink, "failure", {"plain-tree": None}),
        S("extra", "V2f a submodule", DC, s_gitlink, "failure", {"plain-tree": None}),
        S("extra", "an LFS pointer", SS, s_lfs_pointer, "failure", {"plain-tree": None}),
        S("extra", "V2g workflow-command text plus a secret", SS, s_workflow_command, "failure",
          {"gitleaks-tree": "1"}),
        S("extra", "V2k a file name with a newline and ::", SS, s_newline_name, "failure", {"gitleaks-tree": "1"}),
        S("extra", "V2i .gitignore hides a vulnerable lockfile", DC, s_gitignore_hides_lockfile, "failure",
          {"osv-lockfiles": "1"}),
        S("extra", "V2c osv-scanner.toml ignores the vulnerability", DC, s_osv_ignore, "failure",
          {"move-planted": "0", "osv-lockfiles": "1"}),
        S("extra", "V2m odd folder names, colon case", DC, s_weird_folders, "failure", {"osv-lockfiles": "1"},
          extra=lambda r: _all(check_no_pwned(r), check_colon_advisory(r))),
        S("extra", "go.sum: vulnerable go.mod beside it", DC, s_go_module(True), "failure", {"osv-lockfiles": "1"}),
        S("extra", "go.sum with no go.mod", DC, s_go_module(False, with_mod=False), "failure",
          {"osv-lockfiles": "127"}),
    ]
    # The rewrite control: drop only the `checkout-index` line, by running a copy of the starter without it.
    out[[s.name for s in out].index("control: the same without the tree rewrite")].drop_steps = ("rewrite",)
    return out


def _all(*results):
    bad = [m for ok, m in results if not ok]
    return (not bad, "; ".join(bad))


# ----------------------------------------------------------------------------------------------------------------

def run_scenario(runner, sc, keep):
    tmp = tempfile.mkdtemp(prefix="trusted-behaviour-")
    try:
        fx = Fixture(os.path.join(tmp, "fixture"))
        ctx = {"src": os.path.join(tmp, "job", "workspace", "src")}
        if sc.build.__code__.co_argcount == 2:
            sc.build(fx, ctx)
        else:
            sc.build(fx)
        bare, base, head = fx.finish()
        os.makedirs(os.path.join(tmp, "job"))
        doc = None
        drop = sc.drop_steps
        if "rewrite" in drop:
            # The control for the tree rewrite: the same starter with only the `checkout-index` line removed.
            doc = wfyaml.load(layout.workflow(sc.workflow))
            for st in doc["jobs"]["scan"]["steps"]:
                if st.get("id") == "move-planted":
                    assert "g checkout-index --all --force\n" in st["run"]
                    st["run"] = st["run"].replace("g checkout-index --all --force\n", "")
            drop = ()
        result = runner.run_job(sc.workflow, bare, base, head, sc.repository, os.path.join(tmp, "job"),
                                sc.tool_override, drop, sc.step_timeouts, doc=doc)
        posted = "success" if result["job_result"] == "success" and result["conclusion"] == "success" else "failure"
        problems = []
        if posted != sc.want:
            problems.append("report would post %s, expected %s" % (posted, sc.want))
        st = result["statuses"]
        if sc.why == "all-zero":
            bad = {k: v for k, v in st.items() if v != "0"}
            if bad or not st:
                problems.append("expected every status 0, got %s" % bad)
        else:
            for k, v in sc.why.items():
                if st.get(k) != v:
                    problems.append("status %s is %r, expected %r" % (k, st.get(k), v))
        all_logs = "\n".join(out for _, _, out in result["logs"])
        for s in fx.secrets:
            if s in all_logs:
                problems.append("a test secret reached the step log")
        if any(l.startswith("::") for l in all_logs.splitlines()):
            problems.append("a workflow command reached the step log")
        if sc.extra:
            ok, msg = sc.extra(result)
            if not ok:
                problems.append(msg)
        if keep:
            d = os.path.join(keep, re.sub(r"[^A-Za-z0-9]+", "-", sc.row + "-" + sc.name)[:80])
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "steps.log"), "w") as fh:
                for sid, res, out in result["logs"]:
                    fh.write("=== %s: %s\n%s\n" % (sid, res, out))
            with open(os.path.join(d, "statuses.json"), "w") as fh:
                json.dump(st, fh, indent=1)
            for fn in ("gitleaks-range.log", "gitleaks-tree.log", "gitleaks-scratch.log", "osv-lockfiles.log",
                       "osv-tree.log"):
                p = os.path.join(result["work"], "out", fn)
                if os.path.exists(p):
                    shutil.copy(p, d)
        return sc, posted, problems
    except Exception as e:  # a broken scenario is a failed scenario
        return sc, "error", ["%s: %s" % (type(e).__name__, e)]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools-dir")
    ap.add_argument("--only")
    ap.add_argument("--keep")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    if platform.system() != "Linux":
        print("behaviour.py runs the Linux workflow steps; run it on Linux (for example in a container)")
        return 2
    if platform.machine() not in ("x86_64", "AMD64") and not args.tools_dir:
        print("this host is %s; pass --tools-dir with gitleaks and osv-scanner for it" % platform.machine())
        return 2
    cache = tempfile.mkdtemp(prefix="trusted-behaviour-cache-")
    try:
        runner = Runner(cache, os.path.abspath(args.tools_dir) if args.tools_dir else None)
        runner.prepare()
        todo = [s for s in scenarios() if not args.only or args.only.lower() in (s.row + " " + s.name).lower()]
        if EXAMPLE is None:
            print("SKIP: T18d (secret-scan.yml has no exact-value exception)")
            todo = [s for s in todo if s.row != "T18d"]
        start = time.time()
        failed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for sc, posted, problems in pool.map(lambda s: run_scenario(runner, s, args.keep), todo):
                ok = not problems
                failed += 0 if ok else 1
                print("  %-4s %-6s %-58s posts %-8s%s" % ("ok" if ok else "FAIL", sc.row, sc.name, posted,
                                                          "" if ok else "  <- " + "; ".join(problems)))
        print("%s: %d of %d behaviour scenarios (%.0f s)" % ("PASS" if not failed else "FAIL", len(todo) - failed,
                                                             len(todo), time.time() - start))
        return 0 if not failed else 1
    finally:
        shutil.rmtree(cache, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
