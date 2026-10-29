#!/usr/bin/env python3
"""The plain-tree step's history pass, on any host with git (Gate 2 round 2, G3).

behaviour.py runs every step with the pinned scanners, on Linux only. This test runs only plain-tree's Python, taken
from secret-scan.yml as written, against small fixture repositories built with the system git, so the history
rules are proven wherever the self-test runs:

* a file over 5 MB added, then deleted, fails;
* an archive added, then deleted, has its members written for scanning;
* a Git LFS pointer added, then deleted, fails;
* a symlink whose content is an archive fails, at the head and in history only;
* a symlink whose content is over 4,096 bytes fails, with no NUL byte in it;
* a clean file added, then deleted, and an ordinary symlink, pass.
"""

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layout  # noqa: E402

SECRET = "ARBITER-UC4-TEST-" + "0123456789abcdef" * 2
LFS = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\nsize 123\n"
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "fixture",
           "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "fixture",
           "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}


def plain_tree_python():
    with open(layout.workflow("secret-scan.yml")) as fh:
        text = fh.read()
    step = text.split("id: plain-tree", 1)[1]
    body = step.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
    return "\n".join(line[10:] for line in body.split("\n")) + "\n"


def zipped(name, data):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return b.getvalue()


class Repo:
    def __init__(self, path):
        self.path = path
        os.makedirs(path)
        self.git("init", "-q", "-b", "main")
        self.put("README.md", b"fixture\n")
        self.base = self.commit("base")
        self.git("checkout", "-q", "-b", "feature")

    def git(self, *args, data=None):
        env = dict(os.environ, **GIT_ENV)
        return subprocess.run(["git", *args], cwd=self.path, env=env, input=data, stdout=subprocess.PIPE,
                              check=True).stdout.decode().strip()

    def put(self, name, data):
        with open(os.path.join(self.path, name), "wb") as fh:
            fh.write(data)

    def delete(self, name):
        self.git("rm", "-q", "-f", "--", name)

    def raw_link(self, name, data):
        """A symlink whose stored content is any bytes (what `git update-index --cacheinfo 120000` allows)."""
        oid = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=self.path, input=data,
                             stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "120000,%s,%s" % (oid, name))

    def commit(self, msg):
        self.git("add", "-A")
        return self.commit_index(msg)

    def commit_index(self, msg, checkout=True):
        self.git("commit", "-q", "--allow-empty", "--no-verify", "-m", msg)
        if checkout:  # a link target longer than the host allows cannot be checked out; the pass reads git objects
            self.git("reset", "-q", "--hard")
        return self.git("rev-parse", "HEAD")


def run(script, repo, head, tmp):
    scratch = tempfile.mkdtemp(dir=tmp)
    env = dict(os.environ, PR_BASE_SHA=repo.base, PR_HEAD_SHA=head, **GIT_ENV)
    p = subprocess.run([sys.executable, "-I", script, repo.path, scratch], cwd=tmp, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    counts = {m.group(2): int(m.group(1)) for m in re.finditer(r"^plain-tree: (\d+) (.+)$", p.stdout, re.M)}
    members = b""
    for f in sorted(os.listdir(scratch)):
        with open(os.path.join(scratch, f), "rb") as fh:
            members += fh.read()
    return p.returncode, counts, members, p.stdout


def main():
    tmp = tempfile.mkdtemp(prefix="trusted-history-")
    failed = []
    try:
        script = os.path.join(tmp, "plain_tree.py")
        with open(script, "w") as fh:
            fh.write(plain_tree_python())

        def case(name, build, want_rc, want_count=None, want_member=None):
            repo = Repo(os.path.join(tmp, name.replace(" ", "-")))
            head = build(repo)
            rc, counts, members, out = run(script, repo, head, tmp)
            ok = rc == want_rc
            if want_count is not None:
                ok = ok and counts.get(want_count, 0) >= 1
            if want_member is not None:
                ok = ok and (want_member.encode() in members)
            print("  %-4s %s" % ("ok" if ok else "FAIL", name))
            if not ok:
                failed.append(name)
                print("       exit %d; %s" % (rc, out.strip().replace("\n", "; ")))

        def big_then_deleted(r):
            r.put("big.txt", ("key %s\n" % SECRET).encode() + b"a" * 5_000_001)
            r.commit("add")
            r.delete("big.txt")
            return r.commit_index("delete")

        def zip_then_deleted(r):
            r.put("a.zip", zipped("s.txt", "key %s\n" % SECRET))
            r.commit("add")
            r.delete("a.zip")
            return r.commit_index("delete")

        def lfs_then_deleted(r):
            r.put("lfs.bin", LFS)
            r.commit("add")
            r.delete("lfs.bin")
            return r.commit_index("delete")

        def zip_as_link(r):
            r.raw_link("link", zipped("s.txt", "key %s\n" % SECRET))
            return r.commit_index("add")

        def zip_as_link_then_deleted(r):
            r.raw_link("link", zipped("s.txt", "key %s\n" % SECRET))
            r.commit_index("add")
            r.delete("link")
            return r.commit_index("delete")

        def long_link(r):
            r.raw_link("link", b"a" * 5000)  # no NUL: only the 4,096-byte rule fails it
            return r.commit_index("add", checkout=False)

        def clean_then_deleted(r):
            r.put("clean.txt", b"a\n" * 1000)
            r.commit("add")
            r.delete("clean.txt")
            return r.commit_index("delete")

        def ordinary_link(r):
            os.symlink("README.md", os.path.join(r.path, "readme-link"))
            return r.commit("add")

        case("a file over 5 MB added, then deleted", big_then_deleted, 1, "files over 5 MB in history")
        case("an archive added, then deleted", zip_then_deleted, 0, None, SECRET)
        case("an LFS pointer added, then deleted", lfs_then_deleted, 1, "LFS pointers")
        case("an archive stored as a symlink, at the head", zip_as_link, 1, "symlinks that are not links")
        case("an archive stored as a symlink, then deleted", zip_as_link_then_deleted, 1, "symlinks that are not links")
        case("a symlink whose content is over 4,096 bytes", long_link, 1, "symlinks that are not links")
        case("control: a clean file added, then deleted", clean_then_deleted, 0)
        case("control: an ordinary symlink", ordinary_link, 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("%s: plain-tree's history pass (%d failed)" % ("PASS" if not failed else "FAIL", len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
