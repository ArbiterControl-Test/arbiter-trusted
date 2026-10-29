#!/usr/bin/env python3
"""T18c (PLAN-177-R7): the starters' `report` step against a local stub of Arbiter and of GitHub's token endpoint.

The `report` job's `run:` block is taken from each starter as written. Only Arbiter's URL literal is pointed at the
local stub (the self-test, T18.5, proves the shipped file uses the literal), and `sleep` is replaced by a stub that
records how long the script asked to wait, so the 60-second wait is checked without waiting.

Cases: 429 then 201 (retried with backoff; one stored post); 401 then 201 (retried once after 60 s, with a fresh
token); 401 twice (fails); 503 and network errors beyond 3 retries (fails, no more posts); 400 (fails, no retry);
the body, path, headers and audience; the conclusion rule (`success` only if the scan job and its conclusion are
both `success`); and the token never reaching the step log.

Run with `python3 -I ci/trusted-workflows/report_retry_test.py` from arbiter-control-plane/.
"""

import http.server
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layout  # noqa: E402
import wfyaml  # noqa: E402



class Stub:
    """Answers POSTs from a script of status codes; 'drop' closes the connection with no answer."""

    def __init__(self):
        self.posts = []
        self.token_requests = []
        self.post_script = []
        self.token_script = []
        self.tokens = []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                stub.token_requests.append({"path": u.path, "query": urllib.parse.parse_qs(u.query),
                                            "auth": self.headers.get("Authorization")})
                action = stub.token_script.pop(0) if stub.token_script else 200
                if action == "drop":
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                tok = "eyJ" + secrets.token_urlsafe(48)
                stub.tokens.append(tok)
                body = json.dumps({"count": 1, "value": tok}).encode()
                self.send_response(action)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                stub.posts.append({"path": self.path, "auth": self.headers.get("Authorization"),
                                   "ctype": self.headers.get("Content-Type"), "body": body})
                action = stub.post_script.pop(0) if stub.post_script else 500
                if action == "drop":
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                out = json.dumps({"reason": "stub"}).encode()
                self.send_response(action)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


SLEEP_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$1" >> "$SLEEP_LOG"
"""


def report_script(name):
    doc = wfyaml.load(layout.workflow(name))
    steps = doc["jobs"]["report"]["steps"]
    assert len(steps) == 1, "report has one step"
    run = steps[0]["run"]
    assert run.count(literal(run, "ARBITER_URL")) == 1, "the URL literal appears once"
    return run, doc["jobs"]["report"]["env"]


def literal(run, name):
    """The value set with NAME='...' in report: the example value, or the one a trusted repository set."""
    m = re.search(r"^\s*%s='([^']+)'" % name, run, re.M)
    assert m is not None, "report sets %s as a literal" % name
    return m.group(1)


def run_case(name, post_script, token_script=None, scan_result="success", scan_conclusion="success"):
    run, _ = report_script(name)
    stub = Stub()
    tmp = tempfile.mkdtemp(prefix="trusted-report-")
    try:
        stub.post_script = list(post_script)
        stub.token_script = list(token_script or [])
        script = os.path.join(tmp, "report.sh")
        with open(script, "w") as fh:
            fh.write(run.replace(literal(run, "ARBITER_URL"), "http://127.0.0.1:%d" % stub.port))
        bindir = os.path.join(tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "sleep"), "w") as fh:
            fh.write(SLEEP_STUB)
        os.chmod(os.path.join(bindir, "sleep"), 0o755)
        request_token = secrets.token_urlsafe(32)
        env = {
            "PATH": bindir + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": tmp, "LANG": "C.UTF-8", "SLEEP_LOG": os.path.join(tmp, "sleeps"),
            "GITHUB_REPOSITORY": "acme/payments-api",
            "PR_NUMBER": "42", "PR_HEAD_SHA": "0123456789abcdef0123456789abcdef01234567",
            "SCAN_RESULT": scan_result, "SCAN_CONCLUSION": scan_conclusion,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "http://127.0.0.1:%d/token?api-version=2.0" % stub.port,
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": request_token,
        }
        p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", script], env=env, cwd=tmp,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        sleeps = []
        if os.path.exists(env["SLEEP_LOG"]):
            with open(env["SLEEP_LOG"]) as fh:
                sleeps = [int(x) for x in fh.read().split()]
        log = p.stdout.decode("utf-8", "replace")
        return {"rc": p.returncode, "log": log, "posts": stub.posts, "token_requests": stub.token_requests,
                "tokens": stub.tokens, "sleeps": sleeps, "request_token": request_token}
    finally:
        stub.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)
        return cond

    for name, check_name in (("secret-scan.yml", "gitleaks"), ("dependency-check.yml", "dependency-check")):
        print(name)

        def common(r, desc):
            for t in r["tokens"] + [r["request_token"]]:
                check(t not in r["log"], "%s %s: a token reached the step log" % (name, desc))
            check(not any(l.startswith("::") for l in r["log"].splitlines()),
                  "%s %s: a workflow command in the log" % (name, desc))
            for tr in r["token_requests"]:
                check(tr["query"].get("audience") == [literal(report_script(name)[0], "ARBITER_AUDIENCE")] and tr["query"].get("api-version") == ["2.0"],
                      "%s %s: token requested for the wrong audience" % (name, desc))
                check(tr["auth"] == "bearer " + r["request_token"], "%s %s: token request not authorised" % (name, desc))
            for k, post in enumerate(r["posts"]):
                check(post["path"] == "/api/trusted-check-results/acme/payments-api/42",
                      "%s %s: wrong path %s" % (name, desc, post["path"]))
                check(post["ctype"] == "application/json", "%s %s: wrong content type" % (name, desc))
                check(post["auth"] in ["Bearer " + t for t in r["tokens"]], "%s %s: not the identity token" % (name, desc))

        # 429, then 201: retried with backoff; posted once successfully.
        r = run_case(name, [429, 201])
        common(r, "429-then-201")
        ok = check(r["rc"] == 0 and len(r["posts"]) == 2 and r["sleeps"] == [10] and len(r["tokens"]) == 1,
                   "%s 429-then-201: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        body = json.loads(r["posts"][-1]["body"]) if r["posts"] else {}
        ok &= check(body == {"check": check_name, "head_sha": "0123456789abcdef0123456789abcdef01234567",
                             "conclusion": "success"}, "%s: wrong body %r" % (name, body))
        print("  %-4s 429 then 201: retried after 10 s with the same token; stored once" % ("ok" if ok else "FAIL"))

        # 401, then 201: one retry after 60 s, with a fresh token.
        r = run_case(name, [401, 201])
        common(r, "401-then-201")
        ok = check(r["rc"] == 0 and len(r["posts"]) == 2 and r["sleeps"] == [60] and len(r["tokens"]) == 2
                   and r["posts"][0]["auth"] != r["posts"][1]["auth"],
                   "%s 401-then-201: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        print("  %-4s 401 then 201: retried once after 60 s with a fresh token" % ("ok" if ok else "FAIL"))

        # 401 twice: fails after one retry.
        r = run_case(name, [401, 401, 201])
        common(r, "401-twice")
        ok = check(r["rc"] != 0 and len(r["posts"]) == 2 and r["sleeps"] == [60],
                   "%s 401-twice: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        print("  %-4s 401 twice: fails, no third post" % ("ok" if ok else "FAIL"))

        # 503 four times: 3 retries with backoff, then fails and posts nothing more.
        r = run_case(name, [503, 503, 503, 503, 201])
        common(r, "503x4")
        ok = check(r["rc"] != 0 and len(r["posts"]) == 4 and r["sleeps"] == [10, 20, 40],
                   "%s 503x4: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        print("  %-4s 503 four times: 3 retries (10, 20, 40 s), then fails" % ("ok" if ok else "FAIL"))

        # A network error (connection closed), then 201.
        r = run_case(name, ["drop", 201])
        common(r, "drop-then-201")
        ok = check(r["rc"] == 0 and len(r["posts"]) == 2 and r["sleeps"] == [10],
                   "%s drop-then-201: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        print("  %-4s network error then 201: retried" % ("ok" if ok else "FAIL"))

        # The token endpoint fails once (a network error), then works.
        r = run_case(name, [201], token_script=["drop", 200])
        common(r, "token-drop")
        ok = check(r["rc"] == 0 and len(r["posts"]) == 1 and r["sleeps"] == [10],
                   "%s token-drop: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        print("  %-4s token request network error: retried" % ("ok" if ok else "FAIL"))

        # 429 and network errors share the budget of 3 retries.
        r = run_case(name, [429, "drop", 503, 429, 201])
        common(r, "mixed")
        ok = check(r["rc"] != 0 and len(r["posts"]) == 4, "%s mixed: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        print("  %-4s 429, network error, 503, 429: fails after 3 retries" % ("ok" if ok else "FAIL"))

        # 400: no retry.
        r = run_case(name, [400, 201])
        common(r, "400")
        ok = check(r["rc"] != 0 and len(r["posts"]) == 1 and r["sleeps"] == [],
                   "%s 400: %r" % (name, {k: r[k] for k in ("rc", "sleeps")}))
        print("  %-4s 400: fails, no retry" % ("ok" if ok else "FAIL"))

        # 200 (a replay after a lost answer) counts as delivered.
        r = run_case(name, [200])
        ok = check(r["rc"] == 0 and len(r["posts"]) == 1, "%s 200: rc %r" % (name, r["rc"]))
        print("  %-4s 200 (replay): delivered" % ("ok" if ok else "FAIL"))

        # The conclusion rule.
        for res, concl, want in (("success", "success", "success"), ("success", "failure", "failure"),
                                 ("failure", "success", "failure"), ("cancelled", "", "failure"),
                                 ("success", "", "failure"), ("skipped", "success", "failure")):
            r = run_case(name, [201], scan_result=res, scan_conclusion=concl)
            body = json.loads(r["posts"][0]["body"]) if r["posts"] else {}
            ok = check(r["rc"] == 0 and body.get("conclusion") == want,
                       "%s conclusion(%s,%s): %r" % (name, res, concl, body))
            print("  %-4s scan result %-9s conclusion %-8s -> posts %s" % ("ok" if ok else "FAIL", res, concl or "''",
                                                                         body.get("conclusion")))

    if failures:
        print("FAIL: T18c")
        for m in failures:
            print("  " + m)
        return 1
    print("PASS: T18c (report retries: 429/503/network 3x with backoff; one 401 retried after 60 s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
