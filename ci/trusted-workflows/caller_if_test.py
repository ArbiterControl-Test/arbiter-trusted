#!/usr/bin/env python3
"""T18i (PLAN-177-R7): the caller's job-level `if`.

A title edit skips both trusted jobs, so nothing is posted and a stored `success` stands; a retarget (an `edited`
event that changes the base) runs both, so a fresh scan is stored under the new base. Also checks that the caller
is exactly the plan's shape: `pull_request_target` with the four types, `{ contents: read, id-token: write }`,
jobs that only call a pinned trusted workflow, with no `with:` and no `secrets:`.

Run with `python3 -I ci/trusted-workflows/caller_if_test.py` from arbiter-control-plane/.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghexpr  # noqa: E402
import layout  # noqa: E402
import wfyaml  # noqa: E402

CALLER = layout.CALLER
USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/(secret-scan|dependency-check)\.yml@[0-9a-f]{40}$")


def pr(base="main"):
    return {"number": 42, "head": {"sha": "a" * 40, "ref": "feature"}, "base": {"sha": "b" * 40, "ref": base},
            "title": "t"}


CASES = [
    ("opened", {"action": "opened", "pull_request": pr()}, True),
    ("synchronize (new head)", {"action": "synchronize", "pull_request": pr()}, True),
    ("reopened", {"action": "reopened", "pull_request": pr()}, True),
    ("title edit", {"action": "edited", "changes": {"title": {"from": "old title"}}, "pull_request": pr()}, False),
    ("body edit", {"action": "edited", "changes": {"body": {"from": "old body"}}, "pull_request": pr()}, False),
    ("edit with no changes object", {"action": "edited", "pull_request": pr()}, False),
    ("retarget", {"action": "edited", "changes": {"base": {"ref": {"from": "main"}, "sha": {"from": "c" * 40}}},
                  "pull_request": pr("release")}, True),
    ("retarget from a branch named 0", {"action": "edited", "changes": {"base": {"ref": {"from": "0"},
                                                                                  "sha": {"from": "c" * 40}}},
                                        "pull_request": pr("main")}, True),
    ("title and base edited together", {"action": "edited", "changes": {"title": {"from": "x"},
                                                                         "base": {"ref": {"from": "main"}}},
                                        "pull_request": pr("release")}, True),
]


def main():
    doc = wfyaml.load(CALLER)
    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    check(set(doc) == {"name", "on", "permissions", "jobs"}, "caller: unexpected top-level keys")
    check(doc.get("on") == {"pull_request_target": {"types": ["opened", "synchronize", "reopened", "edited"]}},
          "caller: must be on pull_request_target, types opened/synchronize/reopened/edited")
    check(doc.get("permissions") == {"contents": "read", "id-token": "write"},
          "caller: permissions must be exactly { contents: read, id-token: write }")
    jobs = doc.get("jobs") or {}
    check(set(jobs) == {"secret-scan", "dependency-check"}, "caller: the jobs must be secret-scan and dependency-check")
    ifs = set()
    for name, job in jobs.items():
        check(set(job) == {"if", "uses"}, "caller/%s: a job may only have `if` and `uses` (no with:, no secrets:)"
              % name)
        check(bool(USES_RE.match(job.get("uses") or "")) and (job.get("uses") or "").split("/")[-1].startswith(name),
              "caller/%s: uses must be <owner>/<repo>/.github/workflows/%s.yml@<40-hex commit>" % (name, name))
        ifs.add(job.get("if"))
    check(len(ifs) == 1, "caller: both jobs must use the same `if`")

    for desc, event, want in CASES:
        ctx = {"github": {"event_name": "pull_request_target", "event": event}}
        for name, job in jobs.items():
            got = ghexpr.evaluate_if(job.get("if"), ctx)
            ok = got == want
            print("  %-4s %-34s %-17s %s" % ("ok" if ok else "FAIL", desc, name, "runs" if got else "skipped"))
            check(ok, "T18i %s: %s should %s" % (desc, name, "run" if want else "be skipped"))

    # Mutations: an `if` that ignores retargets, and no `if` at all, must each fail a case above.
    for desc, mutated in (("if ignores retargets", "github.event.action != 'edited'"), ("no if", None)):
        wrong = [c for c, event, want in CASES
                 if ghexpr.evaluate_if(mutated, {"github": {"event_name": "pull_request_target", "event": event}})
                 != want]
        print("  %-4s mutation %-26s fails %d case(s)" % ("ok" if wrong else "FAIL", desc, len(wrong)))
        check(bool(wrong), "T18i mutation %r was not caught" % desc)

    # Both jobs skipped on a title edit means neither `scan` nor `report` runs: nothing is posted.
    if failures:
        print("FAIL: T18i")
        for m in failures:
            print("  " + m)
        return 1
    print("PASS: T18i (title edit skips both jobs, nothing posted; a retarget runs a fresh scan)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
