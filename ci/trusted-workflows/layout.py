"""Where the trusted workflow starters are, so the tests run in either layout (Gate 2 F3).

* The Arbiter repository: <root>/starter/trusted-workflows/ holds secret-scan.yml, dependency-check.yml, caller.yml
  and gitleaks/.
* A trusted repository built by the README's step 1: <root>/.github/workflows/ holds the two workflows, and
  <root>/gitleaks/ and <root>/caller.yml sit at the top.

<root> is the folder that holds ci/trusted-workflows/. The Arbiter layout wins when its secret-scan.yml exists.
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_STARTER = os.path.join(ROOT, "starter", "trusted-workflows")

if os.path.isfile(os.path.join(_STARTER, "secret-scan.yml")):
    NAME = "arbiter"
    WORKFLOWS = _STARTER
    GITLEAKS = os.path.join(_STARTER, "gitleaks")
    CALLER = os.path.join(_STARTER, "caller.yml")
else:
    NAME = "trusted repository"
    WORKFLOWS = os.path.join(ROOT, ".github", "workflows")
    GITLEAKS = os.path.join(ROOT, "gitleaks")
    CALLER = os.path.join(ROOT, "caller.yml")


def workflow(name):
    """The path of a starter file by its starter name: a workflow, or caller.yml."""
    return CALLER if name == "caller.yml" else os.path.join(WORKFLOWS, name)
