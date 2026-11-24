import subprocess
from pathlib import Path

import pytest

from scoper.incidents import load_incidents

TJ_BAD = "0e58ed8671d6b60d0890c21b07f8835ace038e67"
RD_BAD = "f0d342d24037bb11d26b9bd8496e0808ba32e9ec"
SAFE_SHA = "2f7c5bfce28377bc069a65ba478de0a74aa0ca32"


@pytest.fixture(scope="session")
def incidents():
    return load_incidents()


def _git(repo: Path, *args: str, env: dict | None = None) -> str:
    base = {
        "GIT_AUTHOR_NAME": "Lab",
        "GIT_AUTHOR_EMAIL": "lab@example.invalid",
        "GIT_COMMITTER_NAME": "Lab",
        "GIT_COMMITTER_EMAIL": "lab@example.invalid",
        "HOME": str(repo),
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }
    base.update(env or {})
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=base
    ).stdout.strip()


@pytest.fixture
def make_repo(tmp_path):
    """Build a git repo from a list of {path: content} snapshots; return (repo, [sha, ...])."""

    def build(snapshots: list[dict[str, str]]):
        repo = tmp_path / "repo"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        shas = []
        for i, files in enumerate(snapshots):
            for rel, content in files.items():
                f = repo / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(content)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "--allow-empty", "-m", f"c{i}")
            shas.append(_git(repo, "rev-parse", "HEAD"))
        return repo, shas

    return build
