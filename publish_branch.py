"""Publish the working tree as one commit on a branch (no git binary needed).

Uses the GitHub Git Data API: blobs -> tree -> commit -> ref.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
from pathlib import Path

import requests

OWNER = os.environ.get("MIZAN_OWNER", "Toufiqtoufiqbo")
REPO = os.environ.get("MIZAN_REPO", "mizan")
BRANCH = os.environ.get("MIZAN_BRANCH", "fix/mizan-021-postgres-ci-hardening")
BASE = os.environ.get("MIZAN_BASE", "main")
ROOT = Path(__file__).resolve().parent
API = "https://api.github.com"

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".hypothesis",
    ".schemathesis",
    "demo-proofs",
    "node_modules",
}
SKIP_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".log"}


def session() -> requests.Session:
    token = os.environ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    client = requests.Session()
    client.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "User-Agent": "mizan-publisher",
            "Accept": "application/vnd.github+json",
        }
    )
    return client


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def local_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.suffix in SKIP_SUFFIXES:
            continue
        if relative.parts and relative.parts[0] in {"mizan.egg-info", "build", "dist"}:
            continue
        files.append(path)
    return sorted(files)


def main() -> int:
    client = session()

    base_ref = client.get(f"{API}/repos/{OWNER}/{REPO}/git/ref/heads/{BASE}").json()
    base_commit = base_ref["object"]["sha"]
    base_tree = client.get(f"{API}/repos/{OWNER}/{REPO}/git/commits/{base_commit}").json()["tree"]["sha"]
    remote = client.get(f"{API}/repos/{OWNER}/{REPO}/git/trees/{base_tree}?recursive=1").json()
    remote_map = {entry["path"]: entry["sha"] for entry in remote.get("tree", []) if entry["type"] == "blob"}

    changed: list[tuple[str, Path]] = []
    for path in local_files():
        relative = path.relative_to(ROOT).as_posix()
        data = path.read_bytes()
        if remote_map.get(relative) == blob_sha(data):
            continue
        changed.append((relative, path))

    print(f"changed files: {len(changed)}")
    for relative, _ in changed:
        print(f"  {relative}")

    if not changed:
        print("nothing to publish")
        return 0

    # The branch, from the base.
    exists = client.get(f"{API}/repos/{OWNER}/{REPO}/git/ref/heads/{BRANCH}")
    if exists.status_code == 404:
        response = client.post(
            f"{API}/repos/{OWNER}/{REPO}/git/refs",
            json={"ref": f"refs/heads/{BRANCH}", "sha": base_commit},
        )
        response.raise_for_status()
        print(f"created branch {BRANCH}")

    entries = []
    for relative, path in changed:
        data = path.read_bytes()
        response = client.post(
            f"{API}/repos/{OWNER}/{REPO}/git/blobs",
            json={"content": base64.b64encode(data).decode("ascii"), "encoding": "base64"},
        )
        response.raise_for_status()
        entries.append({"path": relative, "mode": "100644", "type": "blob", "sha": response.json()["sha"]})

    tree = client.post(
        f"{API}/repos/{OWNER}/{REPO}/git/trees",
        json={"base_tree": base_tree, "tree": entries},
    )
    tree.raise_for_status()

    message = sys.argv[1] if len(sys.argv) > 1 else "chore: publish the working tree"
    commit = client.post(
        f"{API}/repos/{OWNER}/{REPO}/git/commits",
        json={"message": message, "tree": tree.json()["sha"], "parents": [base_commit]},
    )
    commit.raise_for_status()
    commit_sha = commit.json()["sha"]

    update = client.patch(
        f"{API}/repos/{OWNER}/{REPO}/git/refs/heads/{BRANCH}",
        json={"sha": commit_sha, "force": False},
    )
    update.raise_for_status()
    print(f"commit: {commit_sha}")
    print(f"branch: https://github.com/{OWNER}/{REPO}/tree/{BRANCH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
