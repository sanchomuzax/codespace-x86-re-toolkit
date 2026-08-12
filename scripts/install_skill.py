#!/usr/bin/env python3
"""Install the portable Agent Skill for one supported client."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil


SKILL_NAME = "codespace-x86-re"


def client_root(client: str, home: Path) -> Path:
    roots = {
        "agents": home / ".agents" / "skills",
        "codex": home / ".codex" / "skills",
        "claude": home / ".claude" / "skills",
    }
    return roots[client]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install the codespace-x86-re skill.")
    parser.add_argument(
        "--client", choices=("agents", "codex", "claude"), default="agents"
    )
    parser.add_argument("--target", type=Path, help="Override the skills root directory")
    parser.add_argument("--copy", action="store_true", help="Copy instead of symlinking")
    parser.add_argument("--force", action="store_true", help="Replace this exact skill only")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    source = repo_root / "skills" / SKILL_NAME
    target_root = (
        args.target.expanduser().resolve()
        if args.target
        else client_root(args.client, Path.home())
    )
    destination = target_root / SKILL_NAME
    target_root.mkdir(parents=True, exist_ok=True)

    if destination.exists() or destination.is_symlink():
        if not args.force:
            raise SystemExit(f"Destination exists; pass --force to replace it: {destination}")
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
        else:
            shutil.rmtree(destination)

    if args.copy:
        shutil.copytree(source, destination)
    else:
        destination.symlink_to(source, target_is_directory=True)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
