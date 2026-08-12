#!/usr/bin/env python3
"""Dependency-free validation for the repository's Agent Skill."""

from __future__ import annotations

from pathlib import Path
import re


def main() -> int:
    skill = Path(__file__).resolve().parents[1] / "skills" / "codespace-x86-re"
    text = (skill / "SKILL.md").read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not match:
        raise SystemExit("SKILL.md frontmatter is missing.")
    frontmatter = match.group(1)
    if "name: codespace-x86-re" not in frontmatter:
        raise SystemExit("Skill name does not match its directory.")
    if not re.search(r"^description:\s*\S", frontmatter, re.MULTILINE):
        raise SystemExit("Skill description is missing.")
    if "TODO" in text:
        raise SystemExit("Unresolved TODO remains in SKILL.md.")
    print("Skill is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
