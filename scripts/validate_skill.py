#!/usr/bin/env python3
"""Strict dependency-free validation for this repository's Agent Skill."""

from __future__ import annotations

from pathlib import Path
import re


NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FRONTMATTER_RE = re.compile(r"\A---\n(?P<header>.*?)\n---\n(?P<body>.*)\Z", re.DOTALL)
LOCAL_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
ALLOWED_SKILL_ENTRIES = {"SKILL.md", "agents", "assets", "references", "scripts"}


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Parse the deliberately small frontmatter contract used by this skill."""
    match = FRONTMATTER_RE.fullmatch(text)
    if not match:
        raise ValueError("SKILL.md must have LF-delimited YAML frontmatter.")

    fields: dict[str, str] = {}
    for line in match.group("header").splitlines():
        field = re.fullmatch(r"([a-z][a-z0-9_-]*):\s*(\S.*)", line)
        if not field:
            raise ValueError(f"Unsupported frontmatter line: {line!r}")
        key, value = field.groups()
        if key in fields:
            raise ValueError(f"Duplicate frontmatter field: {key}")
        fields[key] = value.strip()

    if set(fields) != {"name", "description"}:
        raise ValueError("Frontmatter must contain exactly name and description.")
    return fields, match.group("body")


def validate_skill(skill: Path) -> list[str]:
    """Return all repository-specific validation errors for *skill*."""
    errors: list[str] = []
    skill_file = skill / "SKILL.md"
    if not skill_file.is_file():
        return ["SKILL.md is missing."]

    text = skill_file.read_text(encoding="utf-8")
    try:
        fields, body = parse_frontmatter(text)
    except ValueError as error:
        return [str(error)]

    name = fields["name"]
    description = fields["description"]
    if len(name) > 64 or not NAME_RE.fullmatch(name):
        errors.append("Skill name must be 1-64 lowercase letters, digits, or hyphens.")
    if name != skill.name:
        errors.append("Skill name must match its directory name.")
    if not 1 <= len(description) <= 1024:
        errors.append("Description must contain 1-1024 characters.")
    if not body.strip():
        errors.append("SKILL.md must contain Markdown instructions.")
    if len(text.splitlines()) > 500:
        errors.append("SKILL.md exceeds the 500-line progressive-disclosure limit.")

    unexpected = sorted(
        path.name
        for path in skill.iterdir()
        if path.name not in ALLOWED_SKILL_ENTRIES
    )
    if unexpected:
        errors.append(f"Unexpected skill-root entries: {', '.join(unexpected)}")

    for link in LOCAL_LINK_RE.findall(body):
        target = link.split("#", 1)[0]
        if not target or "://" in target or target.startswith("#"):
            continue
        linked = (skill / target).resolve()
        try:
            linked.relative_to(skill.resolve())
        except ValueError:
            errors.append(f"Local link escapes the skill directory: {link}")
        else:
            if not linked.is_file():
                errors.append(f"Local link target does not exist: {link}")

    for path in skill.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".md", ".py", ".java", ".yaml", ".yml"}:
            if "TODO" in path.read_text(encoding="utf-8"):
                errors.append(f"Unresolved TODO remains in {path.relative_to(skill)}.")

    metadata = skill / "agents" / "openai.yaml"
    if not metadata.is_file():
        errors.append("agents/openai.yaml is missing.")
    else:
        metadata_text = metadata.read_text(encoding="utf-8")
        quoted_fields = dict(
            re.findall(
                r'^  (display_name|short_description|default_prompt): "([^"]+)"$',
                metadata_text,
                re.MULTILINE,
            )
        )
        if set(quoted_fields) != {"display_name", "short_description", "default_prompt"}:
            errors.append("openai.yaml must contain the three required quoted interface fields.")
        else:
            if not 25 <= len(quoted_fields["short_description"]) <= 64:
                errors.append("openai.yaml short_description must contain 25-64 characters.")
            if f"${name}" not in quoted_fields["default_prompt"]:
                errors.append("openai.yaml default_prompt must mention the skill by $name.")

    return errors


def main() -> int:
    skill = Path(__file__).resolve().parents[1] / "skills" / "codespace-x86-re"
    errors = validate_skill(skill)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Skill is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
