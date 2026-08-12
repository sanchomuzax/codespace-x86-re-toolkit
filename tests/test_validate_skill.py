from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "validate_skill.py"
SPEC = importlib.util.spec_from_file_location("validate_skill", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ValidateSkillTests(unittest.TestCase):
    def make_skill(self, frontmatter: str | None = None) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        skill = Path(temporary.name) / "example-skill"
        (skill / "agents").mkdir(parents=True)
        (skill / "references").mkdir()
        header = frontmatter or (
            "name: example-skill\n"
            "description: Perform a focused example task when requested."
        )
        (skill / "SKILL.md").write_text(
            f"---\n{header}\n---\n\n# Example\n\nRead [the guide](references/guide.md).\n",
            encoding="utf-8",
        )
        (skill / "references" / "guide.md").write_text("# Guide\n", encoding="utf-8")
        (skill / "agents" / "openai.yaml").write_text(
            'interface:\n'
            '  display_name: "Example Skill"\n'
            '  short_description: "Perform one focused example task"\n'
            '  default_prompt: "Use $example-skill to perform the example task."\n',
            encoding="utf-8",
        )
        return skill

    def test_accepts_complete_skill(self) -> None:
        self.assertEqual(MODULE.validate_skill(self.make_skill()), [])

    def test_rejects_extra_frontmatter_field(self) -> None:
        errors = MODULE.validate_skill(
            self.make_skill(
                "name: example-skill\n"
                "description: Perform a focused example task when requested.\n"
                "version: 1.0.0"
            )
        )
        self.assertIn("Frontmatter must contain exactly name and description.", errors)

    def test_rejects_missing_local_reference(self) -> None:
        skill = self.make_skill()
        (skill / "references" / "guide.md").unlink()
        self.assertIn(
            "Local link target does not exist: references/guide.md",
            MODULE.validate_skill(skill),
        )

    def test_rejects_stale_agent_metadata(self) -> None:
        skill = self.make_skill()
        metadata = skill / "agents" / "openai.yaml"
        metadata.write_text(
            metadata.read_text(encoding="utf-8").replace("$example-skill", "$old-name"),
            encoding="utf-8",
        )
        self.assertIn(
            "openai.yaml default_prompt must mention the skill by $name.",
            MODULE.validate_skill(skill),
        )

    def test_project_skill_defines_a_bounded_background_monitor(self) -> None:
        skill_file = (
            Path(__file__).parents[1]
            / "skills"
            / "codespace-x86-re"
            / "SKILL.md"
        )
        text = skill_file.read_text(encoding="utf-8")
        for required in (
            "CODESPACE_X86_RE_DONE",
            "MONITOR_TIMEOUT",
            "deadline=$((SECONDS + 2100))",
            "sleep 20",
            "MONITOR_PID=$!",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
