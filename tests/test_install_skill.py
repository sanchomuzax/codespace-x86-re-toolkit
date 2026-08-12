from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "install_skill.py"


class InstallSkillTests(unittest.TestCase):
    def test_client_destinations_are_portable(self) -> None:
        spec = importlib.util.spec_from_file_location("install_skill", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            self.assertEqual(
                module.client_root("agents", home), home / ".agents" / "skills"
            )
            self.assertEqual(
                module.client_root("codex", home), home / ".codex" / "skills"
            )
            self.assertEqual(
                module.client_root("claude", home), home / ".claude" / "skills"
            )


if __name__ == "__main__":
    unittest.main()
