from __future__ import annotations

import json
from pathlib import Path
import unittest


class DevcontainerTests(unittest.TestCase):
    def test_codespace_supports_java_21_and_gh_ssh(self) -> None:
        config_path = Path(__file__).parents[1] / ".devcontainer" / "devcontainer.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        features = config["features"]
        java = features["ghcr.io/devcontainers/features/java:1"]
        self.assertEqual(java["version"], "21")
        self.assertIn("ghcr.io/devcontainers/features/sshd:1", features)

    def test_codespace_supports_rea_node_runtime(self) -> None:
        config_path = Path(__file__).parents[1] / ".devcontainer" / "devcontainer.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        node = config["features"]["ghcr.io/devcontainers/features/node:1"]
        # REA supports Node 22.19+, 24.11+ or 26+, never 23 or 25.
        self.assertEqual(node["version"], "24")


if __name__ == "__main__":
    unittest.main()
