from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock


MODULE_PATH = (
    Path(__file__).parents[1]
    / "skills"
    / "codespace-x86-re"
    / "scripts"
    / "codespace_re.py"
)
SPEC = importlib.util.spec_from_file_location("codespace_re", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class BinaryDetectionTests(unittest.TestCase):
    def write_binary(self, data: bytes) -> Path:
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(Path(handle.name).unlink, missing_ok=True)
        handle.write(data)
        handle.close()
        return Path(handle.name)

    def test_detects_pe_x86_and_x86_64(self) -> None:
        for machine, expected in ((0x14C, "x86"), (0x8664, "x86-64")):
            data = bytearray(256)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)
            data[0x80:0x84] = b"PE\0\0"
            struct.pack_into("<H", data, 0x84, machine)
            self.assertEqual(MODULE.detect_x86_binary(self.write_binary(data)), expected)

    def test_detects_elf_x86_and_x86_64(self) -> None:
        for elf_class, machine, expected in ((1, 3, "x86"), (2, 62, "x86-64")):
            data = bytearray(64)
            data[:6] = b"\x7fELF" + bytes((elf_class, 1))
            struct.pack_into("<H", data, 18, machine)
            self.assertEqual(MODULE.detect_x86_binary(self.write_binary(data)), expected)

    def test_rejects_non_x86_and_unknown_files(self) -> None:
        arm = bytearray(64)
        arm[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", arm, 18, 183)
        for data in (arm, b"not an executable"):
            with self.assertRaises(SystemExit):
                MODULE.detect_x86_binary(self.write_binary(data))


class CommandSafetyTests(unittest.TestCase):
    def test_version_matches_release_file(self) -> None:
        version_file = Path(__file__).parents[1] / "VERSION"
        self.assertEqual(MODULE.__version__, version_file.read_text().strip())

    def test_pinned_ghidra_metadata_is_consistent(self) -> None:
        self.assertIn(MODULE.GHIDRA_VERSION, MODULE.GHIDRA_ZIP)
        self.assertIn(MODULE.GHIDRA_ZIP, MODULE.GHIDRA_URL)
        self.assertRegex(MODULE.GHIDRA_SHA256, r"^[0-9a-f]{64}$")

    def test_validates_external_identifiers(self) -> None:
        self.assertEqual(MODULE.validate_repo("owner/repo-name"), "owner/repo-name")
        self.assertEqual(MODULE.validate_script_name("Export.java"), "Export.java")
        for value in ("owner/repo;bad", "missing-owner", "../repo"):
            with self.assertRaises(SystemExit):
                MODULE.validate_repo(value)
        for value in ("../Export.java", "bad name.java", "script.py", "script.sh"):
            with self.assertRaises(SystemExit):
                MODULE.validate_script_name(value)

    def test_analysis_uses_fixed_remote_names(self) -> None:
        script = MODULE.analysis_script(600)
        self.assertIn('"$root/input.bin"', script)
        self.assertIn('"$root/project" analysis', script)
        self.assertNotIn("program.exe", script)

    def test_custom_script_uses_an_isolated_leaf_directory(self) -> None:
        script = MODULE.script_execution_script(
            "ExportFunctions.java", ["00401000", "name with spaces"]
        )
        self.assertIn('-scriptPath "$root/scripts/ExportFunctions"', script)
        self.assertNotIn('-scriptPath "$root"', script)
        self.assertIn("'name with spaces'", script)
        self.assertIn("REPORT SCRIPT ERROR", script)


class ReaMcpTests(unittest.TestCase):
    def entry(self, name: str, state: str = "Available", display: str = "codespace-x86-re") -> dict:
        return {"name": name, "state": state, "displayName": display}

    def test_selects_the_single_available_toolkit_codespace(self) -> None:
        entries = [
            self.entry("cs-a"),
            self.entry("cs-b", state="Shutdown"),
            self.entry("cs-c", display="other"),
        ]
        self.assertEqual(MODULE.select_codespace(entries), "cs-a")

    def test_selects_a_single_stopped_toolkit_codespace(self) -> None:
        # gh codespace ssh starts a stopped Codespace on connect.
        self.assertEqual(MODULE.select_codespace([self.entry("cs-b", state="Shutdown")]), "cs-b")

    def test_refuses_missing_or_ambiguous_codespace(self) -> None:
        for entries in ([], [self.entry("cs-a"), self.entry("cs-b")]):
            with self.assertRaises(SystemExit):
                MODULE.select_codespace(entries)
        with self.assertRaises(SystemExit) as raised:
            MODULE.select_codespace(
                [self.entry("cs-a", state="Shutdown"), self.entry("cs-b", state="Shutdown")]
            )
        self.assertIn("cs-a", str(raised.exception))

    def test_remote_script_pins_rea_and_ghidra(self) -> None:
        script = MODULE.rea_mcp_script("6.4.0")
        self.assertIn("exec npx -y rea-agents@6.4.0 mcp", script)
        self.assertIn(f"GHIDRA_INSTALL_DIR=\"$root/tools/{MODULE.GHIDRA_DIR}\"", script)
        self.assertIn('JAVA_HOME="$(cat "$root/java21-home")"', script)
        self.assertIn("REA_GHIDRA_STARTUP_TIMEOUT_MS=900000", script)
        self.assertIn("support/analyzeHeadless", script)
        self.assertIn("command -v npx", script)
        subprocess.run(["bash", "-n", "-c", script], check=True)

    def test_remote_script_keeps_profile_output_off_mcp_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as home:
            Path(home, ".profile").write_text("echo PROFILE-NOISE\n")
            bindir = Path(home, "bin")
            bindir.mkdir()
            fake_npx = bindir / "npx"
            fake_npx.write_text("#!/bin/sh\necho MCP-ONLY\n")
            fake_npx.chmod(0o755)
            root = Path(home, "root")
            tools = root / "tools" / MODULE.GHIDRA_DIR / "support"
            tools.mkdir(parents=True)
            headless = tools / "analyzeHeadless"
            headless.write_text("#!/bin/sh\n")
            headless.chmod(0o755)
            (root / "java21-home").write_text(home + "\n")
            script = MODULE.rea_mcp_script("6.4.0").replace(
                repr(MODULE.REMOTE_ROOT), shlex.quote(str(root))
            )
            result = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                env={"HOME": home, "PATH": f"{bindir}:/usr/bin:/bin"},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "MCP-ONLY\n")
        self.assertIn("PROFILE-NOISE", result.stderr)

    def test_rejects_unpinned_rea_version(self) -> None:
        for value in ("latest", "6", "6.4.0; rm -rf /", ""):
            with self.assertRaises(SystemExit):
                MODULE.rea_mcp_script(value)

    def test_command_runs_the_script_without_a_login_shell(self) -> None:
        command = MODULE.rea_mcp_command("cs-a", "6.4.0")
        self.assertEqual(command[1:6], ["codespace", "ssh", "-c", "cs-a", "--"])
        self.assertEqual(shlex.split(command[6]), ["bash", "-c", MODULE.rea_mcp_script("6.4.0")])

    def test_setup_prewarms_the_pinned_rea_package(self) -> None:
        self.assertIn(f"rea-agents@{MODULE.REA_VERSION} --version", MODULE.SETUP_SCRIPT)

    def args(self, **overrides) -> object:
        values = {"codespace": None, "repo": MODULE.DEFAULT_HOST_REPO, "rea_version": "6.4.0"}
        return mock.Mock(**{**values, **overrides})

    def test_rea_mcp_lists_codespaces_and_execs_ssh(self) -> None:
        listing = subprocess.CompletedProcess([], 0, stdout='[{"name": "cs-a", "state": "Available", "displayName": "codespace-x86-re"}]', stderr="")
        with mock.patch.object(MODULE, "run", return_value=listing) as run, mock.patch.object(MODULE.os, "execvp") as execvp:
            MODULE.rea_mcp(self.args())
        self.assertIn("--repo", run.call_args.args[0])
        self.assertEqual(execvp.call_args.args[1][4], "cs-a")

    def test_rea_mcp_with_explicit_name_skips_listing(self) -> None:
        with mock.patch.object(MODULE, "run") as run, mock.patch.object(MODULE.os, "execvp") as execvp:
            MODULE.rea_mcp(self.args(codespace="cs-z"))
        run.assert_not_called()
        self.assertEqual(execvp.call_args.args[1][4], "cs-z")

    def test_rea_mcp_reports_listing_failures_briefly(self) -> None:
        failure = subprocess.CalledProcessError(1, ["gh"], stderr="not logged in")
        for effect in (failure, subprocess.CompletedProcess([], 0, stdout="not json", stderr="")):
            kwargs = {"side_effect": effect} if isinstance(effect, Exception) else {"return_value": effect}
            with mock.patch.object(MODULE, "run", **kwargs), mock.patch.object(MODULE.os, "execvp"):
                with self.assertRaises(SystemExit) as raised:
                    MODULE.rea_mcp(self.args())
            self.assertIsInstance(raised.exception.code, str)

    def test_rea_mcp_reports_missing_gh(self) -> None:
        with mock.patch.object(MODULE.os, "execvp", side_effect=FileNotFoundError("gh")):
            with self.assertRaises(SystemExit) as raised:
                MODULE.rea_mcp(self.args(codespace="cs-z"))
        self.assertIn("gh", str(raised.exception))

if __name__ == "__main__":
    unittest.main()
