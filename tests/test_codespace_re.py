from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
