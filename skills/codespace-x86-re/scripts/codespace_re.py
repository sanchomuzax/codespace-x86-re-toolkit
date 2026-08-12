#!/usr/bin/env python3
"""Run authorized x86 reverse engineering in an ephemeral GitHub Codespace."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys


DEFAULT_HOST_REPO = "sanchomuzax/codespace-x86-re-toolkit"
DEFAULT_MACHINE = "basicLinux32gb"
DEFAULT_LOCATION = "WestEurope"
DISPLAY_NAME = "codespace-x86-re"
REMOTE_ROOT = "/var/tmp/codespace-x86-re"
REMOTE_INPUT = f"{REMOTE_ROOT}/input.bin"
REMOTE_SCRIPTS = f"{REMOTE_ROOT}/scripts"
GHIDRA_VERSION = "12.1.2"
GHIDRA_DIR = f"ghidra_{GHIDRA_VERSION}_PUBLIC"
GHIDRA_ZIP = "ghidra_12.1.2_PUBLIC_20260605.zip"
GHIDRA_SHA256 = "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d"
GHIDRA_URL = (
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    f"Ghidra_{GHIDRA_VERSION}_build/{GHIDRA_ZIP}"
)

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SCRIPT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.java$")
RESULT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def gh_binary() -> str:
    return os.environ.get("CODESPACE_X86_RE_GH_BIN", "gh")


def run(
    command: list[str], *, capture: bool = False, stdin=None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        stdin=stdin,
        text=stdin is None,
        capture_output=capture,
    )


def validate_codespace(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise SystemExit(f"Invalid Codespace name: {name!r}")
    return name


def validate_repo(repo: str) -> str:
    parts = repo.split("/")
    if not REPO_RE.fullmatch(repo) or any(part in {".", ".."} for part in parts):
        raise SystemExit(f"Repository must be in OWNER/NAME form: {repo!r}")
    return repo


def validate_script_name(name: str) -> str:
    if not SCRIPT_NAME_RE.fullmatch(name):
        raise SystemExit(f"Script must have a simple .java filename: {name!r}")
    return name


def validate_result_name(name: str) -> str:
    if not RESULT_NAME_RE.fullmatch(name):
        raise SystemExit(f"Result must be a simple filename: {name!r}")
    return name


def remote(
    name: str, script: str, *, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    validate_codespace(name)
    return run(
        [
            gh_binary(),
            "codespace",
            "ssh",
            "-c",
            name,
            "--",
            f"bash -lc {shlex.quote(script)}",
        ],
        capture=capture,
    )


def detect_x86_binary(path: Path) -> str:
    """Return x86 or x86-64 after validating a PE/ELF header."""
    with path.open("rb") as handle:
        header = handle.read(64)
        if header.startswith(b"MZ"):
            if len(header) < 64:
                raise SystemExit("Truncated DOS/PE header.")
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            handle.seek(pe_offset)
            pe_header = handle.read(6)
            if len(pe_header) != 6 or pe_header[:4] != b"PE\0\0":
                raise SystemExit("Invalid PE signature.")
            machine = struct.unpack_from("<H", pe_header, 4)[0]
            architectures = {0x14C: "x86", 0x8664: "x86-64"}
        elif header.startswith(b"\x7fELF"):
            if len(header) < 20 or header[5] not in (1, 2):
                raise SystemExit("Invalid or truncated ELF header.")
            endian = "<" if header[5] == 1 else ">"
            machine = struct.unpack_from(f"{endian}H", header, 18)[0]
            architectures = {3: "x86", 62: "x86-64"}
        else:
            raise SystemExit("Only x86/x86-64 PE and ELF binaries are accepted.")

    architecture = architectures.get(machine)
    if architecture is None:
        raise SystemExit(f"Unsupported non-x86 machine type: 0x{machine:04x}")
    return architecture


def doctor(args: argparse.Namespace) -> None:
    repo = validate_repo(args.repo)
    run([gh_binary(), "auth", "status"])
    run([gh_binary(), "codespace", "list", "--json", "name,state,repository"])
    result = run(
        [gh_binary(), "api", f"repos/{repo}/codespaces/machines"], capture=True
    )
    machines = json.loads(result.stdout).get("machines", [])
    selected = next((item for item in machines if item.get("name") == args.machine), None)
    if selected is None:
        raise SystemExit(f"Codespaces machine is unavailable for {repo}: {args.machine}")
    print(
        f"OK: {repo}; {selected['cpus']} CPU; "
        f"{selected['memory_in_bytes'] // (1024**3)} GiB RAM"
    )


def create(args: argparse.Namespace) -> None:
    repo = validate_repo(args.repo)
    command = [
        gh_binary(),
        "codespace",
        "create",
        "-R",
        repo,
        "-b",
        args.branch,
        "-m",
        args.machine,
        "-l",
        args.location,
        "-d",
        DISPLAY_NAME,
        "--idle-timeout",
        args.idle_timeout,
        "--retention-period",
        args.retention_period,
        "--default-permissions",
    ]
    result = run(command, capture=True)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise SystemExit("GitHub did not return a Codespace name.")
    print(validate_codespace(lines[-1]))


def list_codespaces(_: argparse.Namespace) -> None:
    run(
        [
            gh_binary(),
            "codespace",
            "list",
            "--json",
            "name,repository,state,machineName,createdAt,lastUsedAt",
        ]
    )


def status(args: argparse.Namespace) -> None:
    remote(
        args.codespace,
        "uname -m; nproc; free -h; df -h /var/tmp; "
        f"if test -f {REMOTE_ROOT!r}/java21-home; then "
        f"java_home=$(cat {REMOTE_ROOT!r}/java21-home); "
        '"$java_home/bin/java" -version; else java -version; fi',
    )


SETUP_SCRIPT = f"""
set -euo pipefail
root={REMOTE_ROOT!r}
mkdir -p "$root/tools" "$root/results" "$root/scripts"

java_home=""
for candidate in /usr/local/sdkman/candidates/java/21* /usr/lib/jvm/java-21*; do
    if test -x "$candidate/bin/java"; then
        java_home="$candidate"
        break
    fi
done
if test -z "$java_home"; then
    echo "Java 21 was not found in the Codespace." >&2
    exit 21
fi
printf '%s\n' "$java_home" > "$root/java21-home"
export JAVA_HOME="$java_home"
export PATH="$java_home/bin:$PATH"

zip="$root/tools/{GHIDRA_ZIP}"
install="$root/tools/{GHIDRA_DIR}"
if ! test -x "$install/support/analyzeHeadless"; then
    rm -rf "$install"
    curl -fL {GHIDRA_URL!r} -o "$zip"
    printf '%s  %s\n' {GHIDRA_SHA256!r} "$zip" | sha256sum -c -
    unzip -q "$zip" -d "$root/tools"
fi
"$java_home/bin/java" -version
"$install/support/analyzeHeadless" 2>&1 | head -n 3 || true
"""


def setup(args: argparse.Namespace) -> None:
    remote(args.codespace, SETUP_SCRIPT)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def upload(args: argparse.Namespace) -> None:
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"Not a regular file: {binary}")
    architecture = detect_x86_binary(binary)
    local_hash = sha256(binary)
    remote(args.codespace, f"mkdir -p {REMOTE_ROOT!r}")
    command = [
        gh_binary(),
        "codespace",
        "ssh",
        "-c",
        validate_codespace(args.codespace),
        "--",
        f"cat > {shlex.quote(REMOTE_INPUT)}",
    ]
    with binary.open("rb") as handle:
        subprocess.run(command, check=True, stdin=handle)
    result = remote(
        args.codespace, f"sha256sum {REMOTE_INPUT!r} | cut -d' ' -f1", capture=True
    )
    remote_hash = result.stdout.strip()
    if remote_hash != local_hash:
        raise SystemExit(f"Upload SHA-256 mismatch: {local_hash} != {remote_hash}")
    print(
        f"OK: {binary.name}; {architecture}; {binary.stat().st_size} bytes; "
        f"sha256={local_hash}"
    )


def analyze(args: argparse.Namespace) -> None:
    if not 1 <= args.timeout <= 86400:
        raise SystemExit("Analysis timeout must be between 1 and 86400 seconds.")
    remote(args.codespace, analysis_script(args.timeout))


def analysis_script(timeout: int) -> str:
    return f"""
set -euo pipefail
root={REMOTE_ROOT!r}
test -s "$root/input.bin"
test -f "$root/java21-home"
java_home=$(cat "$root/java21-home")
ghidra="$root/tools/{GHIDRA_DIR}"
test -x "$ghidra/support/analyzeHeadless"
rm -rf "$root/project"
mkdir -p "$root/project" "$root/results"
export JAVA_HOME="$java_home"
export PATH="$java_home/bin:$PATH"
log="$root/results/analyze.log"
"$ghidra/support/analyzeHeadless" "$root/project" analysis \
  -import "$root/input.bin" -analysisTimeoutPerFile {timeout} \
  2>&1 | tee "$log"
grep -q "REPORT: Import succeeded" "$log"
"""


def run_script(args: argparse.Namespace) -> None:
    script = args.script.resolve()
    if not script.is_file():
        raise SystemExit(f"Not a regular file: {script}")

    script_name = validate_script_name(script.name)
    script_dir = f"{REMOTE_SCRIPTS}/{script.stem}"
    remote_script = f"{script_dir}/{script_name}"
    local_hash = sha256(script)
    remote(args.codespace, f"mkdir -p {script_dir!r}")
    command = [
        gh_binary(),
        "codespace",
        "ssh",
        "-c",
        validate_codespace(args.codespace),
        "--",
        f"cat > {shlex.quote(remote_script)}",
    ]
    with script.open("rb") as handle:
        subprocess.run(command, check=True, stdin=handle)

    result = remote(
        args.codespace, f"sha256sum {remote_script!r} | cut -d' ' -f1", capture=True
    )
    if result.stdout.strip() != local_hash:
        raise SystemExit("GhidraScript upload SHA-256 verification failed.")
    remote(args.codespace, script_execution_script(script_name, args.script_arg))


def script_execution_script(script_name: str, script_args: list[str]) -> str:
    stem = Path(script_name).stem
    arguments = ""
    if script_args:
        arguments = " " + shlex.join(script_args)
    return f"""
set -euo pipefail
root={REMOTE_ROOT!r}
test -f "$root/java21-home"
test -s "$root/scripts/{stem}/{script_name}"
java_home=$(cat "$root/java21-home")
ghidra="$root/tools/{GHIDRA_DIR}"
log="$root/results/script-{stem}.log"
test -x "$ghidra/support/analyzeHeadless"
test -d "$root/project/analysis.rep"
export JAVA_HOME="$java_home"
export PATH="$java_home/bin:$PATH"
"$ghidra/support/analyzeHeadless" "$root/project" analysis \
  -process input.bin -noanalysis -scriptPath "$root/scripts/{stem}" \
  -postScript {script_name!r}{arguments} 2>&1 | tee "$log"
if grep -q "REPORT SCRIPT ERROR" "$log"; then
    echo "GhidraScript failed; see $log" >&2
    exit 42
fi
"""


def download(args: argparse.Namespace) -> None:
    result_name = validate_result_name(args.result)
    destination = args.output.resolve()
    if destination.exists() and not args.overwrite:
        raise SystemExit(f"Destination exists; pass --overwrite: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    remote_path = f"{REMOTE_ROOT}/results/{result_name}"
    command = [
        gh_binary(),
        "codespace",
        "ssh",
        "-c",
        validate_codespace(args.codespace),
        "--",
        f"cat {shlex.quote(remote_path)}",
    ]
    partial = destination.with_name(f".{destination.name}.part")
    try:
        with partial.open("wb") as handle:
            subprocess.run(command, check=True, stdout=handle)
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)
    print(f"OK: {destination}; sha256={sha256(destination)}")


def stop(args: argparse.Namespace) -> None:
    run([gh_binary(), "codespace", "stop", "-c", validate_codespace(args.codespace)])


def delete(args: argparse.Namespace) -> None:
    run(
        [
            gh_binary(),
            "codespace",
            "delete",
            "-c",
            validate_codespace(args.codespace),
            "--force",
        ]
    )


def add_host_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", default=DEFAULT_HOST_REPO, help="OWNER/NAME host repo")
    parser.add_argument("--machine", default=DEFAULT_MACHINE)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized x86 reverse engineering in an isolated GitHub Codespace."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    doctor_parser = commands.add_parser("doctor", help="Check auth and machine access")
    add_host_options(doctor_parser)
    doctor_parser.set_defaults(handler=doctor)

    create_parser = commands.add_parser("create", help="Create an ephemeral Codespace")
    add_host_options(create_parser)
    create_parser.add_argument("--branch", default="main")
    create_parser.add_argument("--location", default=DEFAULT_LOCATION)
    create_parser.add_argument("--idle-timeout", default="10m")
    create_parser.add_argument("--retention-period", default="1h")
    create_parser.set_defaults(handler=create)

    commands.add_parser("list", help="List existing Codespaces").set_defaults(
        handler=list_codespaces
    )
    for command, handler, help_text in (
        ("status", status, "Show remote resources and Java version"),
        ("setup", setup, "Install pinned Ghidra with Java 21"),
        ("stop", stop, "Stop the exact Codespace name"),
        ("delete", delete, "Delete the exact Codespace name"),
    ):
        subparser = commands.add_parser(command, help=help_text)
        subparser.add_argument("--codespace", required=True)
        subparser.set_defaults(handler=handler)

    upload_parser = commands.add_parser("upload", help="Validate and upload a binary")
    upload_parser.add_argument("--codespace", required=True)
    upload_parser.add_argument("--binary", required=True, type=Path)
    upload_parser.set_defaults(handler=upload)

    analyze_parser = commands.add_parser("analyze", help="Run full Ghidra analysis")
    analyze_parser.add_argument("--codespace", required=True)
    analyze_parser.add_argument("--timeout", type=int, default=600)
    analyze_parser.set_defaults(handler=analyze)

    script_parser = commands.add_parser(
        "run-script", help="Upload and run an isolated Java GhidraScript"
    )
    script_parser.add_argument("--codespace", required=True)
    script_parser.add_argument("--script", required=True, type=Path)
    script_parser.add_argument("--script-arg", action="append", default=[])
    script_parser.set_defaults(handler=run_script)

    download_parser = commands.add_parser("download", help="Download one result file")
    download_parser.add_argument("--codespace", required=True)
    download_parser.add_argument("--result", required=True)
    download_parser.add_argument("--output", required=True, type=Path)
    download_parser.add_argument("--overwrite", action="store_true")
    download_parser.set_defaults(handler=download)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.handler(args)
    except subprocess.CalledProcessError as error:
        if error.stderr:
            message = (
                error.stderr.decode(errors="replace")
                if isinstance(error.stderr, bytes)
                else error.stderr
            )
            print(message.rstrip(), file=sys.stderr)
        print(f"Command failed (exit {error.returncode}).", file=sys.stderr)
        return error.returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
