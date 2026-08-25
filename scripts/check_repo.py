"""Single dependency-free verification entry point for the THYROROS repository."""

from __future__ import annotations

import ast
import email.parser
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from thyroros import __version__  # noqa: E402
from thyroros.canonical import canonical_digest  # noqa: E402
from thyroros.contracts import ContractDocumentError, load_contract  # noqa: E402
from thyroros.schema import schema_bytes  # noqa: E402

TEXT_SUFFIXES = {
    "",
    ".gitignore",
    ".in",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}
FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519"}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}
PRIVATE_KEY_PREFIX = b"-----BEGIN "
PRIVATE_KEY_SUFFIX = b"PRIVATE KEY-----"
SECRET_PATTERNS = {
    "private key block": re.compile(
        re.escape(PRIVATE_KEY_PREFIX)
        + rb"(?:[A-Z0-9 ]+ )?"
        + re.escape(PRIVATE_KEY_SUFFIX),
        re.IGNORECASE,
    ),
    "GitHub token": re.compile(rb"gh(?:p|o|u|s|r)_[A-Za-z0-9]{30,}"),
    "GitHub fine-grained token": re.compile(rb"github_pat_[A-Za-z0-9_]{40,}"),
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "OpenAI-style key": re.compile(rb"sk-[A-Za-z0-9]{20,}"),
}
MARKDOWN_LINK_RE = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")
HTML_LINK_RE = re.compile(r"(?:href|src)=['\"]([^'\"]+)['\"]", re.IGNORECASE)


def _iter_repository_files() -> Iterable[Path]:
    for path in ROOT.rglob("*"):
        if not path.is_file() and not path.is_symlink():
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        yield path


def _load_json_no_duplicates(path: Path) -> Any:
    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key {key!r}")
            value[key] = item
        return value

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_hook)


def _check_python_syntax(failures: list[str]) -> None:
    for path in sorted(ROOT.rglob("*.py")):
        relative = path.relative_to(ROOT)
        if any(part in SKIP_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(relative))
            compile(tree, str(relative), "exec", dont_inherit=True)
        except Exception as exc:
            failures.append(f"{relative}: Python compilation failed: {exc}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            seen: dict[Any, int] = {}
            for key in node.keys:
                if key is None:
                    continue
                try:
                    literal = ast.literal_eval(key)
                    hash(literal)
                except (ValueError, TypeError):
                    continue
                if literal in seen:
                    failures.append(
                        f"{relative}:{getattr(key, 'lineno', '?')}: duplicate literal "
                        f"dict key {literal!r}; first declared on line {seen[literal]}"
                    )
                else:
                    seen[literal] = getattr(key, "lineno", 0)


def _check_metadata_and_json(failures: list[str]) -> str | None:
    try:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]
    except Exception as exc:
        failures.append(f"pyproject.toml: invalid project metadata: {exc}")
        return None

    metadata_version = project.get("version")
    if metadata_version != __version__:
        failures.append(
            f"version mismatch: pyproject={metadata_version!r}, package={__version__!r}"
        )
    if project.get("dependencies") != []:
        failures.append("runtime dependencies must remain an explicit empty array")
    if project.get("requires-python") != ">=3.11":
        failures.append("requires-python must remain >=3.11 for the 0.2.x line")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if f"**{__version__} alpha" not in readme:
        failures.append("README.md does not expose the package version/status")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{__version__}]" not in changelog:
        failures.append("CHANGELOG.md has no entry for the package version")

    for path in sorted(ROOT.rglob("*.json")):
        relative = path.relative_to(ROOT)
        if any(part in SKIP_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        try:
            _load_json_no_duplicates(path)
        except Exception as exc:
            failures.append(f"{relative}: invalid or ambiguous JSON: {exc}")

    repository_schema = ROOT / "schemas" / "run-contract.schema.json"
    try:
        if repository_schema.read_bytes() != schema_bytes():
            failures.append("repository and packaged Run Contract schemas differ")
    except OSError as exc:
        failures.append(f"schema parity check failed: {exc}")

    digest: str | None = None
    examples = sorted((ROOT / "examples").glob("*.json"))
    if not examples:
        failures.append("no JSON example contracts found")
    for example in examples:
        try:
            contract = load_contract(example)
            current = canonical_digest(contract)
            if len(current) != 71 or not current.startswith("sha256:"):
                failures.append(f"{example.relative_to(ROOT)}: unexpected digest form")
            if example.name == "run-contract.json":
                digest = current
        except ContractDocumentError as exc:
            failures.append(f"{example.relative_to(ROOT)}: {exc}")
    return digest


def _check_repository_hygiene(failures: list[str]) -> None:
    for path in _iter_repository_files():
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            failures.append(f"symlink is not admitted in the repository: {relative}")
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            failures.append(f"{relative}: stat failed: {exc}")
            continue
        if size > 5 * 1024 * 1024:
            failures.append(f"{relative}: file exceeds the 5 MiB repository limit")

        lower_name = path.name.lower()
        if lower_name in FORBIDDEN_NAMES or (
            path.suffix.lower() in FORBIDDEN_SUFFIXES and lower_name != "security.md"
        ):
            failures.append(f"forbidden secret-like file name: {relative}")

        try:
            raw = path.read_bytes()
        except OSError as exc:
            failures.append(f"{relative}: read failed: {exc}")
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(raw):
                failures.append(f"{relative}: possible {label}")

        suffix = path.suffix.lower() if path.suffix else path.name.lower()
        if suffix in TEXT_SUFFIXES or path.name in {"LICENSE", "MANIFEST.in"}:
            if raw.startswith(b"\xef\xbb\xbf"):
                failures.append(f"{relative}: UTF-8 BOM is forbidden")
            if b"\x00" in raw:
                failures.append(f"{relative}: NUL byte in text file")
            try:
                raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                failures.append(f"{relative}: text is not strict UTF-8: {exc}")


def _local_link_target(markdown: Path, target: str) -> Path | None:
    target = target.strip()
    if not target or target.startswith(("#", "http://", "https://", "mailto:")):
        return None
    if " " in target and not target.startswith("<"):
        target = target.split(" ", 1)[0]
    target = target.strip("<>").split("#", 1)[0].split("?", 1)[0]
    if not target:
        return None
    return (markdown.parent / target).resolve()


def _check_workflow_security(failures: list[str]) -> None:
    workflow_root = ROOT / ".github" / "workflows"
    for workflow in sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml"))):
        relative = workflow.relative_to(ROOT)
        try:
            text = workflow.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"{relative}: workflow read failed: {exc}")
            continue

        if re.search(r"(?m)^permissions:\s*$\n\s+contents:\s+read\s*$", text) is None:
            failures.append(f"{relative}: workflow must declare contents: read permissions")

        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped.startswith("uses:"):
                continue
            reference = stripped.removeprefix("uses:").split("#", 1)[0].strip()
            if reference.startswith(("./", "docker://")):
                continue
            if re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference) is None:
                failures.append(
                    f"{relative}:{line_number}: third-party action must be pinned "
                    "to a full 40-character commit SHA"
                )

        if "actions/checkout@" in text and "persist-credentials: false" not in text:
            failures.append(
                f"{relative}: checkout must explicitly disable persisted credentials"
            )


def _check_markdown_links(failures: list[str]) -> None:
    root = ROOT.resolve()
    for markdown in sorted(ROOT.rglob("*.md")):
        relative = markdown.relative_to(ROOT)
        if any(part in SKIP_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        try:
            text = markdown.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"{relative}: link scan failed: {exc}")
            continue
        targets = MARKDOWN_LINK_RE.findall(text) + HTML_LINK_RE.findall(text)
        for raw_target in targets:
            target = _local_link_target(markdown, raw_target)
            if target is None:
                continue
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{relative}: local link escapes repository: {raw_target}")
                continue
            if not target.exists():
                failures.append(f"{relative}: broken local link: {raw_target}")


def _run_unit_tests(failures: list[str]) -> None:
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        failures.append("unit tests failed")


def _copy_for_build(destination: Path) -> None:
    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = set()
        for name in names:
            if name in SKIP_PARTS or name.endswith(".egg-info"):
                ignored.add(name)
        return ignored

    shutil.copytree(ROOT, destination, ignore=ignore)


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _check_distributions(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory(prefix="thyroros-build-") as directory:
        temporary = Path(directory)
        source = temporary / "source"
        wheel_dir = temporary / "wheel"
        sdist_dir = temporary / "sdist"
        site = temporary / "site"
        wheel_dir.mkdir()
        sdist_dir.mkdir()
        _copy_for_build(source)

        wheel_build = _run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheel_dir),
            ],
            cwd=source,
        )
        if wheel_build.returncode != 0:
            failures.append("wheel build failed:\n" + wheel_build.stdout[-4000:])
            return

        sdist_env = os.environ.copy()
        sdist_env["THYROROS_SDIST_DIR"] = str(sdist_dir)
        sdist_build = _run(
            [
                sys.executable,
                "-c",
                (
                    "import os; from setuptools.build_meta import build_sdist; "
                    "print(build_sdist(os.environ['THYROROS_SDIST_DIR']))"
                ),
            ],
            cwd=source,
            env=sdist_env,
        )
        if sdist_build.returncode != 0:
            failures.append("source-distribution build failed:\n" + sdist_build.stdout[-4000:])
            return

        wheels = sorted(wheel_dir.glob("*.whl"))
        sdists = sorted(sdist_dir.glob("*.tar.gz"))
        if len(wheels) != 1:
            failures.append(f"expected exactly one wheel, found {len(wheels)}")
            return
        if len(sdists) != 1:
            failures.append(f"expected exactly one source distribution, found {len(sdists)}")
            return
        wheel = wheels[0]
        sdist = sdists[0]

        try:
            with zipfile.ZipFile(wheel) as archive:
                names = set(archive.namelist())
                required = {
                    "thyroros/py.typed",
                    "thyroros/data/run-contract.schema.json",
                }
                for item in required:
                    if item not in names:
                        failures.append(f"wheel is missing {item}")
                metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
                if len(metadata_names) != 1:
                    failures.append("wheel has an unexpected METADATA layout")
                else:
                    metadata = email.parser.BytesParser().parsebytes(
                        archive.read(metadata_names[0])
                    )
                    if metadata.get("Version") != __version__:
                        failures.append("wheel metadata version differs from package version")
                    if metadata.get("Requires-Dist") is not None:
                        failures.append("wheel unexpectedly declares a runtime dependency")
                    if metadata.get("Requires-Python") != ">=3.11":
                        failures.append("wheel has unexpected Requires-Python metadata")
        except (OSError, zipfile.BadZipFile) as exc:
            failures.append(f"wheel inspection failed: {exc}")

        try:
            with tarfile.open(sdist, "r:gz") as archive:
                names = archive.getnames()
                required_suffixes = {
                    "/README.md",
                    "/SECURITY.md",
                    "/docs/POLICY_ENGINE.md",
                    "/examples/run-contract.json",
                    "/schemas/run-contract.schema.json",
                }
                for suffix in required_suffixes:
                    if not any(name.endswith(suffix) for name in names):
                        failures.append(f"source distribution is missing *{suffix}")
        except (OSError, tarfile.TarError) as exc:
            failures.append(f"source-distribution inspection failed: {exc}")

        install = _run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--no-index",
                "--target",
                str(site),
                str(wheel),
            ],
            cwd=temporary,
        )
        if install.returncode != 0:
            failures.append("isolated wheel installation failed:\n" + install.stdout[-4000:])
            return

        smoke_env = os.environ.copy()
        smoke_env.pop("PYTHONPATH", None)
        smoke_env["PYTHONPATH"] = str(site)
        smoke = _run(
            [
                sys.executable,
                "-c",
                (
                    "import thyroros; "
                    f"assert thyroros.__version__ == {__version__!r}; "
                    "assert thyroros.schema_document()['title'] == 'THYROROS Run Contract'"
                ),
            ],
            cwd=temporary,
            env=smoke_env,
        )
        if smoke.returncode != 0:
            failures.append("installed-package import smoke test failed:\n" + smoke.stdout[-4000:])

        cli = _run(
            [sys.executable, "-m", "thyroros", "--version"],
            cwd=temporary,
            env=smoke_env,
        )
        if cli.returncode != 0 or cli.stdout.strip() != f"thyroros {__version__}":
            failures.append(
                "installed CLI smoke test failed: "
                f"exit={cli.returncode}, output={cli.stdout.strip()!r}"
            )


def main() -> int:
    failures: list[str] = []

    _check_python_syntax(failures)
    digest = _check_metadata_and_json(failures)
    _check_repository_hygiene(failures)
    _check_workflow_security(failures)
    _check_markdown_links(failures)
    _run_unit_tests(failures)
    _check_distributions(failures)

    if failures:
        print("\nREPOSITORY CHECK: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nREPOSITORY CHECK: PASS")
    print(f"version: {__version__}")
    if digest is not None:
        print(f"example digest: {digest}")
    print("runtime dependencies: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
