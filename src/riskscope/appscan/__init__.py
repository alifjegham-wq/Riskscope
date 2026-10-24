"""Application scanning: vulnerable dependencies and hard-coded secrets in uploaded code.

Uploads are processed in memory and never written to disk or stored.
"""

from __future__ import annotations

import io
import time
import zipfile
from pathlib import PurePosixPath

from ..models import Category, CheckError, Report
from ..scoring import apply_score
from .manifests import extract_packages, parser_for
from .osv import Package, VulnSource, findings_for
from .secrets import MAX_FILE_BYTES, find_secrets

MAX_ARCHIVE_FILES = 5000
MAX_TOTAL_UNCOMPRESSED = 50_000_000
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}


class UploadError(ValueError):
    pass


def expand_upload(filename: str, data: bytes) -> dict[str, bytes]:
    """Return {path: content}; zip archives are unpacked with size and count limits."""
    if not filename.lower().endswith(".zip"):
        return {PurePosixPath(filename).name: data}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UploadError("That .zip file could not be opened") from exc
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > MAX_ARCHIVE_FILES:
        raise UploadError(f"Archive has more than {MAX_ARCHIVE_FILES} files")
    if sum(i.file_size for i in infos) > MAX_TOTAL_UNCOMPRESSED:
        raise UploadError("Archive is too large once unpacked")
    out: dict[str, bytes] = {}
    total = 0  # header sizes can lie (zip bombs), so count what we actually read
    for info in infos:
        parts = PurePosixPath(info.filename).parts
        if any(p in SKIP_DIRS for p in parts[:-1]) or ".." in parts:
            continue
        # Lockfiles inside skipped dirs are irrelevant; big blobs are skipped for secrets anyway.
        if info.file_size > MAX_FILE_BYTES and parser_for(info.filename) is None:
            continue
        with zf.open(info) as fh:
            content = fh.read(MAX_TOTAL_UNCOMPRESSED - total + 1)
        total += len(content)
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise UploadError("Archive is too large once unpacked")
        out[info.filename] = content
    return out


def _is_text(data: bytes) -> bool:
    return b"\x00" not in data[:8192]


async def scan_code(files: dict[str, bytes], vulns: VulnSource, label: str = "uploaded code") -> Report:
    started = time.monotonic()
    report = Report(target=label, kind="code")
    packages: list[Package] = []
    manifests = 0
    for path, data in sorted(files.items()):
        if not _is_text(data):
            continue
        text = data.decode("utf-8", errors="replace")
        if parser_for(path):
            manifests += 1
            try:
                packages.extend(extract_packages(path, text))
            except (ValueError, KeyError, TypeError) as exc:
                report.errors.append(CheckError(check=f"Parse {path}", message=f"Could not parse ({exc})"[:200]))
            continue
        if len(data) <= MAX_FILE_BYTES:
            report.findings.extend(find_secrets(path, text))

    if packages:
        try:
            report.findings.extend(findings_for(await vulns.lookup(packages), Category.DEPENDENCIES))
            if not any(f.category is Category.DEPENDENCIES for f in report.findings):
                report.passed.append(f"No known vulnerabilities in {len(set(packages))} dependencies")
        except Exception as exc:  # noqa: BLE001 - the vulnerability DB being down must not lose secret findings
            report.errors.append(CheckError(check="Dependency vulnerabilities", message=type(exc).__name__))
    elif manifests == 0:
        report.errors.append(
            CheckError(
                check="Dependency vulnerabilities",
                message="No lockfile found (package-lock.json, poetry.lock, go.mod, Gemfile.lock, ...)",
            )
        )
    if not any(f.category is Category.SECRETS for f in report.findings):
        report.passed.append(f"No hard-coded secrets found in {len(files)} files")
    report.duration_ms = int((time.monotonic() - started) * 1000)
    return apply_score(report)


__all__ = ["UploadError", "expand_upload", "scan_code"]
