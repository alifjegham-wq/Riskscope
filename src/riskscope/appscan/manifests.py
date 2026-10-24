"""Extract exact (name, version) pairs from dependency lockfiles and manifests.

Only pinned versions are reported: a range like ``^1.2`` says nothing about
what is actually installed, so lockfiles give the most accurate results.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

from .osv import Package

Parser = Callable[[str, str], list[Package]]


def parse_requirements(text: str, source: str) -> list[Package]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)", line)
        if m:
            out.append(Package("PyPI", m.group(1), m.group(2), source))
    return out


def _toml_packages(ecosystem: str) -> Parser:
    def parse(text: str, source: str) -> list[Package]:
        data = tomllib.loads(text)
        return [
            Package(ecosystem, str(p["name"]), str(p["version"]), source)
            for p in data.get("package", [])
            if "name" in p and "version" in p
        ]

    return parse


def parse_pipfile_lock(text: str, source: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str((info or {}).get("version", ""))
            if version.startswith("=="):
                out.append(Package("PyPI", name, version[2:], source))
    return out


def parse_package_lock(text: str, source: str) -> list[Package]:
    data = json.loads(text)
    out: list[Package] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, info in packages.items():
            if not path or "node_modules/" not in path or not isinstance(info, dict):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[1]
            if "version" in info and not info.get("link"):
                out.append(Package("npm", str(name), str(info["version"]), source))
        return out

    def walk(deps: dict[str, Any]) -> None:  # lockfileVersion 1
        for name, info in deps.items():
            if isinstance(info, dict) and "version" in info:
                out.append(Package("npm", name, str(info["version"]), source))
                walk(info.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return out


def parse_yarn_lock(text: str, source: str) -> list[Package]:
    out: list[Package] = []
    current: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            specs = [s.strip().strip('"') for s in line.rstrip()[:-1].split(",")]
            current = sorted({s.rsplit("@", 1)[0] for s in specs if "@" in s[1:]})
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and current:
                out.extend(Package("npm", name, m.group(1), source) for name in current)
                current = []
    return out


def parse_go_mod(text: str, source: str) -> list[Package]:
    out = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :]
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append(Package("Go", parts[0], parts[1], source))
    return out


def parse_composer_lock(text: str, source: str) -> list[Package]:
    data = json.loads(text)
    return [
        Package("Packagist", str(p["name"]), str(p["version"]).lstrip("v"), source)
        for key in ("packages", "packages-dev")
        for p in data.get(key) or []
        if "name" in p and "version" in p
    ]


def parse_gemfile_lock(text: str, source: str) -> list[Package]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([0-9][^)\s-]*)(?:-[^)]*)?\)$", line)
        if m:
            out.append(Package("RubyGems", m.group(1), m.group(2), source))
    return out


PARSERS: dict[str, Parser] = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "poetry.lock": _toml_packages("PyPI"),
    "uv.lock": _toml_packages("PyPI"),
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": _toml_packages("crates.io"),
    "go.mod": parse_go_mod,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
}


def parser_for(filename: str) -> Parser | None:
    base = PurePosixPath(filename).name
    if base in PARSERS:
        return PARSERS[base]
    if re.fullmatch(r"requirements[\w.-]*\.txt", base):
        return parse_requirements
    return None


def extract_packages(filename: str, text: str) -> list[Package]:
    parser = parser_for(filename)
    if parser is None:
        return []
    return parser(text, filename)
