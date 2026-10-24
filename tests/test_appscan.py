import io
import json
import zipfile

import pytest

from riskscope.appscan import UploadError, expand_upload, scan_code
from riskscope.appscan.manifests import extract_packages
from riskscope.appscan.osv import Package, Vuln, parse_vuln
from riskscope.appscan.secrets import find_secrets, mask
from riskscope.models import Category, Severity

from .conftest import FakeVulns


def pkgs(name: str, text: str) -> set[tuple[str, str, str]]:
    return {(p.ecosystem, p.name, p.version) for p in extract_packages(name, text)}


def test_requirements() -> None:
    text = "django==3.2.0  # pinned\nrequests>=2\nuvicorn[standard]==0.30.0\n-e .\n"
    assert pkgs("requirements-dev.txt", text) == {("PyPI", "django", "3.2.0"), ("PyPI", "uvicorn", "0.30.0")}


def test_package_lock_v3_and_v1() -> None:
    v3 = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
        },
    }
    assert pkgs("package-lock.json", json.dumps(v3)) == {
        ("npm", "lodash", "4.17.15"),
        ("npm", "@scope/b", "1.0.0"),
    }
    v1 = {
        "lockfileVersion": 1,
        "dependencies": {"x": {"version": "1.0.0", "dependencies": {"y": {"version": "2.0.0"}}}},
    }
    assert pkgs("package-lock.json", json.dumps(v1)) == {("npm", "x", "1.0.0"), ("npm", "y", "2.0.0")}


def test_yarn_lock() -> None:
    text = """# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.1.2"
  resolved "https://registry.yarnpkg.com/..."

lodash@^4.17.0:
  version "4.17.20"
"""
    assert pkgs("yarn.lock", text) == {("npm", "@babel/core", "7.1.2"), ("npm", "lodash", "4.17.20")}


def test_toml_locks() -> None:
    text = '[[package]]\nname = "jinja2"\nversion = "2.10"\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
    assert pkgs("poetry.lock", text) == {("PyPI", "jinja2", "2.10"), ("PyPI", "serde", "1.0.0")}
    assert ("crates.io", "serde", "1.0.0") in pkgs("Cargo.lock", text)


def test_go_mod() -> None:
    text = (
        "module x\n\ngo 1.22\n\nrequire github.com/a/b v1.2.3\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n)\n"
    )
    assert pkgs("go.mod", text) == {("Go", "github.com/a/b", "v1.2.3"), ("Go", "golang.org/x/net", "v0.17.0")}


def test_composer_and_gemfile_and_pipfile() -> None:
    composer = json.dumps({"packages": [{"name": "monolog/monolog", "version": "v1.0.0"}]})
    assert pkgs("composer.lock", composer) == {("Packagist", "monolog/monolog", "1.0.0")}
    gem = "GEM\n  specs:\n    rails (5.2.0)\n      actionpack (= 5.2.0)\n    nokogiri (1.10.0-x86_64-linux)\n"
    assert pkgs("Gemfile.lock", gem) == {("RubyGems", "rails", "5.2.0"), ("RubyGems", "nokogiri", "1.10.0")}
    pip = json.dumps({"default": {"flask": {"version": "==1.0"}}, "develop": {}})
    assert pkgs("Pipfile.lock", pip) == {("PyPI", "flask", "1.0")}


def test_secrets_found_and_masked() -> None:
    src = 'AWS = "AKIAIOSFODNN7EXAMPLE"\nkey = """-----BEGIN RSA PRIVATE KEY-----\nMIIE..."""\n'
    found = find_secrets("app/settings.py", src)
    assert {f.id for f in found} == {
        "secrets.aws_access_key.app/settings.py",
        "secrets.private_key.app/settings.py",
    }
    aws = next(f for f in found if "aws" in f.id)
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.evidence and "app/settings.py:1" in aws.evidence
    assert mask("short") == "sh…"


def test_parse_vuln() -> None:
    data = {
        "id": "GHSA-1",
        "summary": "Bad",
        "aliases": ["CVE-2024-1"],
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "lodash"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            },
            {"package": {"name": "other"}, "ranges": [{"events": [{"fixed": "9"}]}]},
        ],
    }
    v = parse_vuln(data, Package("npm", "lodash", "4.17.15"))
    assert v.severity is Severity.HIGH and v.fixed == ["4.17.21"]


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_expand_zip_skips_vendored_dirs() -> None:
    data = _zip({"proj/package-lock.json": "{}", "proj/node_modules/x/package-lock.json": "{}", "proj/a.py": "x"})
    assert set(expand_upload("p.zip", data)) == {"proj/package-lock.json", "proj/a.py"}


def test_expand_bad_zip() -> None:
    with pytest.raises(UploadError):
        expand_upload("p.zip", b"not a zip")


async def test_scan_code_end_to_end(jquery_vuln: Vuln) -> None:
    lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/jquery": {"version": "3.4.1"}}})
    files = {"package-lock.json": lock.encode(), "config.js": b'const k = "sk_live_' + b"a" * 24 + b'";'}
    report = await scan_code(files, FakeVulns({("jquery", "3.4.1"): [jquery_vuln]}))
    cats = {f.category for f in report.findings}
    assert cats == {Category.DEPENDENCIES, Category.SECRETS}
    assert report.grade == "F"  # Stripe live key is critical


async def test_scan_code_clean() -> None:
    lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/left-pad": {"version": "1.3.0"}}})
    report = await scan_code({"package-lock.json": lock.encode()}, FakeVulns())
    assert report.grade == "A" and len(report.passed) == 2 and not report.errors
