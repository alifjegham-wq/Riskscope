import httpx
import pytest

from riskscope.checks.php import ADVISORIES, PhpVersionCheck, Version, branch_status
from riskscope.models import Finding, Severity

from .conftest import make_ctx, site

PHPINFO = (
    b'<html><head><title>PHP 8.3.30 - phpinfo()</title></head><body><h1 class="p">PHP Version 8.3.30</h1>'
    b'<tr><td class="e">session.upload_progress.enabled</td><td class="v">On</td><td class="v">On</td></tr>'
)


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


async def run(
    headers: dict[str, str] | list[tuple[str, str]],
    html: str = "<html></html>",
    extra: dict[str, httpx.Response] | None = None,
) -> dict[str, Finding]:
    r = {"/": httpx.Response(200, headers=headers, text=html), **(extra or {})}
    return by_id(await PhpVersionCheck().run(make_ctx(site(r))))


@pytest.mark.parametrize(
    ("version", "affected", "eol"),
    [
        ((8, 5, 11), True, False),
        ((8, 5, 12), False, False),
        ((8, 4, 26), True, False),
        ((8, 4, 27), False, False),
        ((8, 3, 36), False, False),
        ((8, 2, 34), True, False),
        ((8, 1, 31), True, True),
        ((7, 4, 33), True, True),
        ((5, 3, 29), False, True),  # older than the first affected release, but still end-of-life
        ((8, 6, 0), False, False),  # a branch released after the fix
    ],
)
def test_branch_status(version: Version, affected: bool, eol: bool) -> None:
    advs, is_eol = branch_status(version)
    assert bool(advs) is affected and is_eol is eol


def test_advisory_table_is_consistent() -> None:
    for adv in ADVISORIES:
        assert adv.cves and adv.references and adv.fixed
        for branch, fixed in adv.fixed.items():
            assert fixed[:2] == branch


async def test_vulnerable_header_version_is_critical() -> None:
    found = await run({"x-powered-by": "PHP/8.3.12", "server": "nginx"})
    f = found["php.php2shell"]
    assert f.severity is Severity.CRITICAL
    assert "8.3.36" in f.fix and "CVE-2026-109618" in f.title and "PHP/8.3.12" in f.evidence
    assert "php.eol" not in found


async def test_patched_version_is_clean() -> None:
    assert await run({"x-powered-by": "PHP/8.4.27"}) == {}


async def test_distro_backport_downgrades_to_high() -> None:
    found = await run({"server": "Apache/2.4.57 (Red Hat Enterprise Linux) PHP/8.2.13"})
    f = found["php.php2shell"]
    assert f.severity is Severity.HIGH and "backported" in f.description


async def test_eol_branch_is_critical_and_flagged_eol() -> None:
    found = await run({"x-powered-by": "PHP/7.4.33", "server": "Apache (Ubuntu)"})
    assert found["php.php2shell"].severity is Severity.CRITICAL  # no distro excuse: no fix exists upstream
    assert "end-of-life" in found["php.php2shell"].fix
    assert found["php.eol"].severity is Severity.HIGH


async def test_version_from_exposed_phpinfo() -> None:
    found = await run({}, extra={"/info.php": httpx.Response(200, content=PHPINFO)})
    f = found["php.php2shell"]
    assert "/info.php reports PHP 8.3.30" in f.evidence and "session.upload_progress.enabled = On" in f.evidence


async def test_hidden_version_gives_info_note() -> None:
    found = await run([("set-cookie", "PHPSESSID=abc; Secure; HttpOnly")])
    note = found["php.version_unknown"]
    assert note.severity is Severity.INFO and "PHPSESSID" in note.description and "8.5.12" in note.fix

    wp = await run({}, html='<link href="/wp-content/themes/x/style.css">')
    assert "WordPress" in wp["php.version_unknown"].description


async def test_no_php_no_findings() -> None:
    assert await run({"server": "nginx", "x-powered-by": "Express"}, html='<a href="/about">x</a>') == {}
