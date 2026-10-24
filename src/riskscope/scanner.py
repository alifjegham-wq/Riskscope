"""Run every website check concurrently and assemble a scored report."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from .checks import Check, ScanContext
from .models import CheckError, Report
from .safety import UnsafeTargetError, assert_public_host
from .scoring import apply_score

log = logging.getLogger(__name__)

CHECK_TIMEOUT = 45.0


async def scan_website(ctx: ScanContext, checks: list[Check]) -> Report:
    started = time.monotonic()
    report = Report(target=ctx.target.host, kind="website", verified_owner=ctx.verified_owner)
    # Fail fast (and loudly) on private/unresolvable targets before any check runs.
    await assert_public_host(ctx.target.host, ctx.fetcher.resolver)

    selected = [c for c in checks if ctx.verified_owner or not c.active]

    async def run(check: Check) -> None:
        try:
            findings = await asyncio.wait_for(check.run(ctx), CHECK_TIMEOUT)
        except TimeoutError:
            report.errors.append(CheckError(check=check.title, message="Timed out"))
        except UnsafeTargetError as exc:
            report.errors.append(CheckError(check=check.title, message=str(exc)))
        except httpx.HTTPError as exc:
            report.errors.append(CheckError(check=check.title, message=f"Could not connect: {type(exc).__name__}"))
        except Exception as exc:  # noqa: BLE001 - one broken check must not lose the whole report
            log.exception("check %s failed", check.name)
            report.errors.append(CheckError(check=check.title, message=f"Internal error ({type(exc).__name__})"))
        else:
            if findings:
                report.findings.extend(findings)
            else:
                report.passed.append(check.title)

    await asyncio.gather(*(run(c) for c in selected))
    report.passed.sort()
    report.duration_ms = int((time.monotonic() - started) * 1000)
    return apply_score(report)
