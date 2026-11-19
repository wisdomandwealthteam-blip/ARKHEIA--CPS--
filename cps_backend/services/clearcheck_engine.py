"""
cps_backend.services.clearcheck_engine
=========================================
The deterministic ClearCheck rules engine. Pure functions only — no I/O,
no clock reads, no randomness. The same request always produces the same
check_id, the same findings in the same order, and the same redacted
summary. Persistence lives in services/clearcheck_store.py.

Every account reference emitted by this module is masked via
utils/redaction.py before it goes anywhere (response, log, or disk).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from cps_backend.schemas.clearcheck import (
    AccountStatus,
    ClearCheckAccountEntry,
    ClearCheckPreviewRequest,
    Finding,
)
from cps_backend.utils.redaction import mask_value

NON_LEGAL_ADVICE_NOTICE = (
    "ClearCheck performs automated, deterministic consistency checks on "
    "the data you provide. Its output is informational only, is not legal "
    "advice, and does not create an attorney-client relationship. Consult "
    "a licensed attorney or a qualified consumer-protection professional "
    "in your jurisdiction before acting on these findings."
)

# Jurisdiction metadata attached to every preview/report. This is
# informational context, not legal guidance (see notice above).
JURISDICTION_METADATA: dict[str, dict[str, Any]] = {
    "US": {
        "name": "United States (federal)",
        "primary_statute": "Fair Credit Reporting Act (15 U.S.C. § 1681)",
        "dispute_window_days": 30,
        "regulator": "Consumer Financial Protection Bureau (CFPB)",
    },
    "US-CA": {
        "name": "California, United States",
        "primary_statute": (
            "California Consumer Credit Reporting Agencies Act "
            "(Cal. Civ. Code § 1785.1 et seq.) alongside the federal FCRA"
        ),
        "dispute_window_days": 30,
        "regulator": "California DFPI and the CFPB",
    },
    "US-NY": {
        "name": "New York, United States",
        "primary_statute": (
            "N.Y. Gen. Bus. Law Art. 25 (Fair Credit Reporting) "
            "alongside the federal FCRA"
        ),
        "dispute_window_days": 30,
        "regulator": "New York DFS and the CFPB",
    },
}

_UNKNOWN_JURISDICTION: dict[str, Any] = {
    "name": "Unrecognized jurisdiction",
    "primary_statute": None,
    "dispute_window_days": None,
    "regulator": None,
    "note": (
        "No jurisdiction-specific metadata is available for this code; "
        "federal/US defaults were not assumed."
    ),
}


def jurisdiction_metadata(code: str) -> dict[str, Any]:
    return dict(JURISDICTION_METADATA.get(code.upper(), _UNKNOWN_JURISDICTION))


def compute_check_id(request: ClearCheckPreviewRequest) -> str:
    """Deterministic check id: the SHA-256 of the canonical JSON form of
    the request. The same submission always maps to the same check, so a
    consumer re-running a preview never creates (or pays for) a
    duplicate. The raw input is hashed, never stored or echoed."""
    canonical = json.dumps(
        request.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"chk_{digest}"


def _finding(
    code: str,
    severity: str,
    account: ClearCheckAccountEntry,
    field: str,
    description: str,
) -> Finding:
    return Finding(
        code=code,
        severity=severity,
        account_ref=mask_value(account.account_number, visible_suffix=4),
        field=field,
        description=description,
    )


def run_checks(request: ClearCheckPreviewRequest) -> list[Finding]:
    """Runs every consistency rule against every account, in a fixed
    order (accounts in submission order; date, then balance, then status
    rules). Output is fully deterministic for a given request."""
    findings: list[Finding] = []
    report_date = request.report_date

    for account in request.accounts:
        # ---- date consistency -------------------------------------
        if account.date_closed and account.date_closed < account.date_opened:
            findings.append(
                _finding(
                    "DATE_CLOSED_BEFORE_OPENED",
                    "high",
                    account,
                    "date_closed",
                    "Closed date precedes the opened date.",
                )
            )
        if (
            account.date_of_last_activity
            and account.date_of_last_activity < account.date_opened
        ):
            findings.append(
                _finding(
                    "ACTIVITY_BEFORE_OPENED",
                    "medium",
                    account,
                    "date_of_last_activity",
                    "Last-activity date precedes the opened date.",
                )
            )
        for field_name, value in (
            ("date_opened", account.date_opened),
            ("date_closed", account.date_closed),
            ("date_of_last_activity", account.date_of_last_activity),
        ):
            if value and value > report_date:
                findings.append(
                    _finding(
                        "DATE_IN_FUTURE",
                        "medium",
                        account,
                        field_name,
                        f"{field_name} is after the report date.",
                    )
                )

        # ---- balance consistency ----------------------------------
        if (
            account.status in (AccountStatus.CLOSED, AccountStatus.PAID)
            and account.reported_balance > 0
        ):
            findings.append(
                _finding(
                    "BALANCE_ON_CLOSED_ACCOUNT",
                    "high",
                    account,
                    "reported_balance",
                    "A closed/paid account still reports a nonzero balance.",
                )
            )
        if (
            account.credit_limit is not None
            and account.reported_balance > account.credit_limit
        ):
            findings.append(
                _finding(
                    "BALANCE_EXCEEDS_LIMIT",
                    "medium",
                    account,
                    "reported_balance",
                    "Reported balance exceeds the credit limit.",
                )
            )
        if account.reported_past_due > account.reported_balance:
            findings.append(
                _finding(
                    "PAST_DUE_EXCEEDS_BALANCE",
                    "high",
                    account,
                    "reported_past_due",
                    "Past-due amount exceeds the reported balance.",
                )
            )

        # ---- status consistency -----------------------------------
        if account.status == AccountStatus.CLOSED and account.date_closed is None:
            findings.append(
                _finding(
                    "CLOSED_WITHOUT_DATE",
                    "low",
                    account,
                    "date_closed",
                    "Account is marked closed but has no closed date.",
                )
            )
        if account.status == AccountStatus.OPEN and account.date_closed is not None:
            findings.append(
                _finding(
                    "OPEN_WITH_CLOSED_DATE",
                    "medium",
                    account,
                    "status",
                    "Account is marked open but carries a closed date.",
                )
            )
        if account.status == AccountStatus.PAID and account.reported_past_due > 0:
            findings.append(
                _finding(
                    "PAID_WITH_PAST_DUE",
                    "high",
                    account,
                    "reported_past_due",
                    "Account is marked paid but reports a past-due amount.",
                )
            )

    return findings


def redacted_summary(findings: list[Finding]) -> list[str]:
    """One masked line per finding — safe for the locked preview. Only
    the masked account reference and rule description appear."""
    return [
        f"[{f.severity}] account {f.account_ref}: {f.description}"
        for f in findings
    ]
