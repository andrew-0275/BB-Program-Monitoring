import logging
from datetime import datetime, timezone

import requests

from config import (
    DISCORD_CHANGE_WEBHOOK_URL,
    DISCORD_LOG_WEBHOOK_URL,
    DISCORD_BB_REPORTS_URL,
    DISCORD_HACKTIVITY_WEBHOOK_URL,
    DISCORD_TIMEOUT,
)


def discord_bool(value: bool) -> str:
    return "✅ True" if value else "❌ False"


def truncate(value, limit: int = 900) -> str:
    value = str(value or "")
    return value if len(value) <= limit else value[:limit] + "...[truncated]"


def choose_embed_color(diff: dict) -> int:
    if diff["removed"]:
        return 0xED4245
    if diff["added"]:
        return 0x57F287
    return 0x5865F2

def format_instruction(item: dict, limit: int = 350) -> str:
    instruction = truncate(item.get("instruction", ""), limit)
    return instruction if instruction else "N/A"

def format_scope_added(items: list[dict]) -> str:
    if not items:
        return "None"

    lines = []

    for item in items[:8]:
        lines.append(
            f"```text\n"
            f"{item['identifier']}\n"
            f"Bounty: {discord_bool(item['eligible_for_bounty'])}\n"
            f"Submission: {discord_bool(item['eligible_for_submission'])}\n"
            f"Severity: {item['cvss_score'] or 'N/A'}\n"
            f"Instruction: {format_instruction(item)}\n"
            f"```"
        )

    if len(items) > 8:
        lines.append(f"...and {len(items) - 8} more added item(s).")

    return "\n".join(lines)


def format_scope_removed(items: list[dict]) -> str:
    if not items:
        return "None"

    lines = []

    for item in items[:8]:
        lines.append(
            f"```text\n"
            f"{item['identifier']}\n"
            f"Bounty: {discord_bool(item['eligible_for_bounty'])}\n"
            f"Submission: {discord_bool(item['eligible_for_submission'])}\n"
            f"Severity: {item['cvss_score'] or 'N/A'}\n"
            f"Instruction: {format_instruction(item)}\n"
            f"```"
        )

    if len(items) > 8:
        lines.append(f"...and {len(items) - 8} more removed item(s).")

    return "\n".join(lines)


def send_discord_scope_notification(handle: str, diff: dict) -> None:
    if not DISCORD_CHANGE_WEBHOOK_URL:
        logging.info("[%s] Discord change webhook not configured. Skipping alert.", handle)
        return

    added_count = len(diff["added"])
    removed_count = len(diff["removed"])

    payload = {
        "username": "BB Scope Alerts",
        "embeds": [
            {
                "title": "🚨 HackerOne Paid Scope Change",
                "url": f"https://hackerone.com/{handle}/policy_scopes",
                "color": choose_embed_color(diff),
                "fields": [
                    {"name": "Program", "value": f"`{handle}`", "inline": True},
                    {"name": "Platform", "value": "`HackerOne`", "inline": True},
                    {
                        "name": "Summary",
                        "value": (
                            f"🟢 Added: **{added_count}**\n"
                            f"🔴 Removed: **{removed_count}**\n"
                        ),
                        "inline": False,
                    },
                    {
                        "name": "🟢 Added",
                        "value": format_scope_added(diff["added"])[:1024],
                        "inline": False,
                    },
                    {
                        "name": "🔴 Removed",
                        "value": format_scope_removed(diff["removed"])[:1024],
                        "inline": False,
                    },
                    {
                        "name": "Policy",
                        "value": f"https://hackerone.com/{handle}/policy_scopes",
                        "inline": False,
                    },
                ],
                "footer": {"text": "HackerOne Scope Watcher"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    response = requests.post(
        DISCORD_CHANGE_WEBHOOK_URL,
        json=payload,
        timeout=DISCORD_TIMEOUT,
    )
    response.raise_for_status()

    logging.info("[%s] Discord scope-change notification sent.", handle)


def send_run_success(log_line: str) -> None:
    if not DISCORD_LOG_WEBHOOK_URL:
        logging.info("Discord log webhook not configured. Skipping success summary.")
        return

    payload = {
        "username": "BB Scope Script Log",
        "content": f"```text\n{log_line}\n```",
    }

    response = requests.post(
        DISCORD_LOG_WEBHOOK_URL,
        json=payload,
        timeout=DISCORD_TIMEOUT,
    )
    response.raise_for_status()

    logging.info("Discord run success summary sent.")


def send_run_error(total_targets: int, failures: int) -> None:
    if not DISCORD_CHANGE_WEBHOOK_URL:
        logging.info("Discord change webhook not configured. Skipping error alert.")
        return

    payload = {
        "username": "BB Scope Alerts",
        "embeds": [
            {
                "title": "🚨 Scope Watcher Completed With Errors",
                "color": 0xED4245,
                "fields": [
                    {"name": "Targets", "value": str(total_targets), "inline": True},
                    {"name": "Failures", "value": str(failures), "inline": True},
                ],
                "footer": {"text": "BB Scope Alerts"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    response = requests.post(
        DISCORD_CHANGE_WEBHOOK_URL,
        json=payload,
        timeout=DISCORD_TIMEOUT,
    )
    response.raise_for_status()

    logging.info("Discord run error alert sent.")


def format_program_handles(items: list[str], symbol: str) -> str:
    if not items:
        return "None"

    lines = [
        f"{symbol} [`{handle}`](https://hackerone.com/{handle}?type=team)"
        for handle in items[:20]
    ]

    if len(items) > 20:
        lines.append(f"...and {len(items) - 20} more program(s).")

    return "\n".join(lines)


def send_program_discovery_notification(diff: dict) -> None:
    if not DISCORD_CHANGE_WEBHOOK_URL:
        logging.info("Discord change webhook not configured. Skipping program discovery alert.")
        return

    added = diff.get("added", [])
    removed = diff.get("removed", [])

    if not added and not removed:
        return

    color = 0x57F287 if added and not removed else 0xED4245 if removed and not added else 0xFAA61A

    payload = {
        "username": "BB Scope Alerts",
        "embeds": [
            {
                "title": "📡 HackerOne Program Discovery Change",
                "color": color,
                "fields": [
                    {"name": "Platform", "value": "`HackerOne`", "inline": True},
                    {"name": "Old Total", "value": str(diff.get("old_total")), "inline": True},
                    {"name": "Current Total", "value": str(diff.get("total")), "inline": True},
                    {
                        "name": "🟢 New Programs",
                        "value": format_program_handles(added, "+")[:1024],
                        "inline": False,
                    },
                    {
                        "name": "🔴 Removed Programs",
                        "value": format_program_handles(removed, "-")[:1024],
                        "inline": False,
                    },
                    {
                        "name": "HackerOne Paid Programs List",
                        "value": "<https://hackerone.com/opportunities/all/search?bbp=true&ordering=Newest+programs>",
                        "inline": False,
                    },
                    {
                        "name": "Targets File",
                        "value": f"`{diff.get('targets_file')}`",
                        "inline": False,
                    },
                ],
                "footer": {"text": "HackerOne Program Discovery"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    response = requests.post(
        DISCORD_CHANGE_WEBHOOK_URL,
        json=payload,
        timeout=DISCORD_TIMEOUT,
    )
    response.raise_for_status()

    logging.info("Discord program discovery notification sent.")
    

def send_target_error(handle: str, error: Exception) -> None:
    if not DISCORD_CHANGE_WEBHOOK_URL:
        logging.info("[%s] Discord change webhook not configured. Skipping target error alert.", handle)
        return

    policy_url = getattr(error, "policy_url", f"https://hackerone.com/{handle}/policy_scopes")
    graphql_url = getattr(error, "graphql_url", "https://hackerone.com/graphql")
    status_code = getattr(error, "status_code", "N/A")
    response_text = getattr(error, "response_text", "")

    payload = {
        "username": "BB Scope Alerts",
        "embeds": [
            {
                "title": "🚨 HackerOne Scope Watcher Target Failed",
                "url": policy_url,
                "color": 0xED4245,
                "fields": [
                    {"name": "Target", "value": f"`{handle}`", "inline": True},
                    {"name": "HTTP Status", "value": f"`{status_code}`", "inline": True},
                    {"name": "Error Type", "value": f"`{type(error).__name__}`", "inline": True},
                    {"name": "Policy URL", "value": policy_url, "inline": False},
                    {"name": "GraphQL Endpoint", "value": graphql_url, "inline": False},
                    {"name": "Error", "value": f"```text\n{truncate(str(error), 900)}\n```", "inline": False},
                    {
                        "name": "Response",
                        "value": f"```text\n{truncate(response_text, 900)}\n```" if response_text else "`N/A`",
                        "inline": False,
                    },
                ],
                "footer": {"text": "BB Scope Alerts"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    response = requests.post(
        DISCORD_CHANGE_WEBHOOK_URL,
        json=payload,
        timeout=DISCORD_TIMEOUT,
    )
    response.raise_for_status()

    logging.info("[%s] Discord target error alert sent.", handle)


def format_report_changes(handle: str, items: list[dict]) -> str:
    if not items:
        return "None"

    sections = []

    for item in items[:10]:
        asset = item.get("asset", {})
        identifier = item.get("identifier") or asset.get("identifier") or "Unknown asset"

        values = item["changes"]["total_resolved_reports"]
        old = values["old"]
        new = values["new"]

        sections.append(
            f"Asset: **{identifier}**\n"
            f"Resolved Reports: `{old}` → `{new}`\n"
            f"Type: `{asset.get('display_name', 'N/A')}`\n"
            f"Bounty: {discord_bool(asset.get('eligible_for_bounty', False))}\n"
            f"Submission: {discord_bool(asset.get('eligible_for_submission', False))}\n"
            f"Severity: `{asset.get('cvss_score') or 'N/A'}`\n"
            f"Policy: <https://hackerone.com/{handle}/policy_scopes>"
        )

    if len(items) > 10:
        sections.append(f"...and {len(items) - 10} more report-count change(s).")

    return "\n\n".join(sections)


def send_discord_reports_notification(handle: str, diff: dict) -> None:
    if not DISCORD_BB_REPORTS_URL:
        logging.info("[%s] Discord BB reports webhook not configured. Skipping report alert.", handle)
        return

    changed = diff.get("changed", [])

    if not changed:
        return

    policy_url = f"https://hackerone.com/{handle}/policy_scopes"

    payload = {
        "username": "BB Reports",
        "embeds": [
            {
                "title": "📊 HackerOne Resolved Reports Changed",
                "url": policy_url,
                "color": 0x5865F2,
                "fields": [
                    {"name": "Program", "value": f"`{handle}`", "inline": True},
                    {"name": "Platform", "value": "`HackerOne`", "inline": True},
                    {"name": "Changed Assets", "value": str(len(changed)), "inline": True},
                    {
                        "name": "Report Count Changes",
                        "value": format_report_changes(handle, changed)[:1024],
                        "inline": False,
                    },
                    {
                        "name": "Policy",
                        "value": policy_url,
                        "inline": False,
                    },
                ],
                "footer": {"text": "HackerOne Resolved Reports Watcher"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    response = requests.post(
        DISCORD_BB_REPORTS_URL,
        json=payload,
        timeout=DISCORD_TIMEOUT,
    )
    response.raise_for_status()

    logging.info("[%s] Discord resolved-reports notification sent.", handle)


def hacktivity_severity_color(severity: str) -> int:
    colors = {
        "critical": 0xED4245,
        "high": 0xF47B20,
        "medium": 0xFEE75C,
        "low": 0x57F287,
        "none": 0x5865F2,
    }

    return colors.get(
        str(severity or "").lower(),
        0x5865F2,
    )


def format_hacktivity_award(report: dict) -> str:
    amount = report.get("total_awarded_amount")

    if amount is None:
        return "Not shown"

    currency = report.get("program_currency") or "USD"

    try:
        return f"{currency} {float(amount):,.2f}"
    except (TypeError, ValueError):
        return f"{currency} {amount}"


def build_hacktivity_embed(report: dict) -> dict:
    title = truncate(
        report.get("title") or "Untitled report",
        250,
    )

    summary = truncate(
        report.get("hacktivity_summary") or "No summary available.",
        1000,
    )

    program_name = (
        report.get("program_name")
        or report.get("program_handle")
        or "Unknown program"
    )

    program_handle = report.get("program_handle") or "N/A"
    program_url = (
        report.get("program_url")
        or f"https://hackerone.com/{program_handle}"
    )

    reporter = report.get("reporter") or "N/A"
    severity = report.get("severity_rating") or "N/A"
    cwe = report.get("cwe") or "N/A"
    disclosed_at = report.get("disclosed_at") or "N/A"
    report_state = report.get("report_state") or "N/A"
    votes = report.get("votes")

    return {
        "title": title,
        "url": report.get("report_url"),
        "description": summary,
        "color": hacktivity_severity_color(severity),
        "fields": [
            {
                "name": "Program",
                "value": f"[{program_name}]({program_url})",
                "inline": True,
            },
            {
                "name": "Handle",
                "value": f"`{program_handle}`",
                "inline": True,
            },
            {
                "name": "Report ID",
                "value": f"`{report.get('report_id')}`",
                "inline": True,
            },
            {
                "name": "Severity",
                "value": f"`{severity}`",
                "inline": True,
            },
            {
                "name": "State",
                "value": f"`{report_state}`",
                "inline": True,
            },
            {
                "name": "Award",
                "value": format_hacktivity_award(report),
                "inline": True,
            },
            {
                "name": "Reporter",
                "value": f"`{reporter}`",
                "inline": True,
            },
            {
                "name": "Votes",
                "value": str(votes if votes is not None else "N/A"),
                "inline": True,
            },
            {
                "name": "CWE",
                "value": truncate(cwe, 250),
                "inline": False,
            },
            {
                "name": "Disclosed",
                "value": f"`{disclosed_at}`",
                "inline": False,
            },
        ],
        "footer": {
            "text": "HackerOne Hacktivity Watcher"
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def send_discord_hacktivity_notification(
    reports: list[dict],
    source_url: str,
) -> None:
    if not DISCORD_HACKTIVITY_WEBHOOK_URL:
        logging.info(
            "Discord Hacktivity webhook not configured. "
            "Skipping Hacktivity alert."
        )
        return

    if not reports:
        return

    # Discord accepts at most 10 embeds in one webhook message.
    batch_size = 10

    for start in range(0, len(reports), batch_size):
        batch = reports[start:start + batch_size]

        payload = {
            "username": "BB Hacktivity",
            "content": (
                f"📰 **{len(batch)} new HackerOne disclosure(s)**\n"
                f"Filtered Hacktivity: <{source_url}>"
            ),
            "embeds": [
                build_hacktivity_embed(report)
                for report in batch
            ],
        }

        response = requests.post(
            DISCORD_HACKTIVITY_WEBHOOK_URL,
            json=payload,
            timeout=DISCORD_TIMEOUT,
        )
        response.raise_for_status()

    logging.info(
        "Discord Hacktivity notification sent for %s new report(s).",
        len(reports),
    )