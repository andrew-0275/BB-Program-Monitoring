import logging
from datetime import datetime, timezone

import requests

from config import (
    DISCORD_CHANGE_WEBHOOK_URL,
    DISCORD_LOG_WEBHOOK_URL,
    DISCORD_BB_REPORTS_URL,
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
            f"**{identifier}**\n"
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