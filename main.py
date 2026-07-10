#!/usr/bin/env python3

import json
import logging
import random
import shutil
import sys
import time
from pathlib import Path
import argparse

from config import (
    HACKERONE_SCOPE_DIR,
    LOG_DIR,
    LOG_FILE,
    HACKERONE_TARGETS_FILE,
)
from discord_notify import (
    send_discord_scope_notification,
    send_program_discovery_notification,
    send_discord_reports_notification,
    send_discord_hacktivity_notification,
    send_run_error,
    send_run_success,
    send_target_error,
)
from Programs.Hackerone.hackerone_graphql import (
    fetch_hackerone_scopes,
    normalize_response,
)

from Programs.Hackerone.hackerone_discovery import (
    discover_hackerone_bounty_programs,
)

from Programs.Hackerone.hackerone_helper import (
    load_hackerone_targets,
)

from Programs.Hackerone.discover_new_hacktivity_reports import (
    discover_new_hacktivity_reports,
)


# Main() delay config
MIN_DELAY_SECONDS = 1
MAX_DELAY_SECONDS = 2


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--no-alerts",
        action="store_true",
        help="Run normally but do not send Discord notifications.",
    )
    return parser.parse_args()


def setup_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict) -> None:
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

# identifier is the key
# changed identifier usually becomes a removed old / added new asset, not a "changed" item. 
# Would alert because paid added/removed assets are included in "added = [new_map[k]"
def scope_key(item: dict) -> str:
    return f"{item.get('identifier', '')}|{item.get('display_name', '')}"


# True only when the scope asset is both bounty-eligible and submission-eligible.
# Used to filter added/removed assets so mobile alerts only fire for paid, actionable scope.
def is_paid_scope(item: dict) -> bool:
    return (
        item.get("eligible_for_bounty") is True
        and item.get("eligible_for_submission") is True
    )

EXCLUDED_REPORT_ASSET_TYPES = {
    "Executable",
    "SourceCode",
    "AndroidPlayStore",
}


def specific_report_changes(item: dict) -> bool:
    return item.get("display_name") not in EXCLUDED_REPORT_ASSET_TYPES


def compare_snapshots(old: dict, new: dict) -> dict:
    old_map = {scope_key(item): item for item in old.get("scopes", [])}
    new_map = {scope_key(item): item for item in new.get("scopes", [])}

    # First Check - A New Asset was identified as either removed or added
    # old: api.example.com - new: api-v2.example.co
    # changed identifier usually becomes a removed old / added new asset, not a "changed" item. 
    # Would alert because paid added/removed assets are included in "added = [new_map[k]"
    added = [
        new_map[k]
        for k in sorted(set(new_map) - set(old_map))
        if is_paid_scope(new_map[k]) # Filtering to only include newly added assets where eligible_for_bounty/eligible_for_submission == True
    ]

    removed = [
        old_map[k]
        for k in sorted(set(old_map) - set(new_map))
        if is_paid_scope(old_map[k]) # Filtering to only include the old asset state where eligible_for_bounty/eligible_for_submission == True
    ]
    paid_scope_changes = []
    report_changes = []

    for key in sorted(set(old_map) & set(new_map)):
        old_item = old_map[key]
        new_item = new_map[key]

        changes = {}

        # Second Check #1 - Already existing asset became bounty-eligible
        if (
            old_item.get("eligible_for_bounty") is False
            and new_item.get("eligible_for_bounty") is True
        ):
            changes["eligible_for_bounty"] = {
                "old": old_item.get("eligible_for_bounty"),
                "new": new_item.get("eligible_for_bounty"),
            }
        # Second Check #2 - Already existing asset became bounty-eligible
        if (
            old_item.get("eligible_for_submission") is False
            and new_item.get("eligible_for_submission") is True
            and new_item.get("eligible_for_bounty") is True
        ):
            changes["eligible_for_submission"] = {
                "old": old_item.get("eligible_for_submission"),
                "new": new_item.get("eligible_for_submission"),
            }

        if changes:
            paid_scope_changes.append(
                {
                    "identifier": new_item.get("identifier"),
                    "old_identifier": old_item.get("identifier"),
                    "changes": changes,
                    "asset": new_item,
                }
            )
        # Third check - New reports added to an asset
        if (
            specific_report_changes(new_item)
            and old_item.get("total_resolved_reports")
            != new_item.get("total_resolved_reports")
        ):
            report_changes.append(
                {
                    "identifier": new_item.get("identifier"),
                    "changes": {
                        "total_resolved_reports": {
                            "old": old_item.get("total_resolved_reports"),
                            "new": new_item.get("total_resolved_reports"),
                        }
                    },
                    "asset": new_item,
                }
            )

    return {
        "paid_scope": {
            "added": added,
            "removed": removed,
            "changed": paid_scope_changes,
        },
        "reports": {
            "changed": report_changes,
        },
    }

# Paid Scope Section 
def print_diff(handle: str, diff: dict) -> None:
    paid_scope = diff["paid_scope"]

    added = paid_scope["added"]
    removed = paid_scope["removed"]
    changed = paid_scope["changed"]

    if not added and not removed and not changed:
        logging.info("[%s] No paid scope changes detected.", handle)
    else:
        logging.info("[%s] Paid scope changes detected.", handle)

        if added:
            logging.info("[%s] Added assets:", handle)
            for item in added:
                logging.info(
                    "  + %s | bounty=%s | submission=%s | severity=%s",
                    item["identifier"],
                    item["eligible_for_bounty"],
                    item["eligible_for_submission"],
                    item["cvss_score"],
                )

        if removed:
            logging.info("[%s] Removed assets:", handle)
            for item in removed:
                logging.info(
                    "  - %s | bounty=%s | submission=%s | severity=%s",
                    item["identifier"],
                    item["eligible_for_bounty"],
                    item["eligible_for_submission"],
                    item["cvss_score"],
                )

        if changed:
            logging.info("[%s] Modified paid assets:", handle)
            for item in changed:
                logging.info("  * %s", item["identifier"])
                for field, values in item["changes"].items():
                    logging.info(
                        "      %s: %r -> %r",
                        field,
                        values["old"],
                        values["new"],
                    )

    report_changes = diff["reports"]["changed"]

    if report_changes:
        logging.info("[%s] Resolved report count changes:", handle)
        for item in report_changes:
            values = item["changes"]["total_resolved_reports"]
            logging.info(
                "  * %s | resolved reports: %r -> %r",
                item["identifier"],
                values["old"],
                values["new"],
            )

# Function to process each target 
# 1. Hackerone - Run GraphQL API call fetch_hackerone_scopes() for each handle
def process_target(handle: str, alerts_enabled: bool) -> None:
    HACKERONE_SCOPE_DIR.mkdir(parents=True, exist_ok=True)

    current_file = HACKERONE_SCOPE_DIR / f"{handle}.json"
    previous_file = HACKERONE_SCOPE_DIR / f"{handle}_previous_version.json"

    logging.info("=" * 80)
    logging.info("Processing HackerOne target: %s", handle)

    response_data = fetch_hackerone_scopes(handle)
    new_snapshot = normalize_response(handle, response_data)

    logging.info("[%s] Current fetched scope count: %s", handle, len(new_snapshot["scopes"]))

    if not current_file.exists():
        logging.info("[%s] No previous current JSON exists.", handle)
        logging.info("[%s] Saving first snapshot to: %s", handle, current_file)
        save_json(current_file, new_snapshot)
        return

    logging.info("[%s] Existing JSON found. Beginning comparison.", handle)

    old_snapshot = load_json(current_file)
    diff = compare_snapshots(old_snapshot, new_snapshot) # compare_snapshots function
    print_diff(handle, diff)

    paid_scope_diff = diff["paid_scope"]
    reports_diff = diff["reports"]

    if alerts_enabled and (
        paid_scope_diff["added"]
        or paid_scope_diff["removed"]
    ):
        send_discord_scope_notification(handle, paid_scope_diff)

    if alerts_enabled and reports_diff["changed"]:
        send_discord_reports_notification(handle, reports_diff)

    logging.info("[%s] Renaming old current JSON to previous version: %s", handle, previous_file)
    shutil.copy2(current_file, previous_file)

    logging.info("[%s] Saving new current JSON: %s", handle, current_file)
    save_json(current_file, new_snapshot)


def main() -> int:

    args = parse_args()
    alerts_enabled = not args.no_alerts # if python main.py --no-alerts then alerts_enabled = False
    setup_logging()

    logging.info("Program Watcher Started.")
    logging.info("Working directory: %s", Path.cwd())
    logging.info("Hackerone targets file: %s", HACKERONE_TARGETS_FILE)
    logging.info("Log file: %s", LOG_FILE)

    # Phase 1: Discover and verify HackerOne bounty programs
    logging.info("=" * 80)
    logging.info("Phase 1: Discovering and verifying HackerOne bounty programs...")

    try:
        # Prim Function from hackerone_discovery.py - Run and save output to discovery_diff
        # Which returns of dictionary of report changes
        discovery_diff = discover_hackerone_bounty_programs()

        logging.info(
            "Phase 1 complete. Old total=%s Current total=%s Added=%s Removed=%s",
            discovery_diff["old_total"],
            discovery_diff["total"],
            len(discovery_diff["added"]), # Lists
            len(discovery_diff["removed"]),
        )

        if alerts_enabled and (discovery_diff["added"] or discovery_diff["removed"]):
            send_program_discovery_notification(discovery_diff)

    except Exception as exc:
        logging.exception("Phase 1 failed: HackerOne program discovery error: %s", exc)

        if alerts_enabled:
            try:
                send_run_error(total_targets=0, failures=1)
            except Exception as discord_exc:
                logging.exception("Failed to send Discord discovery error alert: %s", discord_exc)

        return 1

    logging.info("=" * 80)

    # Phase 2: Check individual HackerOne scope changes
    logging.info("Phase 2: Loading targets and checking HackerOne scope changes...")
    
    try:
        targets = load_hackerone_targets() # Pull from /Watchers.hackerone.py
    except Exception as exc:
        logging.exception("Failed to load targets: %s", exc)

        if alerts_enabled:
            try:
                send_run_error(total_targets=0, failures=1)
            except Exception as discord_exc:
                logging.exception("Failed to send Discord startup error alert: %s", discord_exc)

        return 1

    if not targets:
        logging.error("No targets found in %s", HACKERONE_TARGETS_FILE)

        if alerts_enabled:
            try:
                send_run_error(total_targets=0, failures=1)
            except Exception as discord_exc:
                logging.exception("Failed to send Discord no-targets error alert: %s", discord_exc)

        return 1

    logging.info("Loaded %s target(s): %s", len(targets), ", ".join(targets))

    failures = 0

    total_targets = len(targets)

    # Main Loop to iterate over the list of string handles
    for index, handle in enumerate(targets, start=1):
        progress_percent = (index / total_targets) * 100

        logging.info(
            "Progress: target %s/%s (%.1f%% complete)",
            index,
            total_targets,
            progress_percent,
        )
        try:
            process_target(handle, alerts_enabled) # process_target function iteration
        except Exception as exc:
            failures += 1
            logging.exception("[%s] Failed: %s", handle, exc)
            
            
            if alerts_enabled:
                try:
                    
                    send_target_error(handle, exc)
                except Exception as discord_exc:
                    logging.exception(
                        "[%s] Failed to send Discord target error alert: %s",
                        handle,
                        discord_exc,
                    )

        if index < total_targets:
            delay = random.uniform(MIN_DELAY_SECONDS, MAX_DELAY_SECONDS)
            logging.info("Sleeping %.1f seconds before next target...", delay)
            time.sleep(delay)


    # Phase 3: Pull Hactivity Report Data and Send to Discord
    logging.info("=" * 80)
    logging.info(
        "Phase 3: Checking HackerOne Hacktivity for new disclosures..."
    )

    try:
        hacktivity_result = discover_new_hacktivity_reports()

        new_hacktivity_reports = hacktivity_result["new_reports"]

        logging.info(
            "Phase 3 complete. Rows=%s New reports=%s Baseline created=%s",
            hacktivity_result["rows_returned"],
            hacktivity_result["new_report_count"],
            hacktivity_result["baseline_created"],
        )

        if alerts_enabled and new_hacktivity_reports:
            send_discord_hacktivity_notification(
                reports=new_hacktivity_reports,
                source_url=hacktivity_result["source_url"],
            )

    except Exception as exc:
        failures += 1

        logging.exception(
            "Phase 3 failed: HackerOne Hacktivity error: %s",
            exc,
        )

        if alerts_enabled:
            try:
                send_run_error(
                    total_targets=len(targets),
                    failures=failures,
                )
            except Exception as discord_exc:
                logging.exception(
                    "Failed to send Discord Hacktivity error alert: %s",
                    discord_exc,
                )

    logging.info("=" * 80)

    summary_message = f"Run complete. Targets={len(targets)} Failures={failures}"
    logging.info(summary_message)

    # Build the exact same timestamp format as the log file.
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    record = logging.LogRecord(
        name=logging.getLogger().name,
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=summary_message,
        args=(),
        exc_info=None,
    )

    discord_log_line = formatter.format(record)

    if alerts_enabled:
        try:
            if failures == 0:
                send_run_success(discord_log_line)
            else:
                send_run_error(len(targets), failures)
        except Exception as exc:
            logging.exception("Failed to send Discord run status: %s", exc)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())