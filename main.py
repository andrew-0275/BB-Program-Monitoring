#!/usr/bin/env python3

import json
import logging
import random
import shutil
import sys
import time
from pathlib import Path

from config import (
    DATA_DIR,
    LOG_DIR,
    LOG_FILE,
    MAX_DELAY_SECONDS,
    MIN_DELAY_SECONDS,
    TARGETS_FILE,
)
from discord_notify import (
    send_discord_notification,
    send_run_error,
    send_run_success,
    send_target_error,
)
from graphql import fetch_scopes, normalize_response
from watchers.hackerone import load_targets


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


def compare_snapshots(old: dict, new: dict) -> dict:
    old_map = {item["identifier"]: item for item in old.get("scopes", [])}
    new_map = {item["identifier"]: item for item in new.get("scopes", [])}

    added = [new_map[k] for k in sorted(set(new_map) - set(old_map))]
    removed = [old_map[k] for k in sorted(set(old_map) - set(new_map))]

    changed = []

    for identifier in sorted(set(old_map) & set(new_map)):
        old_item = old_map[identifier]
        new_item = new_map[identifier]

        field_changes = {}

        for field in [
            "display_name",
            "eligible_for_bounty",
            "eligible_for_submission",
            "cvss_score",
            "instruction",
            "total_resolved_reports",
        ]:
            if old_item.get(field) != new_item.get(field):
                field_changes[field] = {
                    "old": old_item.get(field),
                    "new": new_item.get(field),
                }

        if field_changes:
            changed.append(
                {
                    "identifier": identifier,
                    "changes": field_changes,
                }
            )

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def print_diff(handle: str, diff: dict) -> None:
    added = diff["added"]
    removed = diff["removed"]
    changed = diff["changed"]

    if not added and not removed and not changed:
        logging.info("[%s] No scope changes detected.", handle)
        return

    logging.info("[%s] Scope changes detected.", handle)

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
        logging.info("[%s] Changed assets:", handle)
        for item in changed:
            logging.info("  * %s", item["identifier"])
            for field, values in item["changes"].items():
                logging.info("      %s: %r -> %r", field, values["old"], values["new"])


def process_target(handle: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    current_file = DATA_DIR / f"{handle}.json"
    previous_file = DATA_DIR / f"{handle}_previous_version.json"

    logging.info("=" * 80)
    logging.info("Processing HackerOne target: %s", handle)

    response_data = fetch_scopes(handle)
    new_snapshot = normalize_response(handle, response_data)

    logging.info("[%s] Current fetched scope count: %s", handle, len(new_snapshot["scopes"]))

    if not current_file.exists():
        logging.info("[%s] No previous current JSON exists.", handle)
        logging.info("[%s] Saving first snapshot to: %s", handle, current_file)
        save_json(current_file, new_snapshot)
        return

    logging.info("[%s] Existing JSON found. Beginning comparison.", handle)

    old_snapshot = load_json(current_file)
    diff = compare_snapshots(old_snapshot, new_snapshot)
    print_diff(handle, diff)

    if diff["added"] or diff["removed"] or diff["changed"]:
        send_discord_notification(handle, diff)

    logging.info("[%s] Renaming old current JSON to previous version: %s", handle, previous_file)
    shutil.copy2(current_file, previous_file)

    logging.info("[%s] Saving new current JSON: %s", handle, current_file)
    save_json(current_file, new_snapshot)


def main() -> int:
    setup_logging()

    logging.info("HackerOne Scope Watcher started.")
    logging.info("Working directory: %s", Path.cwd())
    logging.info("Targets file: %s", TARGETS_FILE)
    logging.info("Log file: %s", LOG_FILE)

    try:
        targets = load_targets()
    except Exception as exc:
        logging.exception("Failed to load targets: %s", exc)

        try:
            send_run_error(total_targets=0, failures=1)
        except Exception as discord_exc:
            logging.exception("Failed to send Discord startup error alert: %s", discord_exc)

        return 1

    if not targets:
        logging.error("No targets found in %s", TARGETS_FILE)

        try:
            send_run_error(total_targets=0, failures=1)
        except Exception as discord_exc:
            logging.exception("Failed to send Discord no-targets error alert: %s", discord_exc)

        return 1

    logging.info("Loaded %s target(s): %s", len(targets), ", ".join(targets))

    failures = 0

    for index, handle in enumerate(targets):
        try:
            process_target(handle)
        except Exception as exc:
            failures += 1
            logging.exception("[%s] Failed: %s", handle, exc)

            try:
                send_target_error(handle, exc)
            except Exception as discord_exc:
                logging.exception(
                    "[%s] Failed to send Discord target error alert: %s",
                    handle,
                    discord_exc,
                )

        if index < len(targets) - 1:
            delay = random.uniform(MIN_DELAY_SECONDS, MAX_DELAY_SECONDS)
            logging.info("Sleeping %.1f seconds before next target...", delay)
            time.sleep(delay)

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