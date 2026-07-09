import json
import logging
import random
import time
from pathlib import Path
import shutil

import requests
from config import (
    HACKERONE_GRAPHQL_BASE_URL,
    HACKERONE_DISCOVERY_DIR,
    HACKERONE_TARGETS_FILE,
    HACKERONE_DISCOVERY_QUERY_FILE,
)

# GraphQL API Call Config
PAGE_SIZE = 100
SLEEP_RANGE = (1, 2)


# Build GraphQL variables for HackerOne program discovery.
# This filters to programs where the PROGRAM has offers_bounties=True.
def build_variables(offset: int) -> dict:
    return {
        "size": PAGE_SIZE,
        "from": offset,
        "query": {},
        "filter": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {
                                    "term": {
                                        "offers_bounties": True
                                    }
                                }
                            ],
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "field": "launched_at",
                "direction": "DESC",
            }
        ],
        "post_filters": {
            "my_programs": False,
            "bookmarked": False,
            "campaign_teams": False,
        },
        "product_area": "opportunity_discovery",
        "product_feature": "search",
    }


def fetch_page(session: requests.Session, query: str, offset: int) -> dict:
    payload = {
        "operationName": "DiscoveryQuery",
        "query": query,
        "variables": build_variables(offset), # Applies the offers_bounties = True discovery filter 
    }

    response = session.post(HACKERONE_GRAPHQL_BASE_URL, json=payload, timeout=30)

    if response.status_code == 429:
        logging.warning("Rate limited during program discovery. Sleeping 90 seconds.")
        time.sleep(90)
        return fetch_page(session, query, offset)

    response.raise_for_status()
    data = response.json()

    if data.get("errors"):
        raise RuntimeError(json.dumps(data["errors"], indent=2))

    return data


def load_old_snapshot() -> list[str]:
    if not SNAPSHOT_FILE.exists():
        return []

    return json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))


def fetch_all_bounty_programs() -> list[str]:
    query = HACKERONE_DISCOVERY_QUERY_FILE.read_text(encoding="utf-8")

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": "https://hackerone.com",
            "Referer": "https://hackerone.com/directory/programs",
        }
    )

    current_program_handles = []
    total = None
    offset = 0

    while total is None or offset < total:
        logging.info("Discovery: fetching HackerOne programs offset=%s", offset)

        data = fetch_page(session, query, offset)
        search = data["data"]["opportunities_search"]
        total = search["total_count"]

        for node in search.get("nodes", []):
            handle = node.get("handle")
            if handle and handle not in current_program_handles:
                current_program_handles.append(handle)

        offset += PAGE_SIZE
        time.sleep(random.uniform(*SLEEP_RANGE))

    return current_program_handles


# Function write hackerone_targets.txt with all currently fetched programs everytime regardless of diff
# Bundled with full URL and / policy_scopes
def write_hackerone_targets_file(current_program_handles: list[str]) -> None:
    urls = [f"https://hackerone.com/{handle}/policy_scopes" for handle in current_program_handles]
    HACKERONE_TARGETS_FILE.write_text("\n".join(urls) + "\n", encoding="utf-8")


# 1. Read the previous snapshot
# 2. Compare it to the new porgram handles
# 3. Saving the snapshots
# 4. Returning the diff
def compare_program_snapshots(current_program_handles: list[str]) -> dict:
    current_snapshot_file = HACKERONE_DISCOVERY_DIR / "hackerone_programs_snapshot.json"
    previous_snapshot_file = HACKERONE_DISCOVERY_DIR / "hackerone_programs_previous_version.json"

    if not current_snapshot_file.exists():
        logging.info("[Discovery] No previous current JSON exists.")
        logging.info("[Discovery] Saving first snapshot to: %s", current_snapshot_file)

        # Writes/saves first snapshot history with the all program handles
        current_snapshot_file.write_text(
            json.dumps(current_program_handles, indent=2),
            encoding="utf-8",
        )

        return {
            "platform": "hackerone",
            "total": len(current_program_handles),
            "old_total": 0,
            "added": current_program_handles,
            "removed": [],
            "HACKERONE_TARGETS_FILE": str(HACKERONE_TARGETS_FILE),
            "snapshot_file": str(current_snapshot_file),
            "previous_snapshot_file": str(previous_snapshot_file),
        }

    logging.info("[Discovery] Existing JSON found. Beginning comparison.")

    stored_program_handles = json.loads(current_snapshot_file.read_text(encoding="utf-8"))

    # Compare current discovered bounty-program handles against the previous snapshot.
    added = sorted(set(current_program_handles) - set(stored_program_handles)) # in current HackerOne list, but not in old snapshot
    removed = sorted(set(stored_program_handles) - set(current_program_handles)) # in old snapshot, but not in current HackerOne list

    logging.info(
        "[Discovery] Saving already-stored snapshot as previous version: %s",
        previous_snapshot_file,
    )
    shutil.copy2(current_snapshot_file, previous_snapshot_file)

    logging.info(
        "[Discovery] Replacing the disk-stored snapshot with all the fresh programs: %s",
        current_snapshot_file,
    )
    # Replaces the disk-stored snapshot file with all the fetched handle (even with no change)
    # file size is tiny so cost is negligible 
    current_snapshot_file.write_text(
        json.dumps(current_program_handles, indent=2),
        encoding="utf-8",
    )

    return {
        "platform": "hackerone",
        "total": len(current_program_handles),
        "old_total": len(stored_program_handles),
        "added": added,
        "removed": removed,
        "HACKERONE_TARGETS_FILE": str(HACKERONE_TARGETS_FILE),
        "snapshot_file": str(current_snapshot_file),
        "previous_snapshot_file": str(previous_snapshot_file),
    }


def discover_hackerone_bounty_programs() -> dict:
    HACKERONE_DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)

    current_program_handles = fetch_all_bounty_programs()
    write_hackerone_targets_file(current_program_handles) # Rewrite hackerone_targets.txt with all currently fetched programs everytime
    return compare_program_snapshots(current_program_handles)