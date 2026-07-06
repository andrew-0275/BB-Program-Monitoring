import json
import logging
import random
import time
from pathlib import Path
import shutil

import requests
from config import (
    GRAPHQL_URL,
    HACKERONE_DISCOVERY_DIR,
    TARGETS_FILE,
)

QUERY_FILE = Path("graphql/discovery_query.graphql")

DISCOVERY_DIR = Path("data/hackerone/discovery")
OUT_FILE = Path("hackerone_targets.txt")
SNAPSHOT_FILE = DISCOVERY_DIR / "hackerone_programs_snapshot.json"

PAGE_SIZE = 100
SLEEP_RANGE = (1, 2)


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
                            "must_not": {
                                "term": {
                                    "team_type": "Engagements::Assessment"
                                }
                            },
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
        "sort": [{"field": "launched_at", "direction": "DESC"}],
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
        "variables": build_variables(offset),
    }

    response = session.post(GRAPHQL_URL, json=payload, timeout=30)

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


def refresh_hackerone_program_targets() -> dict:
    HACKERONE_DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)

    current_snapshot_file = HACKERONE_DISCOVERY_DIR / "hackerone_programs_snapshot.json"
    previous_snapshot_file = HACKERONE_DISCOVERY_DIR / "hackerone_programs_previous_version.json"

    query = QUERY_FILE.read_text(encoding="utf-8")

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

    handles = []
    total = None
    offset = 0

    while total is None or offset < total:
        logging.info("Discovery: fetching HackerOne programs offset=%s", offset)

        data = fetch_page(session, query, offset)
        search = data["data"]["opportunities_search"]
        total = search["total_count"]

        for node in search.get("nodes", []):
            handle = node.get("handle")
            if handle and handle not in handles:
                handles.append(handle)

        offset += PAGE_SIZE
        time.sleep(random.uniform(*SLEEP_RANGE))

    urls = [f"https://hackerone.com/{handle}/policy_scopes" for handle in handles]
    TARGETS_FILE.write_text("\n".join(urls) + "\n", encoding="utf-8")

    if not current_snapshot_file.exists():
        logging.info("[Discovery] No previous current JSON exists.")
        logging.info("[Discovery] Saving first snapshot to: %s", current_snapshot_file)

        current_snapshot_file.write_text(
            json.dumps(handles, indent=2),
            encoding="utf-8",
        )

        return {
            "platform": "hackerone",
            "total": len(handles),
            "old_total": 0,
            "added": handles,
            "removed": [],
            "targets_file": str(TARGETS_FILE),
            "snapshot_file": str(current_snapshot_file),
            "previous_snapshot_file": str(previous_snapshot_file),
        }

    logging.info("[Discovery] Existing JSON found. Beginning comparison.")

    old_handles = json.loads(current_snapshot_file.read_text(encoding="utf-8"))

    added = sorted(set(handles) - set(old_handles))
    removed = sorted(set(old_handles) - set(handles))

    logging.info(
        "[Discovery] Renaming old current JSON to previous version: %s",
        previous_snapshot_file,
    )
    shutil.copy2(current_snapshot_file, previous_snapshot_file)

    logging.info("[Discovery] Saving new current JSON: %s", current_snapshot_file)
    current_snapshot_file.write_text(
        json.dumps(handles, indent=2),
        encoding="utf-8",
    )

    return {
        "platform": "hackerone",
        "total": len(handles),
        "old_total": len(old_handles),
        "added": added,
        "removed": removed,
        "targets_file": str(TARGETS_FILE),
        "snapshot_file": str(current_snapshot_file),
        "previous_snapshot_file": str(previous_snapshot_file),
    }