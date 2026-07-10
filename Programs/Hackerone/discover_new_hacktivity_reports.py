#!/usr/bin/env python3

import json
import logging
from pathlib import Path

import requests

from config import (
    HACKERONE_GRAPHQL_BASE_URL,
    HACKERONE_HACKTIVITY_DIR,
)

REQUEST_TIMEOUT = 30
PAGE_SIZE = 50
START_OFFSET = 0

# Keep enough historical report IDs to prevent an older report from being
# alerted again if it later returns to the first page of Hacktivity.
MAX_SEEN_REPORT_IDS = 1000

SEEN_REPORT_IDS_FILE = (
    HACKERONE_HACKTIVITY_DIR / "seen_report_ids.json"
)

HACKTIVITY_URL = (
    "https://hackerone.com/hacktivity/overview"
    "?queryString=asset_type%3A%28%22Domain%22%20OR%20%22API%22"
    "%20OR%20%22CIDR%22%20OR%20%22Wildcard%22"
    "%20OR%20%22IP%20Address%22%20OR%20%22Other%20Asset%22"
    "%20OR%20%22AI%20Model%22%20OR%20%22AWS%20Account%22"
    "%20OR%20%22Azure%20Account%22%29%20AND%20disclosed%3Atrue"
    "&sortField=latest_disclosable_activity_at"
    "&sortDirection=DESC"
    "&pageIndex=0"
)

# Search for these asset types only
HACKTIVITY_QUERY_STRING = (
    'asset_type:('
    '"Domain" OR '
    '"API" OR '
    '"CIDR" OR '
    '"Wildcard" OR '
    '"IP Address" OR '
    '"Other Asset" OR '
    '"AI Model" OR '
    '"AWS Account" OR '
    '"Azure Account"'
    ') AND disclosed:true'
)


HACKTIVITY_QUERY = """
query HacktivitySearchQuery(
  $queryString: String!,
  $from: Int,
  $size: Int,
  $sort: SortInput!
) {
  me {
    id
    __typename
  }

  search(
    index: CompleteHacktivityReportIndex
    query_string: $queryString
    from: $from
    size: $size
    sort: $sort
  ) {
    __typename
    total_count

    nodes {
      __typename

      ... on HacktivityDocument {
        id
        _id

        reporter {
          id
          username
          name
          __typename
        }

        cve_ids
        cwe
        severity_rating
        public

        report {
          id
          databaseId: _id
          title
          substate
          url
          disclosed_at

          report_generated_content {
            id
            hacktivity_summary
            __typename
          }

          __typename
        }

        votes

        team {
          id
          handle
          name
          url
          currency
          __typename
        }

        total_awarded_amount
        latest_disclosable_action
        latest_disclosable_activity_at
        submitted_at
        disclosed
        has_collaboration

        collaborators {
          id
          username
          name
          __typename
        }

        __typename
      }
    }
  }
}
"""


class HackerOneHacktivityError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_text: str | None = None,
    ):
        self.hacktivity_url = HACKTIVITY_URL
        self.hackerone_graphql_base_url = HACKERONE_GRAPHQL_BASE_URL
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(message)


def fetch_hacktivity_page(
    offset: int = START_OFFSET,
    size: int = PAGE_SIZE,
) -> dict:
    payload = {
        "operationName": "HacktivitySearchQuery",
        "variables": {
            "queryString": HACKTIVITY_QUERY_STRING,
            "size": size,
            "from": offset,
            "sort": {
                "field": "latest_disclosable_activity_at",
                "direction": "DESC",
            },
            "product_area": "hacktivity",
            "product_feature": "overview",
        },
        "query": HACKTIVITY_QUERY,
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://hackerone.com",
        "Referer": HACKTIVITY_URL,
        "User-Agent": "Mozilla/5.0",
        "x-product-area": "hacktivity",
        "x-product-feature": "overview",
    }

    try:
        response = requests.post(
            HACKERONE_GRAPHQL_BASE_URL,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

    except requests.RequestException as exc:
        status_code = (
            exc.response.status_code
            if exc.response is not None
            else None
        )
        response_text = (
            exc.response.text
            if exc.response is not None
            else None
        )

        raise HackerOneHacktivityError(
            message=f"HackerOne Hacktivity request failed: {exc}",
            status_code=status_code,
            response_text=response_text,
        ) from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise HackerOneHacktivityError(
            message=f"HackerOne returned non-JSON data: {exc}",
            status_code=response.status_code,
            response_text=response.text,
        ) from exc

    if data.get("errors"):
        raise HackerOneHacktivityError(
            message="HackerOne Hacktivity GraphQL returned errors.",
            status_code=response.status_code,
            response_text=json.dumps(data["errors"], indent=2),
        )

    search = data.get("data", {}).get("search")

    if not search:
        raise HackerOneHacktivityError(
            message="No HackerOne Hacktivity search data returned.",
            status_code=response.status_code,
            response_text=json.dumps(data, indent=2),
        )

    return data


def normalize_hacktivity_response(response_data: dict) -> dict:
    search = response_data["data"]["search"]
    normalized_reports = []

    for node in search.get("nodes", []):
        if node.get("__typename") != "HacktivityDocument":
            continue

        report = node.get("report") or {}
        team = node.get("team") or {}
        reporter = node.get("reporter") or {}
        generated_content = (
            report.get("report_generated_content") or {}
        )

        report_id = (
            report.get("databaseId")
            or node.get("_id")
            or ""
        )

        if not report_id:
            logging.warning(
                "Skipping Hacktivity result without a report ID."
            )
            continue

        report_id = str(report_id)

        normalized_reports.append(
            {
                "report_id": report_id,
                "title": report.get("title") or "Untitled report",
                "report_url": (
                    report.get("url")
                    or f"https://hackerone.com/reports/{report_id}"
                ),
                "report_state": report.get("substate") or "",
                "program_handle": team.get("handle") or "",
                "program_name": team.get("name") or "",
                "program_url": team.get("url") or "",
                "program_currency": team.get("currency") or "",
                "reporter": reporter.get("username") or "",
                "reporter_name": reporter.get("name") or "",
                "severity_rating": node.get("severity_rating") or "",
                "cwe": node.get("cwe") or "",
                "cve_ids": node.get("cve_ids") or [],
                "votes": node.get("votes"),
                "total_awarded_amount": node.get(
                    "total_awarded_amount"
                ),
                "submitted_at": node.get("submitted_at") or "",
                "disclosed_at": report.get("disclosed_at") or "",
                "latest_disclosable_activity_at": node.get(
                    "latest_disclosable_activity_at"
                ) or "",
                "latest_disclosable_action": node.get(
                    "latest_disclosable_action"
                ) or "",
                "public": bool(node.get("public")),
                "disclosed": bool(node.get("disclosed")),
                "has_collaboration": bool(
                    node.get("has_collaboration")
                ),
                "hacktivity_summary": generated_content.get(
                    "hacktivity_summary"
                ) or "",
            }
        )

    return {
        "platform": "hackerone",
        "source_url": HACKTIVITY_URL,
        "query_string": HACKTIVITY_QUERY_STRING,
        "total_count": search.get("total_count"),
        "rows_returned": len(normalized_reports),
        "reports": normalized_reports,
    }


def load_seen_report_ids(path: Path = SEEN_REPORT_IDS_FILE) -> list[str]:
    if not path.exists():
        return []

    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, list):
        raise ValueError(
            f"Expected a JSON list in {path}, got {type(data).__name__}"
        )

    return [str(report_id) for report_id in data]


def save_seen_report_ids(
    report_ids: list[str],
    path: Path = SEEN_REPORT_IDS_FILE,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temporary file first, then replace the real file.
    # This reduces the chance of leaving malformed JSON if interrupted.
    temporary_file = path.with_suffix(".tmp")

    temporary_file.write_text(
        json.dumps(report_ids, indent=2),
        encoding="utf-8",
    )

    temporary_file.replace(path)


def merge_seen_report_ids(
    current_report_ids: list[str],
    previously_seen_ids: list[str],
) -> list[str]:
    merged = []
    already_added = set()

    # Put current reports first because they are newest.
    for report_id in current_report_ids + previously_seen_ids:
        if report_id and report_id not in already_added:
            merged.append(report_id)
            already_added.add(report_id)

    return merged[:MAX_SEEN_REPORT_IDS]


def discover_new_hacktivity_reports() -> dict:
    HACKERONE_HACKTIVITY_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    response_data = fetch_hacktivity_page()
    current_snapshot = normalize_hacktivity_response(response_data)

    reports = current_snapshot["reports"]
    current_report_ids = [
        report["report_id"]
        for report in reports
    ]

    # First run: establish a baseline without sending 50 old reports.
    if not SEEN_REPORT_IDS_FILE.exists():
        logging.info(
            "[Hacktivity] No seen-report baseline exists."
        )
        logging.info(
            "[Hacktivity] Saving initial baseline with %s report IDs.",
            len(current_report_ids),
        )

        save_seen_report_ids(current_report_ids)

        return {
            **current_snapshot,
            "baseline_created": True,
            "new_reports": [],
            "new_report_count": 0,
            "seen_ids_file": str(SEEN_REPORT_IDS_FILE),
        }

    previously_seen_ids = load_seen_report_ids()
    previously_seen_set = set(previously_seen_ids)

    new_reports = [
        report
        for report in reports
        if report["report_id"] not in previously_seen_set
    ]

    updated_seen_ids = merge_seen_report_ids(
        current_report_ids,
        previously_seen_ids,
    )
    save_seen_report_ids(updated_seen_ids)

    logging.info(
        "[Hacktivity] Rows=%s New=%s Stored IDs=%s",
        len(reports),
        len(new_reports),
        len(updated_seen_ids),
    )

    return {
        **current_snapshot,
        "baseline_created": False,
        "new_reports": new_reports,
        "new_report_count": len(new_reports),
        "seen_ids_file": str(SEEN_REPORT_IDS_FILE),
    }