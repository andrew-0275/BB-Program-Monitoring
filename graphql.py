import json
from datetime import datetime, timezone

import requests

from config import GRAPHQL_URL, REQUEST_TIMEOUT

class HackerOneGraphQLError(RuntimeError):
    def __init__(
        self,
        handle: str,
        message: str,
        status_code: int | None = None,
        response_text: str | None = None,
    ):
        self.handle = handle
        self.policy_url = f"https://hackerone.com/{handle}/policy_scopes"
        self.graphql_url = GRAPHQL_URL
        self.status_code = status_code
        self.response_text = response_text
        super().__init__(message)


GRAPHQL_SCOPE_QUERY = """
query PolicySearchStructuredScopesQuery(
  $handle: String!,
  $searchString: String,
  $eligibleForSubmission: Boolean,
  $eligibleForBounty: Boolean,
  $minSeverityScore: SeverityRatingEnum,
  $asmTagIds: [Int],
  $assetTypes: [StructuredScopeAssetTypeEnum!],
  $from: Int,
  $size: Int,
  $sort: SortInput
) {
  team(handle: $handle) {
    id
    handle
    structured_scopes_search(
      search_string: $searchString
      eligible_for_submission: $eligibleForSubmission
      eligible_for_bounty: $eligibleForBounty
      min_severity_score: $minSeverityScore
      asm_tag_ids: $asmTagIds
      asset_types: $assetTypes
      from: $from
      size: $size
      sort: $sort
    ) {
      total_count
      nodes {
        __typename
        ... on StructuredScopeDocument {
          id
          identifier
          display_name
          instruction
          cvss_score
          eligible_for_bounty
          eligible_for_submission
          created_at
          updated_at
          total_resolved_reports
        }
      }
    }
  }
}
"""


def fetch_scopes(handle: str) -> dict:
    payload = {
        "operationName": "PolicySearchStructuredScopesQuery",
        "variables": {
            "handle": handle,
            "searchString": "",
            "eligibleForSubmission": None,
            "eligibleForBounty": None,
            "minSeverityScore": None,
            "asmTagIds": [],
            "assetTypes": [],
            "from": 0,
            "size": 100,
            "sort": {
                "field": "cvss_score",
                "direction": "DESC",
            },
        },
        "query": GRAPHQL_SCOPE_QUERY,
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://hackerone.com",
        "Referer": f"https://hackerone.com/{handle}/policy_scopes?type=team",
        "x-product-area": "h1_assets",
        "x-product-feature": "policy_scopes",
    }

    try:
        response = requests.post(
            GRAPHQL_URL,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

    except requests.RequestException as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        response_text = exc.response.text if exc.response is not None else None

        raise HackerOneGraphQLError(
            handle=handle,
            message=f"HackerOne GraphQL request failed: {exc}",
            status_code=status_code,
            response_text=response_text,
        ) from exc

    try:
        data = response.json()

    except ValueError as exc:
        raise HackerOneGraphQLError(
            handle=handle,
            message=f"HackerOne GraphQL returned non-JSON response: {exc}",
            status_code=response.status_code,
            response_text=response.text,
        ) from exc

    if data.get("errors"):
        raise HackerOneGraphQLError(
            handle=handle,
            message="HackerOne GraphQL returned errors.",
            status_code=response.status_code,
            response_text=json.dumps(data["errors"], indent=2),
        )

    team = data.get("data", {}).get("team")
    if not team:
        raise HackerOneGraphQLError(
            handle=handle,
            message=f"No team returned for handle: {handle}",
            status_code=response.status_code,
            response_text=json.dumps(data, indent=2),
        )

    search = team.get("structured_scopes_search")
    if not search:
        raise HackerOneGraphQLError(
            handle=handle,
            message=f"No structured scope data returned for handle: {handle}",
            status_code=response.status_code,
            response_text=json.dumps(data, indent=2),
        )

    return data


def normalize_response(handle: str, response_data: dict) -> dict:
    search = response_data["data"]["team"]["structured_scopes_search"]
    nodes = search.get("nodes", [])

    normalized_scopes = []

    for node in nodes:
        if node.get("__typename") != "StructuredScopeDocument":
            continue

        normalized_scopes.append(
            {
                "identifier": node.get("identifier") or "",
                "display_name": node.get("display_name") or "",
                "eligible_for_bounty": bool(node.get("eligible_for_bounty")),
                "eligible_for_submission": bool(node.get("eligible_for_submission")),
                "cvss_score": node.get("cvss_score") or "",
                "instruction": node.get("instruction") or "",
                "created_at": node.get("created_at") or "",
                "updated_at": node.get("updated_at") or "",
                "total_resolved_reports": node.get("total_resolved_reports"),
            }
        )

    normalized_scopes.sort(key=lambda item: item["identifier"].lower())

    return {
        "platform": "hackerone",
        "handle": handle,
        "source_url": f"https://hackerone.com/{handle}/policy_scopes",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_count": search.get("total_count"),
        "scopes": normalized_scopes,
    }