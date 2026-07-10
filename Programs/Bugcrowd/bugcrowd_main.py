#!/usr/bin/env python3
import json, re, sys, hashlib
from pathlib import Path
from urllib.parse import urljoin
import requests

BASE = "https://bugcrowd.com"
HEADERS = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*"}
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

def fetch(url):
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.text

def get_changelog_url(slug):
    html = fetch(f"{BASE}/engagements/{slug}")
    m = re.search(rf"/engagements/{re.escape(slug)}/changelog/[a-f0-9-]+", html)
    if not m:
        raise RuntimeError("Could not find changelog URL")
    url = urljoin(BASE, m.group(0))
    return url if url.endswith(".json") else url + ".json"

def download_json(url):
    r = requests.get(url, headers=HEADERS, timeout=30)
    print(f"[+] HTTP {r.status_code}")
    print(f"[+] Content-Type: {r.headers.get('Content-Type')}")
    r.raise_for_status()
    return r.json()

def find_scope(doc):
    # Try known paths first
    paths = [
        ("data", "brief", "scope"),
        ("data", "scope"),
        ("brief", "scope"),
        ("scope",),
    ]

    for path in paths:
        cur = doc
        ok = True
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                ok = False
                break
        if ok and isinstance(cur, list):
            return cur, ".".join(path)

    # Recursive fallback: find first list under key named "scope"
    def walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_path = f"{path}.{k}" if path else k
                if k == "scope" and isinstance(v, list):
                    return v, new_path
                found = walk(v, new_path)
                if found:
                    return found
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                found = walk(item, f"{path}[{i}]")
                if found:
                    return found
        return None

    result = walk(doc)
    if result:
        return result

    return [], "NOT_FOUND"

def normalize_scope(doc):
    brief = doc.get("data", {}).get("brief", doc.get("brief", {}))
    scope, scope_path = find_scope(doc)

    print(f"[+] Scope path: {scope_path}")
    print(f"[+] Scope groups found: {len(scope)}")

    normalized = {
        "program": brief.get("name"),
        "safe_harbor": brief.get("safeHarborStatus"),
        "scope": [],
    }

    for group in scope:
        entry = {
            "group": group.get("name"),
            "in_scope": group.get("inScope"),
            "description": group.get("description"),
            "reward_range": group.get("rewardRange"),
            "targets": [],
        }

        for target in group.get("targets", []) or []:
            entry["targets"].append({
                "name": target.get("name"),
                "uri": target.get("uri"),
                "category": target.get("category"),
                "ip": target.get("ipAddress"),
                "tags": [t.get("name") for t in (target.get("tags") or [])],
            })

        normalized["scope"].append(entry)

    return normalized

def stable_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

def main():
    if len(sys.argv) != 2:
        print("Usage: python .\\bugcrowdtest.py <program_slug>")
        print("Example: python .\\bugcrowdtest.py nubank")
        sys.exit(1)

    slug = sys.argv[1]

    print("[+] Fetching engagement page...")
    changelog = get_changelog_url(slug)
    print(f"[+] Changelog endpoint: {changelog}")

    doc = download_json(changelog)

    # Helpful debug output
    print("[+] Top-level keys:", list(doc.keys()))
    if "data" in doc and isinstance(doc["data"], dict):
        print("[+] data keys:", list(doc["data"].keys()))
    if "data" in doc and isinstance(doc["data"], dict) and "brief" in doc["data"]:
        print("[+] brief keys:", list(doc["data"]["brief"].keys()))

    current = normalize_scope(doc)

    current_file = DATA_DIR / f"{slug}.current.json"
    previous_file = DATA_DIR / f"{slug}.previous.json"

    if current_file.exists():
        previous_file.write_text(current_file.read_text(encoding="utf-8"), encoding="utf-8")

    current_file.write_text(json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")

    if not previous_file.exists():
        print("[+] Baseline created.")
        return

    previous = json.loads(previous_file.read_text(encoding="utf-8"))

    if stable_hash(previous) == stable_hash(current):
        print("[+] No changes detected.")
    else:
        print("[!] Scope changed!")
        print(f"Previous: {previous_file}")
        print(f"Current:  {current_file}")

if __name__ == "__main__":
    main()