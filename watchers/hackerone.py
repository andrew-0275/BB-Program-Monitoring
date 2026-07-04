import re
from pathlib import Path
from urllib.parse import urlparse

from config import TARGETS_FILE


def extract_handle(line: str) -> str | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    parsed = urlparse(line)

    if parsed.netloc and "hackerone.com" not in parsed.netloc:
        raise ValueError(f"Not a HackerOne URL: {line}")

    if parsed.netloc:
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            raise ValueError(f"No HackerOne handle found in URL: {line}")
        return parts[0]

    if re.match(r"^[A-Za-z0-9_-]+$", line):
        return line

    raise ValueError(f"Could not parse target line: {line}")


def load_targets() -> list[str]:
    if not TARGETS_FILE.exists():
        raise FileNotFoundError(f"Missing input file: {TARGETS_FILE}")

    handles = []
    seen = set()

    for line_number, line in enumerate(TARGETS_FILE.read_text(encoding="utf-8").splitlines(), 1):
        try:
            handle = extract_handle(line)
        except ValueError as exc:
            print(f"[ERROR] Line {line_number} skipped: {exc}")
            continue

        if handle and handle not in seen:
            handles.append(handle)
            seen.add(handle)

    return handles