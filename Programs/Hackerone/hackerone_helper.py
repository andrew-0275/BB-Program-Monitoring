import re
from urllib.parse import urlparse

from config import HACKERONE_TARGETS_FILE

# Extract direct program handle from URL 
def extract_program_handles(line: str) -> str | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    parsed = urlparse(line)

    if parsed.netloc and "hackerone.com" not in parsed.netloc:
        raise ValueError(f"Not a HackerOne URL: {line}")

    if parsed.netloc:
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            raise ValueError(f"No HackerOne program_handles found in URL: {line}")
        return parts[0]

    if re.match(r"^[A-Za-z0-9_-]+$", line):
        return line

    raise ValueError(f"Could not parse target line: {line}")


# Prepare HACKERONE_TARGETS_FILE for phase 2 in main.py 
def load_hackerone_targets() -> list[str]:
    if not HACKERONE_TARGETS_FILE.exists():
        raise FileNotFoundError(f"Missing input file: {HACKERONE_TARGETS_FILE}")

    program_handles = []
    seen = set()

    for line_number, line in enumerate(HACKERONE_TARGETS_FILE.read_text(encoding="utf-8").splitlines(), 1):
        try:
            extracted_program_handle = extract_program_handles(line) # Extract direct program handle from URL 
        except ValueError as exc:
            print(f"[ERROR] Line {line_number} skipped: {exc}")
            continue
        
        # Check that extract_program_handles() returned a real value and not None.
        # whereas a blank line or comment might return None are skipped
        # Also prevents duplicates due to set
        if extracted_program_handle and extracted_program_handle not in seen:
            # if it passed both checks then add it to program_handles []
            program_handles.append(extracted_program_handle)
            # Recording that it has been processed
            seen.add(extracted_program_handle)

    return program_handles