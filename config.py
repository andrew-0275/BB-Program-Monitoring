import os
from pathlib import Path

from dotenv import load_dotenv


# Directory containing config.py and main.py.
BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

# Logs
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "hackerone_scope_watcher.log"

# Data
DATA_DIR = BASE_DIR / "data"

# Program directories
PROGRAMS_DIR = BASE_DIR / "Programs"

# Hackerone
HACKERONE_PROGRAM_DIR = PROGRAMS_DIR / "Hackerone"
HACKERONE_TARGETS_FILE = HACKERONE_PROGRAM_DIR / "hackerone_targets.txt"
# HackerOne stored data
HACKERONE_DATA_DIR = DATA_DIR / "hackerone"
HACKERONE_SCOPE_DIR = HACKERONE_DATA_DIR / "scopes"
HACKERONE_DISCOVERY_DIR = HACKERONE_DATA_DIR / "discovery"
# HackerOne API
HACKERONE_GRAPHQL_BASE_URL = "https://hackerone.com/graphql"
HACKERONE_DISCOVERY_QUERY_FILE = (
    HACKERONE_PROGRAM_DIR / "hackerone_discovery_query.graphql"
)
# Hackerone activity
HACKERONE_HACKTIVITY_DIR = Path("data/hackerone/hacktivity")

DISCORD_HACKTIVITY_WEBHOOK_URL = os.getenv(
    "DISCORD_HACKTIVITY",
    "",
)
# BugCrowd


# Discord
DISCORD_CHANGE_WEBHOOK_URL = os.getenv("DISCORD_CHANGE_WEBHOOK_URL")
DISCORD_LOG_WEBHOOK_URL = os.getenv("DISCORD_LOG_WEBHOOK_URL")
DISCORD_BB_REPORTS_URL = os.getenv("DISCORD_BB_REPORTS_URL")
DISCORD_TIMEOUT = 15



