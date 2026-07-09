import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "hackerone_scope_watcher.log"

DATA_DIR = Path("data")

# Hackerone
HACKERONE_TARGETS_FILE = Path("hackerone_targets.txt")
HACKERONE_DATA_DIR = DATA_DIR / "hackerone"
HACKERONE_SCOPE_DIR = HACKERONE_DATA_DIR / "scopes"
HACKERONE_DISCOVERY_DIR = HACKERONE_DATA_DIR / "discovery"
HACKERONE_GRAPHQL_BASE_URL = "https://hackerone.com/graphql"
HACKERONE_DISCOVERY_QUERY_FILE = Path("graphql/discovery_query.graphql")

# BugCrowd

# Discord
DISCORD_CHANGE_WEBHOOK_URL = os.getenv("DISCORD_CHANGE_WEBHOOK_URL")
DISCORD_LOG_WEBHOOK_URL = os.getenv("DISCORD_LOG_WEBHOOK_URL")
DISCORD_BB_REPORTS_URL = os.getenv("DISCORD_BB_REPORTS_URL")
DISCORD_TIMEOUT = 15



