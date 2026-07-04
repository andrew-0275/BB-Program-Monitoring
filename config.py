import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()

TARGETS_FILE = Path("hackerone_targets.txt")

DATA_DIR = Path("data") / "hackerone"
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "hackerone_scope_watcher.log"

GRAPHQL_URL = "https://hackerone.com/graphql"

DISCORD_CHANGE_WEBHOOK_URL = os.getenv("DISCORD_CHANGE_WEBHOOK_URL")
DISCORD_LOG_WEBHOOK_URL = os.getenv("DISCORD_LOG_WEBHOOK_URL")

REQUEST_TIMEOUT = 30
DISCORD_TIMEOUT = 15

MIN_DELAY_SECONDS = 3
MAX_DELAY_SECONDS = 8