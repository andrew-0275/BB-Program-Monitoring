# Bug Bounty Program Watcher

Project developed in Python that monitors and alerts for new bug bounty programs and scope changes.

## Currently Supported

- HackerOne

## Features

- Automatically discovers public bounty programs dynamically
- Detects newly added and removed programs
- Monitors scope changes for tracked programs
- Sends Discord notifications for detected changes

## Workflow

### Phase 1 — Program Discovery

```
HackerOne Discovery GraphQL
        ↓
Retrieve public bounty programs
        ↓
Compare to previous snapshot
        ↓
Detect new / removed programs
        ↓
Update hackerone_targets.txt
```

### Phase 2 — Scope Monitoring

```
hackerone_targets.txt
        ↓
Fetch scopes via GraphQL
        ↓
Compare previous snapshot
        ↓
Detect scope changes
        ↓
Send Discord alert
        ↓
Save new snapshot
```

## Usage

Run the project normally:

```bash
python main.py
```

Run the project without sending Discord webhook notifications:

```bash
python main.py --no-alerts
```

`--no-alerts` disables all Discord notifications while still performing program discovery, scope monitoring, comparisons, and snapshot updates. Useful for local development and testing.