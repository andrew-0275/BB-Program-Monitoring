# Bug Bounty Program Watcher

Project developed in Python that monitors and alerts for new bug bounty programs and scope changes.

## Currently Supported

- HackerOne

## Features

- Automatically discovers public bounty programs
- Detects newly added and removed programs
- Monitors scope changes for tracked programs
- Compares current and previous JSON snapshots
- Sends Discord notifications for detected changes

## Workflow

### Phase 1 — Program Discovery

```
HackerOne Discovery GraphQL
        ↓
Retrieve public bounty programs
        ↓
Compare previous snapshot
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
Normalize response
        ↓
Compare previous snapshot
        ↓
Detect scope changes
        ↓
Send Discord alert
        ↓
Save new snapshot
```