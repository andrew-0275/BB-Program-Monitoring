# HackerOne Scope Watcher

Purpose:
Monitor public HackerOne scope changes.

Workflow:

hackerone_targets.txt
    ↓
Extract handle
    ↓
GraphQL
    ↓
Normalize
    ↓
Compare previous snapshot
    ↓
Print changes
    ↓
Save snapshot
