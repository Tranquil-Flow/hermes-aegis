## Phase — Auto-Update Integration

- [x] Add 'update' CLI command to hermes-aegis that runs: git pull + pip install -e . + re-apply patches
- [x] Add version check: hermes-aegis --version shows version + git SHA + clean/dirty status
- [ ] Fix Patch 12 error message (says 'hermes-aegis update' — now correct since command exists, but verify on host)
- [ ] Ensure 'hermes-aegis install' activates the post-update hook (Patch 12) in hermes_cli/main.py — test on host Mac
- [ ] Test full flow on host: hermes update → aegis patches auto-reapplied → verify aegis still functional
