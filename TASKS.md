## Phase -- Auto-Update Integration

- [ ] Add 'update' CLI command to hermes-aegis that runs: git pull + pip install -e . in the aegis directory
- [ ] Fix Patch 12 error message (says 'hermes-aegis update' but command doesn't exist yet)
- [ ] Ensure 'hermes-aegis install' activates the post-update hook (Patch 12) in hermes_cli/main.py
- [ ] Test full flow: hermes update -> aegis patches auto-reapplied -> verify aegis still functional
- [ ] Add version check: hermes-aegis --version shows current git SHA + package version
