#!/usr/bin/env python3
"""Check what happens when hermes CLI loads."""

import sys
import os

print("=== Python Environment Check ===")
print(f"Python executable: {sys.executable}")
print(f"Python version: {sys.version}")
print(f"TERMINAL_ENV: {os.getenv('TERMINAL_ENV')}")

print("\n=== User Site Packages ===")
import site
user_site = site.getusersitepackages()
print(f"User site-packages: {user_site}")
print(f"Enabled: {site.ENABLE_USER_SITE}")

sitecustomize_path = os.path.join(user_site, 'sitecustomize.py')
print(f"sitecustomize.py exists: {os.path.exists(sitecustomize_path)}")

print("\n=== Module Loading Check ===")
if 'hermes_aegis' in sys.modules:
    print("✓ hermes_aegis WAS loaded by sitecustomize")
    import hermes_aegis.integration
    print(f"  _PATCHED: {hermes_aegis.integration._PATCHED}")
else:
    print("✗ hermes_aegis NOT loaded by sitecustomize")

print("\n=== sys.path ===")
for i, p in enumerate(sys.path[:10]):
    print(f"  [{i}] {p}")
