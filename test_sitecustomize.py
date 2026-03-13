import os
import sys

print(f"TERMINAL_ENV in new Python: {os.getenv('TERMINAL_ENV')}")
print(f"Python version: {sys.version}")
print(f"sys.path includes:")
for p in sys.path[:5]:
    print(f"  {p}")

# Check if aegis was loaded
print("\nChecking if Aegis loaded:")
if 'hermes_aegis' in sys.modules:
    print("  ✓ hermes_aegis is in sys.modules")
    import hermes_aegis.integration
    print(f"  _PATCHED: {hermes_aegis.integration._PATCHED}")
else:
    print("  ✗ hermes_aegis NOT in sys.modules")
    
# Try manual import
print("\nManual import test:")
try:
    import hermes_aegis.integration
    result = hermes_aegis.integration.register_aegis_backend()
    print(f"  register_aegis_backend(): {result}")
    print(f"  _PATCHED: {hermes_aegis.integration._PATCHED}")
except Exception as e:
    print(f"  ERROR: {e}")
    import traceback
    traceback.print_exc()
