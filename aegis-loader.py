"""Aegis auto-loader for Hermes integration.

Install this file to auto-load Aegis when TERMINAL_ENV=aegis is set.

Installation:
    python3 aegis-loader.py install
    
This creates a sitecustomize.py that loads Aegis on Python startup.
"""
import os
import sys
import site
from pathlib import Path


def install():
    """Install Aegis auto-loader to site-packages."""
    # Find user site-packages
    user_site = site.getusersitepackages()
    os.makedirs(user_site, exist_ok=True)
    
    sitecustomize_path = Path(user_site) / "sitecustomize.py"
    
    loader_code = '''# Hermes-Aegis Auto-Loader
# Automatically loads Aegis integration when TERMINAL_ENV=aegis

import os

if os.getenv('TERMINAL_ENV') == 'aegis':
    try:
        import hermes_aegis.integration
        hermes_aegis.integration.register_aegis_backend()
    except ImportError:
        pass  # Aegis not installed or not on path
'''
    
    if sitecustomize_path.exists():
        # Append to existing
        existing = sitecustomize_path.read_text()
        if 'Hermes-Aegis Auto-Loader' not in existing:
            with open(sitecustomize_path, 'a') as f:
                f.write('\n\n')
                f.write(loader_code)
            print(f"✓ Appended Aegis loader to {sitecustomize_path}")
        else:
            print(f"✓ Aegis loader already in {sitecustomize_path}")
    else:
        # Create new
        sitecustomize_path.write_text(loader_code)
        print(f"✓ Created {sitecustomize_path}")
    
    print(f"\nAegis will now auto-load when TERMINAL_ENV=aegis is set!")
    print(f"Test: Start a new terminal and run 'hermes'")


def uninstall():
    """Remove Aegis auto-loader from site-packages."""
    user_site = site.getusersitepackages()
    sitecustomize_path = Path(user_site) / "sitecustomize.py"
    
    if not sitecustomize_path.exists():
        print("No sitecustomize.py found")
        return
    
    content = sitecustomize_path.read_text()
    if 'Hermes-Aegis Auto-Loader' not in content:
        print("Aegis loader not found in sitecustomize.py")
        return
    
    # Remove the Aegis section
    lines = content.split('\n')
    new_lines = []
    skip = False
    for line in lines:
        if 'Hermes-Aegis Auto-Loader' in line:
            skip = True
        elif skip and line.strip() and not line.strip().startswith('#') and 'aegis' not in line.lower():
            skip = False
        if not skip:
            new_lines.append(line)
    
    sitecustomize_path.write_text('\n'.join(new_lines))
    print(f"✓ Removed Aegis loader from {sitecustomize_path}")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'uninstall':
        uninstall()
    else:
        install()
