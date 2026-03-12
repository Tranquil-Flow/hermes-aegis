"""Display utilities for showing Aegis status in Hermes."""
from __future__ import annotations

import os
import sys


def check_aegis_active() -> bool:
    """Check if Aegis is currently active."""
    return os.getenv("TERMINAL_ENV") == "aegis"


def get_aegis_tier() -> int:
    """Get current Aegis tier (1 or 2)."""
    try:
        from hermes_aegis.detect import detect_tier
        return detect_tier()
    except Exception:
        return 1


def print_aegis_status():
    """Print Aegis activation status with color."""
    if not check_aegis_active():
        return
    
    tier = get_aegis_tier()
    
    # ANSI color codes
    BOLD = "\033[1m"
    CYAN = "\033[96m"  # Pale blue/cyan
    RESET = "\033[0m"
    
    # Print status
    print(f"{BOLD}{CYAN}🛡️  Aegis Activated{RESET} (Tier {tier})")
    

def inject_aegis_status_hook():
    """Inject Aegis status display into Hermes session info.
    
    This monkey-patches the HermesAgent.show_session_info method
    to display Aegis status after the toolsets line.
    """
    if not check_aegis_active():
        return False
        
    try:
        # Find Hermes Agent class
        hermes_path = os.path.join(os.path.expanduser("~"), ".hermes", "hermes-agent")
        if hermes_path not in sys.path:
            sys.path.insert(0, hermes_path)
        
        # Import and patch
        import cli
        if not hasattr(cli, 'HermesAgent'):
            return False
            
        HermesAgent = cli.HermesAgent
        original_show_info = HermesAgent.show_session_info
        
        def patched_show_info(self):
            """Show session info with Aegis status."""
            # Call original
            original_show_info(self)
            
            # Add Aegis status before the separator
            tier = get_aegis_tier()
            BOLD = "\033[1m"
            CYAN = "\033[96m"
            RESET = "\033[0m"
            print(f"  {BOLD}{CYAN}Security:   Aegis Tier {tier} Active 🛡️{RESET}")
            print()
        
        # Replace method
        HermesAgent.show_session_info = patched_show_info
        return True
        
    except Exception as e:
        # Fail silently - don't break Hermes if patching fails
        return False


# Auto-inject on import if Aegis is active
if check_aegis_active():
    inject_aegis_status_hook()
