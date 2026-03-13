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
    """Inject Aegis status display after the welcome banner.
    
    Much simpler approach: patch the function that CALLS build_welcome_banner
    and add a line right after it.
    """
    if not check_aegis_active():
        return False
        
    try:
        # Find Hermes Agent installation
        hermes_path = os.path.join(os.path.expanduser("~"), ".hermes", "hermes-agent")
        if hermes_path not in sys.path:
            sys.path.insert(0, hermes_path)
        
        # Import cli module
        import cli
        
        # Find the HermesCLI class
        HermesCLI = cli.HermesCLI
        original_show_session_info = HermesCLI.show_session_info
        
        def patched_show_session_info(self):
            """Show session info with Aegis status after banner."""
            # Call original to show the banner
            original_show_session_info(self)
            
            # Add Aegis status line right after the banner
            tier = get_aegis_tier()
            # Use Rich markup for colored output
            self.console.print(f"[bold cyan]🛡️  Aegis Security: Tier {tier} Active[/]")
            self.console.print()  # Extra line for spacing
        
        # Replace the method
        HermesCLI.show_session_info = patched_show_session_info
        return True
        
    except Exception as e:
        # Fail silently - don't break Hermes if patching fails
        import logging
        logging.getLogger(__name__).debug(f"Failed to inject Aegis status: {e}")
        return False


# Don't auto-inject - let integration.py call it after Hermes is loaded
