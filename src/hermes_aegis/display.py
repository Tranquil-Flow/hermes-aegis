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
    """Inject Aegis status display into Hermes welcome banner.
    
    This patches build_welcome_banner to add Aegis info to the left panel.
    """
    if not check_aegis_active():
        return False
        
    try:
        # Find Hermes Agent installation
        hermes_path = os.path.join(os.path.expanduser("~"), ".hermes", "hermes-agent")
        if hermes_path not in sys.path:
            sys.path.insert(0, hermes_path)
        
        # Import the banner module
        from hermes_cli import banner as banner_module
        
        # Save original function
        original_build_welcome = banner_module.build_welcome_banner
        
        def patched_build_welcome_banner(console, model, cwd, tools=None,
                                         enabled_toolsets=None, session_id=None,
                                         get_toolset_for_tool=None, context_length=None):
            """Wrapper that adds Aegis status to the banner."""
            # Import what we need
            from rich.panel import Panel
            from rich.table import Table
            from model_tools import check_tool_availability, TOOLSET_REQUIREMENTS
            if get_toolset_for_tool is None:
                from model_tools import get_toolset_for_tool as _getter
                get_toolset_for_tool = _getter
            
            # Call original to build most of the banner, but we need to rebuild it
            # to inject our status line. Let's just replicate the left panel construction.
            
            tools = tools or []
            enabled_toolsets = enabled_toolsets or []
            
            _, unavailable_toolsets = check_tool_availability(quiet=True)
            disabled_tools = set()
            for item in unavailable_toolsets:
                disabled_tools.update(item.get("tools", []))
            
            layout_table = Table.grid(padding=(0, 2))
            layout_table.add_column("left", justify="center")
            layout_table.add_column("right", justify="left")
            
            # Resolve skin colors
            accent = banner_module._skin_color("banner_accent", "#FFBF00")
            dim = banner_module._skin_color("banner_dim", "#B8860B")
            text = banner_module._skin_color("banner_text", "#FFF8DC")
            session_color = banner_module._skin_color("session_border", "#8B8682")
            
            # LEFT PANEL - WITH AEGIS STATUS
            left_lines = ["", banner_module.HERMES_CADUCEUS, ""]
            model_short = model.split("/")[-1] if "/" in model else model
            if len(model_short) > 28:
                model_short = model_short[:25] + "..."
            ctx_str = f" [dim {dim}]·[/] [dim {dim}]{banner_module._format_context_length(context_length)} context[/]" if context_length else ""
            left_lines.append(f"[{accent}]{model_short}[/]{ctx_str} [dim {dim}]·[/] [dim {dim}]Nous Research[/]")
            left_lines.append(f"[dim {dim}]{cwd}[/]")
            if session_id:
                left_lines.append(f"[dim {session_color}]Session: {session_id}[/]")
            
            # INJECT AEGIS STATUS
            tier = get_aegis_tier()
            left_lines.append(f"[bold #00D9FF]Security: Aegis Tier {tier} 🛡️[/]")
            
            left_content = "\\n".join(left_lines)
            
            # RIGHT PANEL - tools, skills, etc (copied from original)
            right_lines = [f"[bold {accent}]Available Tools[/]"]
            toolsets_dict = {}
            
            for tool in tools:
                tool_name = tool["function"]["name"]
                toolset = get_toolset_for_tool(tool_name) or "other"
                toolsets_dict.setdefault(toolset, []).append(tool_name)
            
            for item in unavailable_toolsets:
                toolset_id = item.get("id", item.get("name", "unknown"))
                display_name = f"{toolset_id}_tools" if not toolset_id.endswith("_tools") else toolset_id
                if display_name not in toolsets_dict:
                    toolsets_dict[display_name] = []
                for tool_name in item.get("tools", []):
                    if tool_name not in toolsets_dict[display_name]:
                        toolsets_dict[display_name].append(tool_name)
            
            sorted_toolsets = sorted(toolsets_dict.keys())
            display_toolsets = sorted_toolsets[:8]
            remaining_toolsets = len(sorted_toolsets) - 8
            
            for toolset in display_toolsets:
                tool_names = toolsets_dict[toolset]
                colored_names = []
                for name in sorted(tool_names):
                    if name in disabled_tools:
                        colored_names.append(f"[red]{name}[/]")
                    else:
                        colored_names.append(f"[{text}]{name}[/]")
                
                tools_str = ", ".join(colored_names)
                if len(", ".join(sorted(tool_names))) > 45:
                    short_names = []
                    length = 0
                    for name in sorted(tool_names):
                        if length + len(name) + 2 > 42:
                            short_names.append("...")
                            break
                        short_names.append(name)
                        length += len(name) + 2
                    colored_names = []
                    for name in short_names:
                        if name == "...":
                            colored_names.append("[dim]...[/]")
                        elif name in disabled_tools:
                            colored_names.append(f"[red]{name}[/]")
                        else:
                            colored_names.append(f"[{text}]{name}[/]")
                    tools_str = ", ".join(colored_names)
                
                right_lines.append(f"[dim #B8860B]{toolset}:[/] {tools_str}")
            
            if remaining_toolsets > 0:
                right_lines.append(f"[dim #B8860B](and {remaining_toolsets} more toolsets...)[/]")
            
            # MCP Servers section
            try:
                from tools.mcp_tool import get_mcp_status
                mcp_status = get_mcp_status()
            except Exception:
                mcp_status = []
            
            if mcp_status:
                right_lines.append("")
                right_lines.append("[bold #FFBF00]MCP Servers[/]")
                for srv in mcp_status:
                    if srv["connected"]:
                        right_lines.append(
                            f"[dim #B8860B]{srv['name']}[/] [#FFF8DC]({srv['transport']})[/] "
                            f"[dim #B8860B]—[/] [#FFF8DC]{srv['tools']} tool(s)[/]"
                        )
                    else:
                        right_lines.append(
                            f"[red]{srv['name']}[/] [dim]({srv['transport']})[/] "
                            f"[red]— failed[/]"
                        )
            
            # Skills section
            right_lines.append("")
            right_lines.append(f"[bold {accent}]Available Skills[/]")
            skills_by_category = banner_module.get_available_skills()
            total_skills = sum(len(s) for s in skills_by_category.values())
            
            if skills_by_category:
                for category in sorted(skills_by_category.keys()):
                    skill_names = sorted(skills_by_category[category])
                    if len(skill_names) > 8:
                        display_names = skill_names[:8]
                        skills_str = ", ".join(display_names) + f" +{len(skill_names) - 8} more"
                    else:
                        skills_str = ", ".join(skill_names)
                    if len(skills_str) > 50:
                        skills_str = skills_str[:47] + "..."
                    right_lines.append(f"[dim {dim}]{category}:[/] [{text}]{skills_str}[/]")
            else:
                right_lines.append(f"[dim {dim}]No skills installed[/]")
            
            # Footer summary
            right_lines.append("")
            mcp_connected = sum(1 for s in mcp_status if s["connected"]) if mcp_status else 0
            summary_parts = [f"{len(tools)} tools", f"{total_skills} skills"]
            if mcp_connected:
                summary_parts.append(f"{mcp_connected} MCP servers")
            summary_parts.append("/help for commands")
            right_lines.append(f"[dim {dim}]{' · '.join(summary_parts)}[/]")
            
            # Update check
            try:
                behind = banner_module.check_for_updates()
                if behind and behind > 0:
                    commits_word = "commit" if behind == 1 else "commits"
                    right_lines.append(
                        f"[bold yellow]⚠ {behind} {commits_word} behind[/]"
                        f"[dim yellow] — run [bold]hermes update[/bold] to update[/]"
                    )
            except Exception:
                pass
            
            right_content = "\\n".join(right_lines)
            layout_table.add_row(left_content, right_content)
            
            agent_name = banner_module._skin_branding("agent_name", "Hermes Agent")
            title_color = banner_module._skin_color("banner_title", "#FFD700")
            border_color = banner_module._skin_color("banner_border", "#CD7F32")
            outer_panel = Panel(
                layout_table,
                title=f"[bold {title_color}]{agent_name} v{banner_module.VERSION} ({banner_module.RELEASE_DATE})[/]",
                border_style=border_color,
                padding=(0, 2),
            )
            
            console.print()
            console.print(banner_module.HERMES_AGENT_LOGO)
            console.print()
            console.print(outer_panel)
        
        # Replace the function
        banner_module.build_welcome_banner = patched_build_welcome_banner
        return True
        
    except Exception as e:
        # Fail silently - don't break Hermes if patching fails
        import logging
        logging.getLogger(__name__).debug(f"Failed to inject Aegis banner: {e}")
        return False


# Don't auto-inject - let integration.py call it after Hermes is loaded
