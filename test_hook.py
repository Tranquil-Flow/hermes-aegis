import os
import sys

os.environ['TERMINAL_ENV'] = 'aegis'
sys.path.insert(0, '/Users/evinova/.hermes/hermes-agent')
sys.path.insert(0, '/Users/evinova/Projects/hermes-aegis/src')

from hermes_aegis.display import inject_aegis_status_hook

result = inject_aegis_status_hook()
print(f"inject_aegis_status_hook() returned: {result}")

if result:
    import cli
    print(f"HermesCLI.show_session_info: {cli.HermesCLI.show_session_info}")
    print(f"Function name: {cli.HermesCLI.show_session_info.__name__}")
