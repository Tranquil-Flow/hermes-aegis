"""Reactive audit agents — automated response to security events."""

import logging
from pathlib import Path

# Route reactive agent logs to file instead of console.
# Without this, logger.exception() tracebacks from agent spawns and
# delivery failures leak into the hermes terminal via the root handler.
_log_path = Path.home() / ".hermes-aegis" / "reactive.log"
_logger = logging.getLogger("hermes_aegis.reactive")
_logger.propagate = False  # Don't bubble up to root/rich handler
_logger.setLevel(logging.DEBUG)
try:
    _log_path.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(_log_path)
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    _logger.addHandler(_fh)
except OSError:
    pass  # Fall back to no logging if we can't write
