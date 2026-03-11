# hermes-aegis

**Security hardening layer for Hermes Agent**

## Overview

hermes-aegis provides defense-in-depth security for Hermes Agent with zero user friction:

- **Encrypted secret vault** with OS keyring integration
- **Two-tier auto-detection**: Container isolation (Tier 2) or in-process hardening (Tier 1)
- **Content scanning** for outbound secret leakage
- **Audit trail** with tamper-evident hash chain
- **File integrity checking** for instruction/config files
- **Anomaly detection** for unusual tool call patterns

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Setup (one-time)
hermes-aegis setup

# Run Hermes securely
hermes-aegis run
```

## Architecture

### Tier 2 (Docker Available)
- Hermes runs in hardened container
- Host-side MITM proxy injects secrets and scans traffic
- Full process isolation

### Tier 1 (No Docker)
- In-process middleware chain
- Encrypted vault, content scanning, audit trail
- Requires hermes-agent installed in same venv

## Development

This project follows strict TDD. Run tests with:

```bash
pytest tests/ -v
```

## Documentation

See `docs/` for:
- Design specification and threat model
- Implementation plan
- Security review notes

## Status

🚧 Under active development (Hackathon MVP)

## License

TBD
