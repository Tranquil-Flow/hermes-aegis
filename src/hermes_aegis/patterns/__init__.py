"""Pattern detection module for secrets and cryptographic keys.

This module provides comprehensive scanning for:
- API keys and tokens (OpenAI, Anthropic, GitHub, AWS, etc.)
- Cryptocurrency private keys and seed phrases
- Database and generic credentials
- Blockchain-specific secrets (Ethereum, Bitcoin, Solana, etc.)

Patterns are used by the middleware chain for redaction and audit logging.
"""
