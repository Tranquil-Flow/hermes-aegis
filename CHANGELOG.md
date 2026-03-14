# Changelog

All notable changes to Hermes Aegis will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-14

### Added
- **Transparent MITM Proxy** - Zero-modification interception of all API calls
- **Secret Vault System** - Secure storage with keyring integration
- **Real-time Request Scanning** - Pattern matching for secrets, PII, dangerous patterns
- **Audit Trail** - Comprehensive JSONL logging of all intercepted requests
- **Rate Limiting** - Protection against token floods and enumeration attacks
- **Allowlist System** - Domain and pattern-based request filtering
- **CLI Interface** - Complete command-line tooling for proxy management
- **Hook Integration** - Automatic injection into Hermes Agent workflow
- **Container Support** - Optional Docker isolation for untrusted commands (Level 3)
- **Run Command** - Sandboxed command execution with network isolation

### Security Features
- Recursive secret redaction at any nesting depth
- Request/response body scanning
- URL parameter scanning
- Header scanning with common secret patterns
- Automatic secret detection (API keys, tokens, passwords)
- Cryptographic audit trail with chain verification

### Technical Details
- Port binding retry logic (handles TOCTOU races)
- Enhanced error handling and logging throughout
- Lifecycle management for proxy processes
- Graceful shutdown with cleanup
- Comprehensive test coverage (60+ tests)

### CLI Commands
- `aegis install` - One-command setup with auto-configuration
- `aegis start` - Launch proxy with hot-reload
- `aegis stop` - Graceful shutdown
- `aegis status` - Connection and health check
- `aegis vault add/list/remove` - Secret management
- `aegis audit show/stats` - Audit trail analysis
- `aegis test-canary` - Verify secret detection works
- `aegis run` - Execute commands in sandboxed environment

### Documentation
- Comprehensive README with quickstart
- Attack scenario demonstrations
- Architecture documentation
- Test coverage reports
- Installation guides

## [0.0.1] - 2026-03-13

### Added
- Initial prototype
- Basic proxy interception
- Simple secret scanning
- Proof of concept

[0.1.0]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.1.0
[0.0.1]: https://github.com/Tranquil-Flow/hermes-aegis/releases/tag/v0.0.1
