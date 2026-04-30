# Hermes Aegis Plugin

Tool-level security enforcement for Hermes v0.11 plugin hooks.

This plugin is a companion to the Aegis proxy. The proxy remains responsible
for network-level controls, while this plugin handles stable in-process hook
enforcement: tool veto, audit logging, secret redaction, security context, API
accounting, and a dashboard tab.
