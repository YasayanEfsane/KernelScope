# Changelog

All notable changes are documented here. The project follows the spirit of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning.

## [Unreleased]

### Added

- Version 1 fixed-width buffered IOCTL protocol with compile-time ABI assertions.
- Secure non-PnP KMDF control device and least-privilege IOCTL access bits.
- Fixed nonpaged telemetry ring, monotonic sequences, and dropped-event reporting.
- Documented process and image-load notification callbacks.
- C++17 collector with protocol negotiation, independent response validation,
  sequence-gap detection, Ctrl+C handling, JSONL, and file rotation.
- Bounds-checked PE/COFF parser, SHA-256, and Authenticode classification.
- Dependency-free offline tests and optional isolated-VM integration guidance.
- Windows user-mode CI, CodeQL, threat model, hardening, and operational docs.
- Portfolio-grade repository landing page with architecture, quick-start,
  protocol, testing, troubleshooting, and documentation indexes.
- Protocol ABI reference and formal release-evidence procedure.
- Support policy, code of conduct, expanded contribution/security guidance,
  structured feature/question issue forms, and Dependabot for GitHub Actions.
