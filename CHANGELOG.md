# Changelog

All notable changes to this package are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- **Breaking:** `KeychainStore.Failure` gained `.itemNotFound` and `.interactionNotAllowed`; add them to exhaustive switches.
- **Breaking:** `PinnedSessionDelegate.pin(for:)` returns the SHA-256 of the SubjectPublicKeyInfo. Pins created from the bare key are still accepted by `init(pinnedPublicKeyHashesBase64:)`.

### Changed

- Rename module(s) -> Anvyx* (naming convention)
- Initial commit

### Fixed

- SPKI-based pins, pin policy, safer keychain and file writes
