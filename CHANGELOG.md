# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [8.0.8]

### Fixed

- Swap: allow native tokens on device-owned change outputs. Accounts holding native
  tokens could not swap ADA, since Cardano's UTXO model forces tokens from spent
  inputs to reappear in an output.

## [8.0.7]

### Fixed

- Swap: allow multi-witness swap transactions. Multi-input swaps spending UTXOs from
  different addresses of the same account require one payment-key witness per unique
  signing key; the previous `num_witnesses != 1` guard rejected these incorrectly.

### Changed

- Migrated Python linter from pylint to ruff.
- Fixed Apex device icon.

## [8.0.6]

### Fixed

- Fixed memory leak in transaction context cleanup path.

## [8.0.5]

### Changed

- Application name refined: displays as `Cardano ADA` in external contexts (Exchange,
  device manager) and as `Cardano` on-screen.

## [8.0.4]

### Added

- Unrestricted signing mode.
- Multisig DRep key support.
- Expert mode now shows network details (network ID and protocol magic).

### Changed

- Address review screen title changed to "Verify Cardano address".
- Skip redundant intro pages when fewer than two of fee/certificate pages are present.

### Fixed

- Fixed stack corruption on Nano X during swap library-mode calls.

## [8.0.3]

### Fixed

- Fixed APDU interleaving handling.
- Improved swap transaction security policies.

## [8.0.2]

### Fixed

- Further hardening of swap transaction security policies.

## [8.0.1]

### Fixed (security — Cerberus audit)

- **CRITICAL** Swap: reject third-party outputs that include native tokens (CWE-20).
- **HIGH** Swap: reject transactions that include a donation field (CWE-20).
- **HIGH** Swap: validate full transaction structure before approving (CWE-306).
- **HIGH** Always show output datum hash regardless of expert mode (CWE-602/CWE-451).
- **MEDIUM** Swap: enforce single witness in swap mode (CWE-862).

### Added

- Auto tx signing mode: signing mode is resolved automatically from transaction fields.

### Fixed

- Fixed APDU interleaving handling.
- Fixed various issues identified during Cerberus security audit.

## [8.0.0]

Complete rewrite of the Cardano Ledger app.

### Changed

- Replaced the previous codebase with a modernized architecture.
- Dropped support for Ledger Nano S.
- Switched to NBGL-only UI flows across supported devices.

### Fixed

- Added voter path validation for Plutus signing mode (previously any path was silently accepted).

### Added

- Support for combined Conway delegation certificates.
