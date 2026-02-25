# Changelog

All notable changes to this project are documented in this file.

## v1.0.6 - 2026-02-25

### Added
- OpenClaw adapter `Execution Firewall` with enforce/audit/off modes, default high-risk command rules, custom tool blocks, and command-level matching via `toolExecutions`.
- OpenClaw adapter `Canary Leak Sentinel` with per-session canary generation, prompt/tool leak detection, and enforce/audit/off modes.
- OpenClaw adapter `Autonomy Budget Guard` to cap autonomous review bypass by count, cumulative risk, single-event risk, and time window.
- OpenClaw adapter `Context Shield` to quarantine suspicious external/unknown context chunks before gateway evaluation.
- OpenClaw adapter `Decision Receipt Chain` with tamper-evident hash receipts and optional chained previous-hash linkage.

### Changed
- Updated OpenClaw scaffold skill and example integration to include all five protections by default.
- Expanded OpenClaw adapter docs and README integration guidance for the new security controls and result telemetry.

### Package Versions
- `@codegrammer/ai-sec-openclaw-adapter`: `0.2.0`
- `@codegrammer/ai-sec-cli`: `1.0.6`
