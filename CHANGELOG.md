# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- ESLint (flat config) wired up via `npm run lint`, alongside the existing `tsc --noEmit` check.
- `lint-staged`, running `eslint --fix` and `prettier --write` on staged files as part of the pre-commit hook, so lint/format issues are caught before they're committed rather than only in CI.

### Changed

- Replaced all remaining `any` types across `cache.ts`, `lockfile-parser.ts`, `osv-client.ts`, and `ast-scanner.ts` with precise types — including real OSV API response interfaces and Babel `NodePath<T>` types for the AST scanner's visitor callbacks.

### Fixed

- Removed three orphaned entries from `ISOMap` (`iso-mapper.ts`) that didn't correspond to any implemented detector.
- Removed several genuinely unused imports and variables (`Finding` in `html.ts` and `audit.ts`, a dead `weakage` field on the `Finding` type, an unused `sevNames` variable, and multiple dangling unused `catch` error bindings) — previously undetected since the project had no linter.
- `lockfile-parser.ts` now handles the case where a `package-lock.json` entry is missing a `version` field (e.g. some workspace/symlink entries), rather than silently allowing `undefined` through where a `string` was expected.

## [1.3.2] - 2026-09-11

### Fixed

- Expired cache entries are now pruned automatically at the start of every scan, so `~/.leetguard/cache.json` no longer grows unbounded over time — including entries left unreachable by 1.3.1's cache schema versioning once their original TTL passes.

## [1.3.1] - 2026-08-30

### Added

- CVE findings now include `fixedVersions`, the actual patched version(s) reported by OSV for each advisory. Text, audit, and HTML reports show a "Recommended Fix: Upgrade to X" line wherever a fix is available.

### Fixed

- The local cache (`~/.leetguard/cache.json`) could retain findings written by an older version of LeetGuard whose internal shape no longer matched the current release, silently mixing incompatible cached data into scan results after an upgrade. Cache keys are now namespaced by a schema version, so an upgrade automatically invalidates incompatible cached entries instead of returning them.

## Earlier versions

Versions 1.0.0 through 1.3.0 predate this changelog and aren't individually documented here. Their release history is visible via git tags (`git tag -l`) and the [npm version history](https://www.npmjs.com/package/leetguard?activeTab=versions) if needed — happy to backfill entries for those from commit history if that's useful.

[Unreleased]: https://github.com/adebayoade/leetguard/compare/v1.3.2...HEAD
[1.3.2]: https://github.com/adebayoade/leetguard/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/adebayoade/leetguard/compare/v1.3.0...v1.3.1
