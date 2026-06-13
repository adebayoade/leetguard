# Contributing to LeetGuard

First off, thank you for considering contributing to LeetGuard!

## Development Setup

1. Fork and clone the repository.
2. Run `npm install` to install dependencies.
3. Run `npm run build` to compile the TypeScript code.
4. Run `npm run test` to execute the test suite.

## Architecture

LeetGuard is split into 4 layers:

- **Layer 1: CLI** (`src/cli/`)
- **Layer 2: Core Engine** (`src/core/`)
- **Layer 3: Intelligence Layer** (`src/intelligence/`)
- **Layer 4: Reporting** (`src/reporting/`)

Please ensure any new features respect this architecture.

## Pull Requests

1. Create a feature branch.
2. Add tests for your changes.
3. Ensure the test suite passes (`npm test`).
4. Submit your PR with a clear description of the problem and your solution.
