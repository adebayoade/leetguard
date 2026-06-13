# LeetGuard

LeetGuard is a lightning-fast, open-source CLI tool designed to parse package manager lockfiles and identify security anti-patterns across a project's dependency tree and source code. Built with modern Node.js environments in mind, it maps findings directly to **ISO 27001 Annex A** controls, giving you immediate compliance and security insights without the noise of bloated commercial scanners.

## 🚀 Key Features

### 1. Intelligent Vulnerability Scanning (OSV API)

Cross-references your entire dependency tree against the Open Source Vulnerability (OSV) database. It resolves transitive dependencies from your `package-lock.json` and automatically chunks queries to respect API limits.

### 2. Supply Chain Abandonment Detection

A package without CVEs isn't necessarily secure if it hasn't been updated in 5 years. LeetGuard checks your direct dependencies against the npm Registry to flag any package that hasn't seen a release in the last **24 months** as a Supply Chain Risk.

### 3. AST Source Code Scanning

Goes beyond dependencies to look at your actual code. It recursively parses `.js`, `.jsx`, `.ts`, and `.tsx` files into an Abstract Syntax Tree (AST) using Babel to identify critical anti-patterns, including:

- Dynamic execution (`eval`, `new Function`)
- Data exposure (`console.log`, `AsyncStorage`)
- Insecure transport protocols (`http://`)
- React Native specific WebView vulnerabilities

### 4. Persistent Filesystem Caching

To dramatically speed up scans and prevent IP rate-limiting:

- OSV CVE data is cached locally for **12 hours**.
- npm abandonment metrics are cached locally for **24 hours**.
  The cache is intelligently stored in `~/.leetguard/cache.json`, making subsequent runs virtually instantaneous.

### 5. Compliance Mapping

Every single finding—from an abandoned npm package to an `eval()` call in your source code—is automatically mapped to a specific ISO 27001 control (e.g., _A.14.2.8 Secure System Engineering_, _A.14.2.7 Outsourced Development_).

---

## 📦 Installation

To install LeetGuard globally on your machine:

```bash
npm install -g leetguard
```

_(Note: During development, you can run `npm run build` and use `node dist/index.js` to execute the CLI locally)._

---

## 💻 Usage

Run the `scan` command and point it to any project directory containing a `package-lock.json`:

```bash
leetguard scan /path/to/project --format text
```

If you omit the `--format` flag, LeetGuard will interactively prompt you to choose an output format.

### Example Output

```text
[LeetGuard] Scanning directory: ./my-react-app...
[LeetGuard] OSV API: Checked 1101 dependencies (all loaded from cache)
[LeetGuard] NPM Registry: Checked 12 direct dependencies (12 loaded from cache)
[LeetGuard] Scanning source code for anti-patterns...

=== LeetGuard Security Report ===
Scanned Directory: ./my-react-app
Timestamp: 2026-06-13T18:00:00.000Z
Total Dependencies: 1101

[!] Issues Found:

- [High] Injection & Dynamic Execution (GHSA-vpq2-c234-7xj6)
  Description: [@tootallnate/once@1.1.2] Known Vulnerability
  ISO 27001 Mapping: A.14.2.8

- [Medium] Supply Chain Risk (Abandoned Package)
  Description: [some-old-lib] Package has not been updated in 36 months.
  ISO 27001 Mapping: A.14.2.7

- [High] Data Exposure (Data Exposure via console.log)
  Description: src/utils/logger.ts:15 - Sensitive data may be exposed to logs.
  ISO 27001 Mapping: A.13.1.1
```

---

## 🛠 Architecture

LeetGuard is broken into four distinct layers:

1. **CLI Layer**: Built with `commander` and `@inquirer/prompts` for a smooth terminal experience.
2. **Core Layer**: Houses the `lockfile-parser` (for traversing npm `dependencies` trees) and the caching mechanisms.
3. **Intelligence Layer**: The brains of the operation. Modules here include the OSV client, npm-registry checker, and the Babel-powered AST source code scanner.
4. **Reporting Layer**: Formats the `Finding[]` arrays into beautiful `chalk`-colored outputs.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
