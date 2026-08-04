# LeetGuard

LeetGuard is a lightning-fast, open-source CLI tool designed to parse package manager lockfiles and identify security anti-patterns across a project's dependency tree and source code. Built with modern Node.js environments in mind, it maps findings directly to **ISO 27001:2022 Annex A** controls, giving you immediate compliance and security insights without the noise of bloated commercial scanners.

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

Every single finding—from an abandoned npm package to an `eval()` call in your source code—is automatically mapped to a specific ISO 27001:2022 control (e.g., _A.8.8 Management of technical vulnerabilities_, _A.5.22 Supplier monitoring_).

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
LeetGuard v1.0.0  |  Scanning project...
[LeetGuard] OSV API: Checked 1101 dependencies (all loaded from cache)
[LeetGuard] NPM Registry: Checked 12 direct dependencies (12 loaded from cache)
[LeetGuard] Scanning source code for anti-patterns...
[INFO]  1101 packages resolved (12 direct, 1089 transitive)
[CRIT]  3 critical CVEs found  |  [HIGH] 3  |  [MED] 0  |  [LOW] 0
[WARN]  1 package not updated in over 2 years or deprecated
[SAST]  2 categories of security anti-patterns detected
[ISO]   Controls triggered: A.8.8  A.5.22  A.8.28
[DONE]  Scan complete

[!] Detailed Findings:

>> Injection & Dynamic Execution
  - [High] GHSA-vpq2-c234-7xj6
    Description: [@tootallnate/once@1.1.2] Known Vulnerability
    Trace: root ➔ jest ➔ @jest/core ➔ jsdom ➔ @tootallnate/once
    ISO 27001 Mapping: A.8.8 Management of technical vulnerabilities

>> Supply Chain Risk
  - [Medium] Abandoned Package
    Description: [some-old-lib] Package has not been updated in 36 months.
    ISO 27001 Mapping: A.5.22 Monitoring, review and change management of supplier services

>> Data Exposure
  - [High] Data Exposure via console.log
    Description: src/utils/logger.ts:15 - Sensitive data may be exposed to logs.
    ISO 27001 Mapping: A.8.28 Secure coding
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
