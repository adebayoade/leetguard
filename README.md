# LeetGuard

LeetGuard is a lightning-fast, open-source CLI tool designed to parse package manager lockfiles and identify security anti-patterns across a project's dependency tree and source code. Built for modern **Node.js, React, and React Native** environments, it maps findings directly to **ISO 27001:2022 Annex A** controls, giving you immediate compliance and security insights without the noise of bloated commercial scanners.

## Key Features

### 1. Intelligent Vulnerability Scanning (OSV API)

Cross-references your entire dependency tree against the Open Source Vulnerability (OSV) database. It resolves transitive dependencies from your `package-lock.json` and automatically chunks queries to respect API limits.

### 2. Supply Chain Abandonment Detection

A package without CVEs isn't necessarily secure if it hasn't been updated in 5 years. LeetGuard checks your direct dependencies against the npm Registry to flag any package that hasn't seen a release in the last **24 months** as a Supply Chain Risk.

### 3. AST Source Code Scanning

Goes beyond dependencies to look at your actual code. It recursively parses `.js`, `.jsx`, `.ts`, and `.tsx` files into an Abstract Syntax Tree (AST) using Babel to identify critical anti-patterns across backend and frontend codebases, including:

- **Node.js & General JS**: Dynamic execution (`eval`, `new Function`), insecure transport protocols (`http://`)
- **React & React Native**: Unsafe component patterns, React Native specific WebView vulnerabilities, and sensitive data exposure in local storage (`AsyncStorage`)
- **Data Exposure**: Accidentally leaving `console.log` with sensitive data in production builds

### 4. Persistent Filesystem Caching

To dramatically speed up scans and prevent IP rate-limiting:

- OSV CVE data is cached locally for **12 hours**.
- npm abandonment metrics are cached locally for **24 hours**.
  The cache is intelligently stored in `~/.leetguard/cache.json`, making subsequent runs virtually instantaneous.

### 5. Compliance Mapping

Every single finding—from an abandoned npm package to an `eval()` call in your source code—is automatically mapped to a specific ISO 27001:2022 control (e.g., _A.8.8 Management of technical vulnerabilities_, _A.5.22 Supplier monitoring_).

---

## Installation

To install LeetGuard globally on your machine:

```bash
npm install -g leetguard
```

_(Note: During development, you can run `npm run build` and use `node dist/index.js` to execute the CLI locally)._

---

## Usage

Run the `scan` command and point it to any project directory containing a `package-lock.json`:

```bash
leetguard scan /path/to/project --format text
```

If you omit the `--format` flag, LeetGuard will interactively prompt you to choose an output format.

### Supported Output Formats

LeetGuard supports multiple output formats via the `--format` flag to accommodate both developers and automated CI/CD pipelines:

- **`text`** (Default): A beautifully formatted, human-readable terminal output with color-coded findings and dependency traces.
- **`json`**: Outputs the raw, structured findings array as JSON. Ideal for integrating LeetGuard into automated pipelines, SIEM tools, or custom dashboards. Includes exact package names, versions, severity levels, and CVE IDs.
- **`audit`** and **`html`**: Both formats generate a formal ISO 27001 Non-Conformity Report (NCR) tailored for security auditors and compliance teams. They include:
  - **Dynamic NCR ID Generation**: Every scan automatically generates a unique report ID (e.g., `NCR-1F1AA65D`) using cryptographic randomness, and sequentially numbers every finding (e.g., `NCR-1F1AA65D-001`).
  - **Automated Severity Mapping**: Findings are mapped to compliance standards based on their OSV severity:
    - **MAJOR NON-CONFORMITY**: For `CRITICAL` and `HIGH` vulnerabilities.
    - **MINOR NON-CONFORMITY**: For `MODERATE` vulnerabilities.
    - **OBSERVATION**: For `LOW` and `INFO` vulnerabilities.
  - **Clean Metadata**: Technical jargon and long markdown descriptions are intentionally omitted. Instead, findings are summarized with actionable metadata, including Package Name, Package Version, Vulnerability ID, CVE ID, CVSS Score, Severity, and the direct OSV URL.

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

## How It Works

1. **Lockfile Parsing:** LeetGuard reads your `package-lock.json` and builds an in-memory dependency tree, computing the exact node resolution paths and traces for how every package is included.
2. **OSV Batch Querying:** It gathers all the unique package versions and sends a highly-optimized batch query (`/querybatch`) to the OSV (Open Source Vulnerability) API. This completely bypasses rate-limiting and retrieves results for thousands of packages in mere seconds.
3. **AST Scanning:** It crawls your source code directories (ignoring `node_modules` and hidden folders), using Babel to build an Abstract Syntax Tree (AST) of your TypeScript and JavaScript files. It traverses the AST to flag anti-patterns like `eval()` usage or insecure connections.
4. **Data Aggregation:** Findings from OSV, npm registry abandonment checks, and source code scans are grouped, deduplicated, and mapped to specific ISO 27001 compliance controls.
5. **Report Generation:** Based on your chosen `--format`, it filters the data and streams it out. For compliance outputs (`audit` and `html`), it strips out excessive vulnerability details to prioritize clean metadata for auditors.

## Architecture

LeetGuard is broken into four distinct layers:

1. **CLI Layer**: Built with `commander` and `@inquirer/prompts` for a smooth terminal experience.
2. **Core Layer**: Houses the `lockfile-parser` (for traversing npm `dependencies` trees) and the caching mechanisms.
3. **Intelligence Layer**: The brains of the operation. Modules here include the OSV client, npm-registry checker, and the Babel-powered AST source code scanner.
4. **Reporting Layer**: Formats the `Finding[]` arrays into beautiful `chalk`-colored outputs.

## License

This project is licensed under the [MIT License](./LICENSE).
