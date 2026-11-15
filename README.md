# npm-sbom-tool

An enterprise-ready, zero-runtime-dependency JavaScript engine and command-line tool for generating Software Bill of Materials (SBOM), auditing security vulnerabilities, and detecting supply chain anomalies in npm projects.

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CycloneDX 1.7](https://img.shields.io/badge/CycloneDX-1.7-blue.svg)](https://cyclonedx.org/)

---

## Table of Contents

- [Project Purpose](#project-purpose)
- [Main Features](#main-features)
- [Prerequisites & Requirements](#prerequisites--requirements)
- [Installation](#installation)
  - [Global CLI Installation](#global-cli-installation)
  - [Local Project Dependency](#local-project-dependency)
  - [Zero-Install Execution via npx](#zero-install-execution-via-npx)
- [Command-Line Interface (CLI)](#command-line-interface-cli)
  - [1. Invocation & Global Options](#1-invocation--global-options)
  - [2. The `scan` Command](#2-the-scan-command)
  - [3. The `sbom` Command](#3-the-sbom-command)
  - [4. The `audit` Command](#4-the-audit-command)
  - [5. Full-Pipeline Multi-File Report Structure (`--full`)](#5-full-pipeline-multi-file-report-structure---full)
  - [6. Error Handling & Exit Codes](#6-error-handling--exit-codes)
- [Programmatic API & Architecture](#programmatic-api--architecture)
  - [Engine Entry Points](#engine-entry-points)
  - [Project Scanner (`scanProject`)](#project-scanner-scanproject)
  - [CycloneDX 1.7 Generation & Structural Validation](#cyclonedx-17-generation--structural-validation)
  - [First-Party Component & Workspace Discovery](#first-party-component--workspace-discovery)
  - [OSV Vulnerability Detection Pipeline](#osv-vulnerability-detection-pipeline)
  - [Anomaly Detection](#anomaly-detection)
  - [SBOM Inventory Comparison](#sbom-inventory-comparison)
  - [Report Generation](#report-generation)
- [Development Setup](#development-setup)
- [Test Execution](#test-execution)
- [Known Limitations](#known-limitations)
- [License Information](#license-information)
- [Repository & Issue Reporting](#repository--issue-reporting)

---

## Project Purpose

In modern software supply chains, deep visibility into software components is essential for security compliance, license tracking, and vulnerability remediation.

`npm-sbom-tool` generates deterministic, referentially integral **CycloneDX 1.7** JSON Software Bill of Materials (SBOM) for npm applications and monorepos. It resolves complete dependency trees (direct, transitive, and local workspaces) entirely offline from project manifests and lockfiles without running arbitrary package lifecycle scripts.

Furthermore, `npm-sbom-tool` provides integrated security auditing against the [Open Source Vulnerabilities (OSV)](https://osv.dev/) database, detects structural anomalies and data smells across SBOM components, and allows inventory diffing between different releases or build artifacts.

---

## Main Features

- **Standard CycloneDX 1.7 Output**: Generates compliant JSON SBOMs containing root application metadata, component inventories, and comprehensive dependency graph edges (`dependsOn`).
- **Offline Structural Validation**: Built-in, zero-network validation (`validateStructure`) verifies required metadata, PURL syntax, duplicate `bom-ref`s, and dependency edge referential integrity.
- **First-Party Monorepo Discovery**: Native detection of npm workspaces (`workspaces` array or object syntax, glob wildcards, pattern negations, scoped packages, and internal symlinks).
- **Automated OSV Vulnerability Matching**: Queries the OSV API with batching and evaluates advisories against installed versions using precise SemVer 2.0.0 rules (handling `introduced`, `fixed`, `last_affected`, and `limit` events).
- **Component & Graph Anomaly Detection**: Proactively uncovers supply chain smells, such as missing or non-SemVer versions, invalid/missing PURLs, duplicate `bom-ref`s, and dangling dependency edges.
- **SBOM Inventory Comparison**: Standalone or integrated semantic comparison of two SBOMs, categorizing packages into `added`, `removed`, `upgrade`, `downgrade`, `metadata-changed`, or `unchanged`.
- **Comprehensive Multi-File Reports**: Generates unified executive reports (`report.json`) as well as dedicated artifact files (`sbom.json`, `vulnerabilities.json`, `anomalies.json`).
- **Zero External Runtime Dependencies**: Implemented entirely with native Node.js standard libraries (`node:fs`, `node:path`, `node:crypto`, `node:https`), ensuring minimal attack surface, fast installation, and rock-solid portability.

---

## Prerequisites & Requirements

- **Node.js**: `>= 18.0.0` (Node.js 20+ LTS recommended). Tested across Node.js 18, 20, and 22.
- **npm**: `>= 9.0.0`
- **Supported Package Managers**: `npm` with `package-lock.json` versions 1, 2, and 3. Projects using Yarn or pnpm are identified and rejected with standard diagnostic errors.
- **Network Access**: Required only for OSV vulnerability queries (`https://api.osv.dev`). All core SBOM generation, workspace discovery, validation, and anomaly detection operate 100% offline.

---

## Installation

### Global CLI Installation

Install globally via npm to make the CLI available across your system:

```bash
npm install -g npm-sbom-tool
```

Verify that the CLI executable is installed and accessible:

```bash
# Verify using either binary name:
sbom-tool --version
npm-sbom-tool --version
```

### Local Project Dependency

Install locally as a development dependency in your project:

```bash
npm install --save-dev npm-sbom-tool
```

Once installed locally, execute commands through `npx`:

```bash
npx sbom-tool scan .
```

### Zero-Install Execution via npx

Run commands directly without prior installation:

```bash
npx npm-sbom-tool --help
# or
npx sbom-tool scan ./my-project
```

---

## Command-Line Interface (CLI)

`npm-sbom-tool` provides two equivalent binary aliases: **`sbom-tool`** and **`npm-sbom-tool`**.

### 1. Invocation & Global Options

```bash
# Display general help and command list
sbom-tool --help

# Display installed version
sbom-tool --version
```

#### Global Options

| Option | Shorthand | Description |
|---|---|---|
| `--help` | `-h` | Display general help or command-specific help message. |
| `--version` | `-V` | Display the installed version number. |

#### Available Commands

- **`scan`**: Scan an npm project and inspect its dependency tree.
- **`sbom`**: Generate a standard CycloneDX 1.7 JSON SBOM document.
- **`audit`**: Perform security vulnerability and anomaly analysis on a project.

---

### 2. The `scan` Command

The `scan` command inspects an npm project directory, discovers manifests and lockfiles, resolves dependencies, and displays a comprehensive summary.

```bash
# Scan current directory
sbom-tool scan .

# Scan a specific project directory
sbom-tool scan ./my-project

# Full-pipeline scan: SBOM generation, validation, OSV vulnerabilities, and anomalies
sbom-tool scan ./my-project --full

# Full-pipeline scan writing multi-file report to a custom directory
sbom-tool scan ./my-project --full --output-dir ./reports

# Output structured scan JSON directly to stdout (clean for piping)
sbom-tool scan ./my-project --json

# Save scan report or generated SBOM to a custom file
sbom-tool scan ./my-project --output ./reports/scan-report.json

# Scan with OSV vulnerability detection enabled
sbom-tool scan ./my-project --vulnerabilities

# Scan and compare dependency inventory against a previous CycloneDX SBOM
sbom-tool scan ./my-project --previous-sbom ./prev-bom.cdx.json

# Display scan-specific help
sbom-tool scan --help
```

#### `scan` Options

| Option | Shorthand | Description |
|---|---|---|
| `--full` | | Perform a complete full-pipeline scan (SBOM generation, validation, OSV vulnerabilities, anomalies, and comparison if `--previous-sbom` provided). |
| `--output <path>` | `-o <path>` | Write scan report (or generated SBOM) to file, or output directory when used with `--full`. |
| `--output-dir <path>` | | Directory to write multi-file report (`sbom.json`, `vulnerabilities.json`, `anomalies.json`, `report.json`). |
| `--json` | | Output structured scan results in JSON format directly to stdout. |
| `--vulnerabilities` | `-v` | Enable OSV vulnerability analysis for discovered dependencies. |
| `--anomalies` | `-a` | Enable anomaly detection explicitly. |
| `--previous-sbom <path>` | | Path to a previous CycloneDX SBOM JSON file for dependency comparison. |
| `--help` | `-h` | Show scan command help message. |

#### Example Terminal Output (`scan`)

```text
Scanning project: /path/to/my-application

Scan status: complete
Project: my-application@1.0.0
Lockfile version: 3
Components discovered: 25
Direct dependencies: 8
Transitive dependencies: 17
Workspace packages: 2
```

---

### 3. The `sbom` Command

The `sbom` command generates an industry-standard **CycloneDX 1.7** JSON Software Bill of Materials (SBOM) for an npm project.

```bash
# Generate CycloneDX SBOM (defaults to ./sbom.cdx.json)
sbom-tool sbom ./my-project

# Save CycloneDX SBOM to a custom file path
sbom-tool sbom ./my-project --output ./bom.cdx.json
sbom-tool sbom ./my-project -o ./reports/sbom.json

# Stream CycloneDX SBOM JSON directly to stdout
sbom-tool sbom ./my-project --json > sbom.json

# Display sbom-specific help
sbom-tool sbom --help
```

#### `sbom` Options

| Option | Shorthand | Description |
|---|---|---|
| `--output <path>` | `-o <path>` | Output file path for generated CycloneDX SBOM (Default: `./sbom.cdx.json`). |
| `--json` | | Output CycloneDX SBOM JSON directly to stdout without diagnostic logs. |
| `--help` | `-h` | Show sbom command help message. |

#### Built-in Safety & Validation Checks

- **Automatic Directory Creation**: Parent directories of the output path are created automatically if they do not exist.
- **Manifest Protection**: Rejects output paths that would overwrite project manifests (`package.json`, `package-lock.json`).
- **Directory Collision Prevention**: Rejects output paths pointing to existing directories unless an output filename is specified.
- **Lockfile Enforcement**: A valid `package-lock.json` is required for complete SBOM generation; partial scans fail safely with a diagnostic error.

---

### 4. The `audit` Command

The `audit` command evaluates a target project against known security vulnerabilities (via the OSV API) and structural anomalies.

```bash
# Run both vulnerability analysis and anomaly detection (default)
sbom-tool audit ./my-project

# Run vulnerability analysis only
sbom-tool audit ./my-project --vuln

# Run anomaly analysis only
sbom-tool audit ./my-project --anomaly

# Run both analyses explicitly
sbom-tool audit ./my-project --vuln --anomaly

# Audit with inventory comparison against a previous CycloneDX SBOM
sbom-tool audit ./my-project --previous-sbom ./prev-bom.cdx.json

# Save structured audit report to a JSON file
sbom-tool audit ./my-project --output ./audit-report.json

# Output structured audit report in JSON format to stdout
sbom-tool audit ./my-project --json

# Display audit-specific help
sbom-tool audit --help
```

#### `audit` Options

| Option | Shorthand | Description |
|---|---|---|
| `--vuln` | `-v` | Perform vulnerability analysis only (or explicitly). |
| `--anomaly` | `-a` | Perform anomaly analysis only (or explicitly). |
| `--previous-sbom <path>` | | Path to a previous CycloneDX SBOM JSON file for dependency comparison. |
| `--output <path>` | `-o <path>` | Output file path for the structured audit report JSON. |
| `--json` | | Output structured audit report JSON directly to stdout. |
| `--help` | `-h` | Show audit command help message. |

*Note: When neither `--vuln` nor `--anomaly` is specified, both analyses are performed by default.*

#### Example Terminal Output (`audit`)

```text
Security Audit

Project: my-application@1.0.0
Path: /path/to/my-application

Dependencies scanned: 25

--- Vulnerabilities ---
Status: COMPLETED
Packages checked: 25/25
Vulnerabilities found: 2
Critical: 0
High: 1
Medium: 1
Low: 0

Vulnerability Findings:
  • GHSA-p6mc-m468-83gw [CVSS_V3: 7.5] - lodash@4.17.15 (transitive) (Fixed in: 4.17.21)
    Summary: Prototype Pollution in lodash

--- Anomalies ---
Anomalies detected: 1 (errors: 0, warnings: 1, info: 0)
  ⚠ [MISSING_PURL] custom-pkg: Component is missing a Package URL (PURL).

Audit completed (Status: completed).
```

---

### 5. Full-Pipeline Multi-File Report Structure (`--full`)

When running `sbom-tool scan ./my-project --full`, the tool executes all supported scanning, SBOM generation, validation, and security analysis capabilities in a single unified execution:

1. Manifest parsing and dependency graph resolution
2. First-party workspace package discovery
3. CycloneDX 1.7 JSON SBOM generation
4. Built-in structural SBOM validation
5. OSV API vulnerability analysis for third-party packages
6. Component metadata and graph anomaly detection
7. Dependency comparison (when `--previous-sbom <path>` is supplied)

#### Multi-File Report Directory

By default, the `--full` option outputs a structured report directory (default `./output/` or configurable via `--output-dir <path>` or `--output <dir>`):

```text
output/
├── sbom.json             # Pure CycloneDX 1.7 JSON Software Bill of Materials
├── vulnerabilities.json  # Structured OSV vulnerability findings and package metrics
├── anomalies.json        # Component and graph anomaly findings with explanations
└── report.json           # Comprehensive combined scan and security report
```

#### Output Artifact Descriptions

| Output File | Format | Description |
|---|---|---|
| `sbom.json` | CycloneDX 1.7 JSON | Pure industry-standard SBOM containing `metadata.component` (root application), `components` (libraries & workspaces), and `dependencies` (referential graph edges). Only emitted on complete, structurally valid scans. |
| `vulnerabilities.json` | JSON | Structured findings for known CVEs/GHSAs, affected SemVer ranges, fixed versions, CVSS severities, and scan metrics. Clearly records `'skipped'` if analysis was not executed or not possible. |
| `anomalies.json` | JSON | Structured findings for invalid SemVer versions, missing/malformed PURLs, dangling graph references, and duplicate `bom-ref`s with human-readable impact explanations. |
| `report.json` | JSON | Unified executive scan report combining scan metadata, project info, SBOM inventory summary, validation results, vulnerability findings, anomaly findings, comparison findings (if requested), and overall status. |

---

### 6. Error Handling & Exit Codes

The CLI returns standard process exit codes:

| Exit Code | Meaning | Scenarios |
|---|---|---|
| `0` | Success | Command completed successfully (including complete scans, partial scans with warnings, and audits with findings). |
| `1` | Error | Invalid command, missing/unrecognized options, nonexistent project directory, manifest parsing failure, missing lockfile for `sbom`, BOM validation failure, or file write failure. |

All errors are reported with actionable human-readable messages without exposing internal stack traces by default. Diagnostic and error messages are routed to `stderr`, keeping `stdout` clean for JSON consumers.

---

## Programmatic API & Architecture

The `npm-sbom-tool` package exposes unified programmatic entry points for use in Node.js applications and CI/CD pipelines.

### Engine Entry Points

```javascript
import {
  executeScan,
  executeSbom,
  executeAudit,
  buildCombinedReport,
  generateReportFiles,
} from 'npm-sbom-tool';

// 1. Full-pipeline scan
const scanResult = await executeScan('./my-project', { full: true });

// 2. Pure CycloneDX SBOM generation
const sbomResult = await executeSbom('./my-project');
if (sbomResult.success) {
  console.log('CycloneDX 1.7 SBOM:', sbomResult.bom);
}

// 3. Security audit
const auditReport = await executeAudit('./my-project', {
  vuln: true,
  anomaly: true,
  previousSbom: './prev-bom.cdx.json',
});

// 4. Combined report object
const report = buildCombinedReport(scanResult);

// 5. Write multi-file report directory
generateReportFiles('./output', scanResult);
```

### Project Scanner (`scanProject`)

```javascript
import { scanProject, scanProjectSync } from 'npm-sbom-tool';

// Asynchronously scan an npm project
const result = await scanProject('./my-project', {
  vulnerabilities: true, // Optional: enable OSV checking
  anomalies: true,       // Optional: enable anomaly detection
});

console.log(result.status);          // 'complete' | 'partial' | 'failed'
console.log(result.projectMetadata); // { name: 'my-project', version: '1.0.0' }
console.log(result.components);      // Discovered component array
console.log(result.dependencyEdges); // Graph adjacency list
console.log(result.bom);             // CycloneDX 1.7 SBOM object (or null)
console.log(result.validation);      // { valid: true, errors: [], warnings: [] }
console.log(result.vulnerabilities); // Vulnerability findings and summary
console.log(result.anomalies);       // Anomaly findings and summary

// Synchronous scan (guaranteed identical result)
const syncResult = scanProjectSync('./my-project');
```

### CycloneDX 1.7 Generation & Structural Validation

```javascript
import {
  generateCycloneDX,
  validateStructure,
  validatePurl,
} from 'npm-sbom-tool';

// 1. Generate CycloneDX 1.7 JSON SBOM from components and dependency edges
const bom = generateCycloneDX(components, dependencyEdges, {
  name: 'my-project',
  version: '1.0.0',
});

// 2. Offline structural validation
const validation = validateStructure(bom);
console.log(validation.valid);    // boolean
console.log(validation.errors);   // string[]
console.log(validation.warnings); // string[]

// 3. Standalone Package URL (PURL) validation
const purlCheck = validatePurl('pkg:npm/%40babel/core@7.24.0');
console.log(purlCheck.valid);     // true
```

### First-Party Component & Workspace Discovery

`npm-sbom-tool` provides built-in discovery for root projects and npm workspaces:

- **Root Application**: Placed in `metadata.component` with `isFirstParty: true` and `origin: 'first-party'`.
- **Local Workspaces**: Discovered via `"workspaces": [...]` array or object configuration. Supports single wildcards (`*`), recursive wildcards (`**`), character wildcards (`?`), and pattern negations (`!pattern`).
- **Symlinks & Resolvers**: Resolves workspace symlinks (`link: true`) in `package-lock.json` v2/v3 without duplicating components.
- **Classification**: Distinguishes first-party local packages (`isFirstParty: true`, `dependencyType: 'workspace'`) from external registry packages (`isFirstParty: false`, `dependencyType: 'direct' | 'transitive'`).

```javascript
import { discoverFirstPartyComponents } from 'npm-sbom-tool';

const discovery = await discoverFirstPartyComponents('./my-monorepo');
console.log(discovery.rootComponent); // Root application metadata
console.log(discovery.workspaces);    // Discovered workspace packages
```

### OSV Vulnerability Detection Pipeline

The vulnerability pipeline queries the [OSV API](https://osv.dev/) in concurrent batches and matches advisories against installed versions using SemVer 2.0.0 rules:

```javascript
import { checkVulnerabilities, queryPackage, queryPackages } from 'npm-sbom-tool';

// Query a single package
const single = await queryPackage({ name: 'lodash', version: '4.17.20' });

// Query a batch of packages
const batch = await queryPackages([
  { name: 'lodash', version: '4.17.20' },
  { name: 'express', version: '4.18.2' },
]);

// Run vulnerability check on an existing CycloneDX BOM
const check = await checkVulnerabilities(bom, {
  concurrency: 8,
  timeout: 10000,
});
console.log(check.status);   // 'completed' | 'partial' | 'failed'
console.log(check.findings); // Array of normalized findings
```

### Anomaly Detection

Identifies supply chain smells across metadata and graph relationships:

```javascript
import { detectAnomalies } from 'npm-sbom-tool';

const { anomalies, summary } = detectAnomalies(bom, { summary: true });
console.log(summary); // { total: 1, bySeverity: { error: 0, warning: 1, info: 0 }, byType: { MISSING_PURL: 1 } }
```

### SBOM Inventory Comparison

Compares two SBOM inventories to classify dependency changes:

```javascript
import { compareInventories } from 'npm-sbom-tool';

const comparison = compareInventories(previousBom, currentBom);
console.log(comparison.status);  // 'completed' | 'failed'
console.log(comparison.summary); // { added, removed, changed, unchanged }
console.log(comparison.added);   // Added dependencies
console.log(comparison.changed); // Upgrades, downgrades, and metadata changes
```

### Report Generation

```javascript
import { buildCombinedReport, generateReportFiles } from 'npm-sbom-tool';

// Build combined report JSON object
const report = buildCombinedReport(scanResult);

// Emit standard four files: sbom.json, vulnerabilities.json, anomalies.json, report.json
generateReportFiles('./output', scanResult);
```

---

## Development Setup

To contribute or develop on `npm-sbom-tool`:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/pankaj-codes06/SBOM-TOOL.git
   cd SBOM-TOOL
   ```

2. **Install development dependencies**:
   ```bash
   npm install
   ```

3. **Verify syntax across all modules**:
   ```bash
   npm run check
   ```

4. **Run the CLI directly from source**:
   ```bash
   node src/cli.js --help
   node src/cli.js scan ./fixtures/simple-project
   ```

---

## Test Execution

`npm-sbom-tool` uses Node.js's built-in native test runner (`node --test`), requiring no third-party test runners or transpilation.

### Run Full Test Suite

Execute all 540+ tests across the entire suite:

```bash
npm test
```

### Targeted Test Scripts

Execute individual sub-suites for specific components:

| Command | Target Module |
|---|---|
| `npm run test:cli` | CLI commands (`scan`, `sbom`, `audit`, argument parsing, exit codes) |
| `npm run test:scanner` | Manifest and lockfile discovery and scanner orchestration |
| `npm run test:parser` | `package.json` and `package-lock.json` parsing |
| `npm run test:resolver` | Dependency resolution and classification |
| `npm run test:graph` | Standalone dependency graph construction |
| `npm run test:workspace` | First-party and monorepo workspace discovery |
| `npm run test:cyclonedx` | CycloneDX 1.7 SBOM generation |
| `npm run test:validator` | CycloneDX structural and schema validation |
| `npm run test:osv` | OSV API client queries and error handling |
| `npm run test:matcher` | SemVer matching and range evaluation |
| `npm run test:findings` | Finding extraction and deduplication |
| `npm run test:vuln` | End-to-end vulnerability pipeline integration |
| `npm run test:anomaly` | SBOM metadata and graph anomaly detection |
| `npm run test:compare` | SBOM inventory diffing and change classification |
| `npm run test:integration` | End-to-end pipeline and integration scenarios |
| `npm run test:order18` | Engine orchestration and pipeline options |
| `npm run test:order19` | Multi-file and executive report generation |
| `npm run test:order20` | Scanner end-to-end fixture validation |
| `npm run test:order21` | Security SBOM generation and CycloneDX 1.7 validation |
| `npm run check` | Static syntax check on all JavaScript files via `node --check` |

---

## Known Limitations

1. **Package Manager Scope**: `npm-sbom-tool` specifically targets the **npm** ecosystem (`package.json` and `package-lock.json`). Projects managed exclusively by Yarn or pnpm are identified and safely rejected with `UNSUPPORTED_PACKAGE_MANAGER`.
2. **Lockfile Dependency**: Complete, referentially sound CycloneDX SBOM generation requires an existing `package-lock.json` (v1, v2, or v3). Scanning a project without a lockfile generates discovered components with `status: 'partial'`, and leaves `bom: null`.
3. **OSV Network Connectivity**: Vulnerability detection requires outbound HTTPS connectivity to `https://api.osv.dev`. When the network is unavailable or times out, the tool records explicit error entries rather than falsely reporting 0 vulnerabilities.
4. **Non-SemVer Version Identifiers**: Dependency versions pointing to Git commit SHAs, URLs, or local tarballs cannot be evaluated against SemVer vulnerability ranges or upgrade/downgrade diffs; these are flagged with `unable-to-evaluate` or `version-changed`.
5. **Release Blocker — Physical LICENSE File**: While `package.json` specifies `"license": "MIT"`, the physical `LICENSE` file is pending repository owner confirmation prior to public npm release.

---

## License Information

This project is licensed under the **MIT License** as declared in `package.json`.

*Note: Creation and publication of the standalone `LICENSE` file in the repository root is pending final authorization from the project owner before public release.*

---

## Repository & Issue Reporting

- **Source Code**: [https://github.com/nithyarajmudhaliyar/SBOM-TOOL](https://github.com/nithyarajmudhaliyar/SBOM-TOOL)
- **Issue Tracker**: [https://github.com/nithyarajmudhaliyar/SBOM-TOOL/issues](https://github.com/nithyarajmudhaliyar/SBOM-TOOL/issues)
- **Author & Maintainer**: Nithyaraj Mudhaliyar
- **Team Members: Harshit Chand & Pankaj Kumar
