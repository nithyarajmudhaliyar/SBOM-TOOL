# Changelog

All notable changes to the `npm-sbom-tool` project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-14

### Initial Public Release Preparation

`npm-sbom-tool` is an enterprise-ready, zero-runtime-dependency JavaScript engine and command-line interface for generating Software Bill of Materials (SBOM), auditing known security vulnerabilities, detecting metadata anomalies, and comparing dependency inventories in npm projects.

### Features

#### 1. Dependency Discovery & Lockfile Parsing
- Discovers and parses `package.json` and `package-lock.json` supporting lockfile format versions 1, 2, and 3.
- Resolves full dependency graphs including direct and transitive relationships, deduplicating identical package references while properly tracking multi-version dependencies.
- Handles missing, malformed, and partial projects with standard diagnostic error structures (`status: 'complete' | 'partial' | 'failed'`).

#### 2. First-Party & Workspace Monorepo Discovery
- Automatically identifies root applications as first-party components (`isFirstParty: true`, `origin: 'first-party'`).
- Detects local npm workspace packages configured via array or object patterns in root `package.json`.
- Supports standard glob wildcards (`*`, `**`, `?`), negation patterns (`!pattern`), and scoped package namespaces.
- Resolves workspace symlinks (`link: true`) in modern npm lockfiles, linking dependencies directly to discovered workspace components without duplication.
- Accurately classifies workspace dependencies vs. third-party registry packages.

#### 3. CycloneDX 1.7 JSON SBOM Generation
- Generates standard CycloneDX 1.7 JSON Software Bill of Materials.
- Populates `metadata.component` with root application identity and metadata.
- Populates `components` array with all discovered libraries, frameworks, and workspace modules.
- Builds referentially sound dependency graph entries (`dependencies` array with `dependsOn` arrays), ensuring zero dangling references.

#### 4. Offline Structural & Schema Validation
- Performs built-in, offline structural validation (`validateStructure`) without external network dependencies.
- Validates Package URLs (PURL) syntax and encoding (`validatePurl`).
- Verifies uniqueness of `bom-ref` identifiers and integrity of dependency edges.
- Supports optional JSON schema validation (`validateAgainstSchema`).

#### 5. OSV Vulnerability Detection Pipeline
- Integrates with the [Open Source Vulnerabilities (OSV)](https://osv.dev/) API.
- Implements concurrent batch querying with customizable timeout and concurrency controls.
- Evaluates advisories against installed package versions using strict SemVer 2.0.0 range matching (`introduced`, `fixed`, `last_affected`, and `limit` events).
- Extracts CVSS scores, ecosystem severity, fixed versions, summaries, and references.
- Classifies vulnerability findings as `direct` or `transitive` based on dependency graph relationships.
- Guarantees isolation: network or API failures never invalidate generated SBOMs.

#### 6. Supply Chain Anomaly Detection
- Analyzes SBOM components and dependency relationships to detect supply chain smells and data inconsistencies.
- Detects missing component names, missing or non-SemVer versions, missing/invalid PURLs, PURL-metadata mismatches, and missing external references.
- Flags broken dependency edges, duplicate `bom-ref`s, circular references, and orphan components.
- Assigns severity levels (`error`, `warning`, `info`) and attaches clear, actionable explanations detailing why the issue was flagged, what was detected, and why it matters.

#### 7. SBOM Inventory Comparison & Diffing
- Compares two CycloneDX SBOM inventories (`previousBom` vs `currentBom`).
- Classifies dependency changes into `added`, `removed`, `upgrade`, `downgrade`, `metadata-changed`, and `unchanged`.
- Implements versionless canonical identity matching to pair packages across version transitions.

#### 8. Multi-File & Executive Report Generation
- Emits unified executive scan summaries (`report.json`).
- Automatically exports dedicated artifact files: `sbom.json` (CycloneDX 1.7), `vulnerabilities.json` (OSV findings), and `anomalies.json` (anomaly findings).

#### 9. Command-Line Interface (CLI)
- Provides dual binary executables: `sbom-tool` and `npm-sbom-tool`.
- Supports three primary commands:
  - **`scan`**: Inspects dependencies, supports `--full` pipeline, `--json` streaming, `--vulnerabilities`, `--anomalies`, and `--previous-sbom`.
  - **`sbom`**: Generates pure CycloneDX 1.7 SBOM with safety checks preventing manifest overwrite.
  - **`audit`**: Audits projects against OSV vulnerabilities and structural anomalies.
- Standard POSIX exit codes (`0` for success, `1` for error) with human-readable error messages on `stderr` and clean JSON on `stdout`.

### Compatibility & Requirements
- **Node.js**: `>= 18.0.0` (tested on Node.js 18, 20, and 22).
- **npm**: `>= 9.0.0`.
- **Runtime Dependencies**: `0` (Zero external dependencies; utilizes native Node.js built-in modules).
- **Development Dependencies**: `ajv` and `ajv-formats` for development/testing schema validation.

### Known Limitations
- **Ecosystem**: Limited to the `npm` ecosystem; Yarn and pnpm projects are identified and rejected.
- **Lockfile Requirement**: Complete SBOM generation requires a valid `package-lock.json`. Projects without lockfiles produce partial scan records with `bom: null`.
- **Network Dependency for Audit**: Vulnerability detection requires outbound HTTPS access to `api.osv.dev`. Offline environments record query errors gracefully without claiming zero vulnerabilities.
- **Non-SemVer Packages**: Git URLs, GitHub shortcuts, and non-SemVer tags cannot be evaluated against SemVer vulnerability ranges.
- **Publication Blocker**: Standalone `LICENSE` file is pending repository owner confirmation prior to public release on npm.

---

## Publication Release Checklist

The following release checklist tracks the preparation of `npm-sbom-tool` for npm publication:

| Item | Status | Notes |
|---|---|---|
| **README verified** | PASS | Comprehensive documentation with installation, CLI usage, options, and examples. |
| **package.json verified** | PASS | Verified `name`, `version`, `main`, `bin`, `engines`, `repository`, `bugs`, `homepage`. |
| **Runtime dependencies verified** | PASS | 0 external runtime dependencies; uses native Node.js modules. |
| **CLI executable verified** | PASS | Shebang `#!/usr/bin/env node` present; file mode executable (`chmod +x`). |
| **Package contents inspected** | PASS | `files` allowlist configured; excludes `test/`, `fixtures/`, `docs/`. |
| **npm pack successful** | PASS | Clean `.tgz` generated (21 files, ~66 kB compressed, ~293 kB unpacked). |
| **Tarball installation successful** | PASS | Installed in isolated `/tmp` directory via `npm install <tarball>`. |
| **CLI execution successful** | PASS | Verified `sbom-tool --help`, `--version`, `scan`, `sbom`, `audit` from isolated install. |
| **Automated tests successful** | PASS | Full test suite passes: 546/546 tests, 128 suites (`npm test`). |
| **Syntax verification successful** | PASS | All 19 source modules pass `node --check` (`npm run check`). |
| **Whitespace verification** | PASS | `git diff --check` passes cleanly with zero whitespace errors. |
| **Version approved** | READY | Initial release version `0.1.0` preserved. |
| **LICENSE file verified** | BLOCKED | `package.json` specifies `"license": "MIT"`, but root `LICENSE` file is missing. Needs owner authorization. |
| **npm publication permissions** | PENDING | Awaiting repository owner review and npm account credentials. |
