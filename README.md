# npm-sbom-tool

A lightweight, reusable JavaScript engine and tool for generating Software Bill of Materials (SBOM) from npm projects.

## Project Structure

```text
├── package.json          # Project metadata, dependencies, and scripts
├── .gitignore            # Git ignore configuration
├── README.md             # Project documentation and setup guide
├── src/
│   ├── index.js          # Main library entry point
│   ├── engine/           # Reusable SBOM engine core
│   │   └── index.js      # Initial engine implementation (entry point)
│   └── scanner/          # npm dependency scanner (Phase 2+)
│       └── index.js      # Scanner module stub
└── test/
    └── engine.test.js    # Unit tests for the engine
```

## Prerequisites

- **Node.js**: v18.0.0 or later (Node.js 20+ recommended)
- **npm**: v9.0.0 or later

## Installation

Install dependencies (if any are added) using npm:

```bash
npm install
```

## Available Scripts

- **`npm test`**: Runs the test suite using Node.js's built-in test runner (`node --test`).
- **`npm run check`**: Runs syntax validation checks across all source and test JavaScript files using `node --check`.

## Programmatic Usage

The core engine is decoupled from UI, CLI, or database layers and can be imported and consumed programmatically:

```javascript
import { runEngine, generateSbom } from 'npm-sbom-tool';

const result = await runEngine('./path/to/target-project');
console.log(result);
// Output structure:
// {
//   targetPath: '/absolute/path/to/target-project',
//   status: 'initialized',
//   timestamp: '2026-10-31T...',
//   engine: { name: 'npm-sbom-tool', version: '0.1.0' },
//   options: {},
//   data: null
// }
```

## Upcoming Phases

- **Phase 2**: Target project scanning (`package.json`, `package-lock.json`, `node_modules`).
- **Phase 3**: Dependency tree parsing and graph construction.
- **Phase 4**: SBOM standard format output (CycloneDX / SPDX).
- **Phase 5**: Vulnerability and anomaly detection.
- **Phase 6**: CLI and Web UI layers.

