import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import defaultGenerateSbom, {
  runEngine,
  generateSbom,
  executeSbom,
  executeAudit,
  ScanStatus,
  ErrorCodes,
  ScanError,
  createScanError,
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');

describe('SBOM Engine - Initial Entry Point & Public API', () => {
  it('accepts a target path and returns structured data via runEngine', async () => {
    const targetPath = './';
    const result = await runEngine(targetPath);

    assert.equal(typeof result, 'object');
    assert.notEqual(result, null);
    assert.equal(result.targetPath, path.resolve(targetPath));
    assert.equal(result.status, 'initialized');
    assert.equal(typeof result.timestamp, 'string');
    assert.equal(result.engine.name, 'npm-sbom-tool');
    assert.equal(result.engine.version, '0.1.0');
    assert.deepEqual(result.options, {});
    assert.equal(result.data, null);
  });

  it('accepts custom options in runEngine and preserves them', async () => {
    const options = { includeDev: true };
    const result = await runEngine('.', options);

    assert.deepEqual(result.options, { includeDev: true });
  });

  it('connects generateSbom to executeSbom and generates a valid CycloneDX SBOM', async () => {
    const projectPath = path.join(fixturesDir, 'simple-project');
    const result = await generateSbom(projectPath);

    assert.equal(result.success, true);
    assert.equal(result.status, 'complete');
    assert.ok(result.bom);
    assert.equal(result.bom.bomFormat, 'CycloneDX');
    assert.equal(result.bom.specVersion, '1.7');
    assert.equal(result.bom.metadata.component.name, 'simple-project');
    assert.ok(result.validation.valid);
  });

  it('supports default export generateSbom identical to named export', async () => {
    const projectPath = path.join(fixturesDir, 'simple-project');
    const result = await defaultGenerateSbom(projectPath);

    assert.equal(result.success, true);
    assert.equal(result.status, 'complete');
    assert.ok(result.bom);
  });

  it('propagates errors when generateSbom is run on missing or invalid project', async () => {
    const projectPath = path.join(fixturesDir, 'nonexistent-project-xyz');
    const result = await generateSbom(projectPath);

    assert.equal(result.success, false);
    assert.equal(result.bom, null);
    assert.ok(result.errors.length > 0);
  });

  it('exports ScanStatus, ErrorCodes, ScanError, and createScanError from public index', () => {
    assert.ok(ScanStatus);
    assert.equal(ScanStatus.COMPLETE, 'complete');
    assert.equal(ScanStatus.PARTIAL, 'partial');
    assert.equal(ScanStatus.FAILED, 'failed');

    assert.ok(ErrorCodes);
    assert.equal(ErrorCodes.UNSUPPORTED_LOCKFILE_VERSION, 'UNSUPPORTED_LOCKFILE_VERSION');
    assert.equal(ErrorCodes.UNSUPPORTED_PACKAGE_MANAGER, 'UNSUPPORTED_PACKAGE_MANAGER');

    assert.equal(typeof ScanError, 'function');
    const err = new ScanError(ErrorCodes.SCAN_ERROR, 'Test scan error');
    assert.equal(err.code, ErrorCodes.SCAN_ERROR);
    assert.equal(err.message, 'Test scan error');

    assert.equal(typeof createScanError, 'function');
    const structErr = createScanError(ErrorCodes.SCAN_ERROR, 'Context error', { file: 'package.json' });
    assert.equal(structErr.code, ErrorCodes.SCAN_ERROR);
    assert.equal(structErr.file, 'package.json');
  });

  it('validates that targetPath is a non-empty string in runEngine', async () => {
    await assert.rejects(
      async () => runEngine(''),
      {
        name: 'TypeError',
        message: 'Target project path must be a non-empty string'
      }
    );

    await assert.rejects(
      async () => runEngine(null),
      {
        name: 'TypeError',
        message: 'Target project path must be a non-empty string'
      }
    );

    await assert.rejects(
      async () => runEngine(123),
      {
        name: 'TypeError',
        message: 'Target project path must be a non-empty string'
      }
    );
  });

  describe('executeAudit boolean option logic', () => {
    const projectPath = path.join(fixturesDir, 'simple-project');

    it('enables both analyses when options are omitted', async () => {
      // Mock fetch so vulnerability check returns clean result
      const origFetch = globalThis.fetch;
      globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: [{ vulns: [] }, { vulns: [] }] }) });
      try {
        const report = await executeAudit(projectPath);
        assert.equal(report.success, true);
        assert.notEqual(report.vulnerabilities, null);
        assert.notEqual(report.anomalies, null);
      } finally {
        globalThis.fetch = origFetch;
      }
    });

    it('skips both analyses when { vuln: false, anomaly: false } is explicitly passed', async () => {
      const report = await executeAudit(projectPath, { vuln: false, anomaly: false });
      assert.equal(report.success, true);
      assert.equal(report.vulnerabilities, undefined);
      assert.equal(report.anomalies, undefined);
    });

    it('runs only anomaly analysis when { anomaly: true } is passed', async () => {
      const report = await executeAudit(projectPath, { anomaly: true });
      assert.equal(report.success, true);
      assert.equal(report.vulnerabilities, undefined);
      assert.notEqual(report.anomalies, null);
    });

    it('runs only vulnerability analysis when { vuln: true } is passed', async () => {
      const origFetch = globalThis.fetch;
      globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: [{ vulns: [] }, { vulns: [] }] }) });
      try {
        const report = await executeAudit(projectPath, { vuln: true });
        assert.equal(report.success, true);
        assert.notEqual(report.vulnerabilities, null);
        assert.equal(report.anomalies, undefined);
      } finally {
        globalThis.fetch = origFetch;
      }
    });

    it('supports canonical scanner options { vulnerabilities: false, anomalies: true }', async () => {
      const report = await executeAudit(projectPath, { vulnerabilities: false, anomalies: true });
      assert.equal(report.success, true);
      assert.equal(report.vulnerabilities, undefined);
      assert.notEqual(report.anomalies, null);
    });

    it('runs only anomaly analysis when { vuln: false } is explicitly passed', async () => {
      const report = await executeAudit(projectPath, { vuln: false });
      assert.equal(report.success, true);
      assert.equal(report.vulnerabilities, undefined);
      assert.notEqual(report.anomalies, null);
    });

    it('runs only vulnerability analysis when { anomaly: false } is explicitly passed', async () => {
      const origFetch = globalThis.fetch;
      globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: [{ vulns: [] }] }) });
      try {
        const report = await executeAudit(projectPath, { anomaly: false });
        assert.equal(report.success, true);
        assert.notEqual(report.vulnerabilities, null);
        assert.equal(report.anomalies, undefined);
      } finally {
        globalThis.fetch = origFetch;
      }
    });

    it('supports canonical scanner option { vulnerabilities: false } to run anomaly only', async () => {
      const report = await executeAudit(projectPath, { vulnerabilities: false });
      assert.equal(report.success, true);
      assert.equal(report.vulnerabilities, undefined);
      assert.notEqual(report.anomalies, null);
    });

    it('supports canonical scanner option { anomalies: false } to run vuln only', async () => {
      const origFetch = globalThis.fetch;
      globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: [{ vulns: [] }] }) });
      try {
        const report = await executeAudit(projectPath, { anomalies: false });
        assert.equal(report.success, true);
        assert.notEqual(report.vulnerabilities, null);
        assert.equal(report.anomalies, undefined);
      } finally {
        globalThis.fetch = origFetch;
      }
    });

    it('supports canonical scanner option { anomalies: true } to run anomaly only', async () => {
      const report = await executeAudit(projectPath, { anomalies: true });
      assert.equal(report.success, true);
      assert.equal(report.vulnerabilities, undefined);
      assert.notEqual(report.anomalies, null);
    });

    it('supports canonical scanner option { vulnerabilities: true } to run vuln only', async () => {
      const origFetch = globalThis.fetch;
      globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: [{ vulns: [] }] }) });
      try {
        const report = await executeAudit(projectPath, { vulnerabilities: true });
        assert.equal(report.success, true);
        assert.notEqual(report.vulnerabilities, null);
        assert.equal(report.anomalies, undefined);
      } finally {
        globalThis.fetch = origFetch;
      }
    });
  });
});

