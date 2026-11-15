import path from 'node:path';
import { scanProject } from '../scanner/index.js';
import { ScanStatus } from '../errors.js';
import {
  generateReport,
  generateReportFiles,
  buildCombinedReport,
  writeMultiFileOutput,
  computeSeverityCounts,
} from '../reportGenerator.js';

export {
  generateReport,
  generateReportFiles,
  buildCombinedReport,
  writeMultiFileOutput,
  computeSeverityCounts,
};

/**
 * Initializes and runs the SBOM engine against a specified target project path.
 * Retained for backward compatibility.
 *
 * @param {string} targetPath - Relative or absolute path to the target project to analyze.
 * @param {object} [options={}] - Optional configuration options for the analysis.
 * @returns {Promise<object>} Structured data object representing engine status and target metadata.
 */
export async function runEngine(targetPath, options = {}) {
  if (typeof targetPath !== 'string' || targetPath.trim() === '') {
    throw new TypeError('Target project path must be a non-empty string');
  }

  const resolvedPath = path.resolve(targetPath);

  return {
    targetPath: resolvedPath,
    status: 'initialized',
    timestamp: new Date().toISOString(),
    engine: {
      name: 'npm-sbom-tool',
      version: '0.1.0'
    },
    options,
    data: null
  };
}

/**
 * Generates a complete, validated CycloneDX SBOM for an npm project.
 * Aliases executeSbom for a consistent and intuitive public API.
 *
 * @param {string} projectPath - Path to project directory.
 * @param {object} [options={}] - Scan and generation options.
 * @returns {Promise<object>} Result containing success boolean, bom, and diagnostic info.
 */
export const generateSbom = executeSbom;

/**
 * Connects the 'scan' command workflow to the engine.
 *
 * @param {string} projectPath - Path to project directory.
 * @param {object} [options={}] - Options (e.g. full, vulnerabilities, previousSbom).
 * @returns {Promise<object>} Scan result.
 */
export async function executeScan(projectPath, options = {}) {
  const scanOpts = { ...options };

  if (options.full) {
    scanOpts.vulnerabilities = true;
    scanOpts.anomalies = true;
  }

  if (options.previousSbom && !scanOpts.previousBom) {
    scanOpts.previousBom = options.previousSbom;
  }

  return await scanProject(projectPath, scanOpts);
}

/**
 * Connects the 'sbom' command workflow to the engine.
 * Generates a CycloneDX SBOM document without running vulnerability or anomaly analysis.
 *
 * @param {string} projectPath - Path to project directory.
 * @param {object} [options={}] - Options.
 * @returns {Promise<object>} Result containing success boolean, bom, and diagnostic info.
 */
export async function executeSbom(projectPath, options = {}) {
  // sbom command generates CycloneDX SBOM; no vulnerability or anomaly analysis
  const scanOpts = {
    ...options,
    vulnerabilities: false,
    anomalies: false,
  };

  const result = await scanProject(projectPath, scanOpts);

  if (result.status === ScanStatus.FAILED) {
    return {
      success: false,
      status: result.status,
      bom: null,
      errors: result.errors,
      warnings: result.warnings,
      projectMetadata: result.projectMetadata,
      message: 'Scan failed. Unable to generate CycloneDX SBOM.',
    };
  }

  if (result.status === ScanStatus.PARTIAL || !result.bom) {
    return {
      success: false,
      status: result.status,
      bom: null,
      errors: result.errors,
      warnings: result.warnings,
      projectMetadata: result.projectMetadata,
      message: 'Cannot generate CycloneDX SBOM for partial scan (package-lock.json is required).',
    };
  }

  if (result.validation && !result.validation.valid) {
    return {
      success: false,
      status: result.status,
      bom: result.bom,
      validation: result.validation,
      errors: result.errors,
      warnings: result.warnings,
      projectMetadata: result.projectMetadata,
      message: 'Generated CycloneDX SBOM failed validation.',
    };
  }

  return {
    success: true,
    status: result.status,
    bom: result.bom,
    validation: result.validation,
    errors: result.errors,
    warnings: result.warnings,
    projectMetadata: result.projectMetadata,
  };
}

/**
 * Connects the 'audit' command workflow to the engine.
 * Performs vulnerability and anomaly analysis, distinguishing findings.
 *
 * @param {string} projectPath - Path to project directory.
 * @param {object} [options={}] - Options (e.g. vuln, anomaly, previousSbom).
 * @returns {Promise<object>} Audit report object.
 */
export async function executeAudit(projectPath, options = {}) {
  // Support both CLI flags (vuln, anomaly) and canonical scanner options (vulnerabilities, anomalies)
  const hasVuln = options.vuln !== undefined
    ? Boolean(options.vuln)
    : (options.vulnerabilities !== undefined ? Boolean(options.vulnerabilities) : undefined);
  const hasAnomaly = options.anomaly !== undefined
    ? Boolean(options.anomaly)
    : (options.anomalies !== undefined ? Boolean(options.anomalies) : undefined);

  let runVuln;
  let runAnomaly;

  if (hasVuln === undefined && hasAnomaly === undefined) {
    // Neither specified: default to running both analyses
    runVuln = true;
    runAnomaly = true;
  } else if (hasVuln !== undefined && hasAnomaly !== undefined) {
    // Both explicitly specified: respect both exact boolean flags
    runVuln = hasVuln;
    runAnomaly = hasAnomaly;
  } else if (hasVuln !== undefined) {
    // Only vuln is specified:
    // If true, focus on vuln only (disables unspecified anomaly analysis).
    // If false, exclude vuln (runs remaining anomaly analysis).
    runVuln = hasVuln;
    runAnomaly = !hasVuln;
  } else {
    // Only anomaly is specified:
    // If true, focus on anomaly only (disables unspecified vuln analysis).
    // If false, exclude anomaly (runs remaining vuln analysis).
    runAnomaly = hasAnomaly;
    runVuln = !hasAnomaly;
  }

  const scanOpts = {
    ...options,
    vulnerabilities: runVuln,
    anomalies: runAnomaly,
  };

  if (options.previousSbom && !scanOpts.previousBom) {
    scanOpts.previousBom = options.previousSbom;
  }

  const scanResult = await scanProject(projectPath, scanOpts);
  const resolvedProject = scanResult.projectPath || path.resolve(projectPath);

  if (scanResult.status === ScanStatus.FAILED) {
    return {
      success: false,
      project: {
        name: scanResult.projectMetadata?.name || path.basename(resolvedProject),
        version: scanResult.projectMetadata?.version || '0.0.0',
        path: resolvedProject,
      },
      summary: { dependenciesScanned: 0 },
      status: 'failed',
      errors: scanResult.errors,
      warnings: scanResult.warnings,
      vulnerabilities: null,
      anomalies: null,
      comparison: null,
    };
  }

  const components = Array.isArray(scanResult.components) ? scanResult.components : [];
  const scannedDepsCount = components.filter(c => !c.isRoot).length;

  let overallStatus = 'completed';
  if (scanResult.status === ScanStatus.PARTIAL) {
    overallStatus = 'partial';
  } else if (scanResult.vulnerabilities && (scanResult.vulnerabilities.status === 'failed' || scanResult.vulnerabilities.status === 'partial')) {
    overallStatus = scanResult.vulnerabilities.status;
  }

  const report = {
    success: true,
    project: {
      name: scanResult.projectMetadata?.name || path.basename(resolvedProject),
      version: scanResult.projectMetadata?.version || '0.0.0',
      path: resolvedProject,
    },
    summary: {
      dependenciesScanned: scannedDepsCount,
    },
    status: overallStatus,
    scanStatus: scanResult.status,
  };

  if (runVuln) {
    if (scanResult.vulnerabilities) {
      report.summary.vulnerabilitiesFound = scanResult.vulnerabilities.findings?.length || 0;
      report.vulnerabilities = {
        status: scanResult.vulnerabilities.status,
        scannedPackages: scanResult.vulnerabilities.scannedPackages,
        totalPackages: scanResult.vulnerabilities.totalPackages,
        vulnerablePackages: scanResult.vulnerabilities.vulnerablePackages,
        findings: scanResult.vulnerabilities.findings || [],
        warnings: scanResult.vulnerabilities.warnings || [],
        errors: scanResult.vulnerabilities.errors || [],
      };
    } else {
      report.vulnerabilities = null;
    }
  }

  if (runAnomaly) {
    if (scanResult.anomalies) {
      report.summary.anomaliesFound = scanResult.anomalies.summary?.total || 0;
      report.anomalies = {
        total: scanResult.anomalies.summary?.total || 0,
        bySeverity: scanResult.anomalies.summary?.bySeverity || { error: 0, warning: 0, info: 0 },
        byType: scanResult.anomalies.summary?.byType || {},
        findings: scanResult.anomalies.findings || [],
      };
    } else {
      report.anomalies = null;
    }
  }

  if (scanResult.comparison) {
    report.summary.comparison = scanResult.comparison.summary;
    report.comparison = scanResult.comparison;
  }

  return report;
}

export default generateSbom;
