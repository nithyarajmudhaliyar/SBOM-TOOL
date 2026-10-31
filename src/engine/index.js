import path from 'node:path';

/**
 * Initializes and runs the SBOM engine against a specified target project path.
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
 * Alias for runEngine to provide an intuitive domain-specific naming.
 */
export const generateSbom = runEngine;

export default runEngine;

