/**
 * Error codes used throughout the SBOM scanner.
 * Each code maps to a specific failure scenario documented in the specification.
 */
export const ErrorCodes = Object.freeze({
  PROJECT_NOT_FOUND: 'PROJECT_NOT_FOUND',
  PROJECT_ACCESS_DENIED: 'PROJECT_ACCESS_DENIED',
  PACKAGE_FILE_NOT_FOUND: 'PACKAGE_FILE_NOT_FOUND',
  INVALID_PACKAGE_FILE: 'INVALID_PACKAGE_FILE',
  UNSUPPORTED_LOCKFILE_VERSION: 'UNSUPPORTED_LOCKFILE_VERSION',
  UNSUPPORTED_PACKAGE_MANAGER: 'UNSUPPORTED_PACKAGE_MANAGER',
  UNSUPPORTED_WORKSPACE_LAYOUT: 'UNSUPPORTED_WORKSPACE_LAYOUT',
  UNRESOLVED_DEPENDENCY: 'UNRESOLVED_DEPENDENCY',
  SCAN_ERROR: 'SCAN_ERROR',
});

/**
 * Scan result status values.
 */
export const ScanStatus = Object.freeze({
  COMPLETE: 'complete',
  PARTIAL: 'partial',
  FAILED: 'failed',
});

/**
 * Creates a structured error object used in scan results.
 *
 * @param {string} code - One of ErrorCodes values.
 * @param {string} message - Human-readable description of the error.
 * @param {object} [extra={}] - Additional context (file, dependency, parent, etc.).
 * @returns {{ code: string, message: string, [key: string]: any }}
 */
export function createScanError(code, message, extra = {}) {
  return { code, message, ...extra };
}

/**
 * ScanError is thrown when a fatal scanning error occurs and processing cannot continue.
 */
export class ScanError extends Error {
  /**
   * @param {string} code - Error code from ErrorCodes.
   * @param {string} message - Human-readable message.
   * @param {object} [extra={}] - Additional context.
   */
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'ScanError';
    this.code = code;
    this.details = extra;
  }
}
