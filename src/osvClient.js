/**
 * OSV (Open Source Vulnerabilities) API client.
 * Queries the OSV API to retrieve vulnerability information for npm packages.
 */

const OSV_API_URL = 'https://api.osv.dev/v1/query';
const OSV_BATCH_API_URL = 'https://api.osv.dev/v1/querybatch';
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_CONCURRENCY = 8;
const DEFAULT_BATCH_SIZE = 1000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_INITIAL_BACKOFF_MS = 50;
const DEFAULT_MAX_BACKOFF_MS = 5000;
const DEFAULT_MAX_DELAY_MS = 5000;

/**
 * Parses the Retry-After HTTP header value.
 * Supports integer seconds and HTTP date strings.
 *
 * @param {string|null} headerValue - Raw header string.
 * @returns {number|null} Delay in milliseconds or null if absent/unparseable.
 */
function parseRetryAfter(headerValue) {
  if (!headerValue) return null;
  const seconds = Number(headerValue);
  if (!Number.isNaN(seconds) && seconds >= 0) {
    return seconds * 1000;
  }
  const dateMs = Date.parse(headerValue);
  if (!Number.isNaN(dateMs)) {
    const diff = dateMs - Date.now();
    return diff > 0 ? diff : 0;
  }
  return null;
}

/**
 * Calculates a bounded retry delay considering Retry-After header,
 * exponential backoff, and a strict configurable maximum delay ceiling.
 *
 * @param {string|null} retryAfterHeader - Raw Retry-After header.
 * @param {number} attempt - Current retry attempt index (0-based).
 * @param {number} initialBackoffMs - Base backoff in ms.
 * @param {number} maxDelayMs - Maximum delay ceiling in ms.
 * @returns {number} Delay in milliseconds clamped to [0, maxDelayMs].
 */
function calculateRetryDelay(retryAfterHeader, attempt, initialBackoffMs, maxDelayMs) {
  const retryAfterMs = parseRetryAfter(retryAfterHeader);
  const rawDelay = retryAfterMs !== null
    ? retryAfterMs
    : (initialBackoffMs * Math.pow(2, attempt));
  return Math.min(Math.max(0, rawDelay), maxDelayMs);
}

/**
 * Delays execution for a specified duration.
 *
 * @param {number} ms - Milliseconds to sleep.
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Normalizes an integer option within bounds, falling back to a default value.
 *
 * @param {*} val - Raw option value.
 * @param {number} defaultVal - Default fallback value.
 * @param {number} [minVal=0] - Minimum allowed value.
 * @param {number} [maxVal=Infinity] - Maximum allowed value.
 * @returns {number} Normalized integer within [minVal, maxVal].
 */
function normalizeInteger(val, defaultVal, minVal = 0, maxVal = Infinity) {
  if (typeof val !== 'number' || Number.isNaN(val) || !Number.isFinite(val)) {
    return defaultVal;
  }
  const intVal = Math.floor(val);
  return Math.min(Math.max(intVal, minVal), maxVal);
}

/**
 * Error class for OSV API failures.
 */
export class OsvError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OsvError';
    this.code = code;
  }
}

/**
 * Validates package query input fields.
 *
 * @param {object} pkg - Package descriptor to validate.
 * @throws {OsvError} If input is invalid.
 */
function validatePackageInput(pkg) {
  if (!pkg || typeof pkg !== 'object') {
    throw new OsvError('INVALID_INPUT', 'Package query requires a non-null package object');
  }

  const { name, version, ecosystem = 'npm' } = pkg;

  if (typeof name !== 'string' || name.trim() === '') {
    throw new OsvError('INVALID_INPUT', 'Package name is required and must be a non-empty string');
  }

  if (typeof version !== 'string' || version.trim() === '') {
    throw new OsvError('INVALID_INPUT', 'Package version is required and must be a non-empty string');
  }

  if (typeof ecosystem !== 'string' || ecosystem.trim() === '') {
    throw new OsvError('INVALID_INPUT', 'Package ecosystem must be a non-empty string');
  }

  return {
    name: name.trim(),
    version: version.trim(),
    ecosystem: ecosystem.trim(),
  };
}

/**
 * Queries the OSV API for vulnerabilities affecting a single package.
 *
 * @param {object} pkg - Package to query.
 * @param {string} pkg.name - Package name (e.g. 'express').
 * @param {string} pkg.version - Installed version (e.g. '4.17.1').
 * @param {string} [pkg.ecosystem='npm'] - Package ecosystem.
 * @param {object} [options={}] - Query options.
 * @param {number} [options.timeoutMs=10000] - Request timeout in milliseconds.
 * @param {string} [options.apiUrl] - Optional custom OSV API endpoint URL.
 * @returns {Promise<{ package: { name: string, version: string, ecosystem: string }, vulnerabilities: object[] }>}
 */
export async function queryPackage(pkg, options = {}) {
  const validated = validatePackageInput(pkg);
  const { name, version, ecosystem } = validated;

  const timeoutMs = normalizeInteger(options.timeoutMs ?? options.timeout, DEFAULT_TIMEOUT_MS, 1);
  const apiUrl = options.apiUrl ?? OSV_API_URL;
  const maxRetries = normalizeInteger(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 100);
  const initialBackoff = normalizeInteger(options.initialBackoffMs, DEFAULT_INITIAL_BACKOFF_MS, 1);
  const maxDelay = normalizeInteger(options.maxDelayMs ?? options.maxBackoffMs, DEFAULT_MAX_DELAY_MS, 0);

  const body = JSON.stringify({
    version,
    package: { name, ecosystem },
  });

  let response;
  let attempt = 0;

  while (true) {
    try {
      response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      if (err.name === 'TimeoutError') {
        throw new OsvError('REQUEST_TIMEOUT', `OSV API request timed out for ${name}@${version}`);
      }
      throw new OsvError('NETWORK_ERROR', `OSV API request failed for ${name}@${version}: ${err.message}`);
    }

    if (response.status === 429) {
      if (attempt < maxRetries) {
        const backoffMs = calculateRetryDelay(
          response.headers?.get?.('retry-after'),
          attempt,
          initialBackoff,
          maxDelay
        );
        attempt++;
        await sleep(backoffMs);
        continue;
      }
      throw new OsvError('RATE_LIMITED', `OSV API rate limit exceeded (HTTP 429) for ${name}@${version}`);
    }

    if (!response.ok) {
      throw new OsvError('API_ERROR', `OSV API returned HTTP ${response.status} for ${name}@${version}`);
    }

    break;
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new OsvError('INVALID_RESPONSE', `OSV API returned invalid JSON for ${name}@${version}`);
  }

  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new OsvError('INVALID_RESPONSE', `OSV API returned unexpected response for ${name}@${version}`);
  }

  if (data.vulns !== undefined && !Array.isArray(data.vulns)) {
    throw new OsvError('INVALID_RESPONSE', `OSV API returned invalid vulns array for ${name}@${version}`);
  }

  const vulns = [];
  if (Array.isArray(data.vulns)) {
    for (const v of data.vulns) {
      const formatted = formatVulnerability(v);
      if (!formatted) {
        throw new OsvError('INVALID_RESPONSE', `OSV API returned malformed vulnerability record for ${name}@${version}`);
      }
      vulns.push(formatted);
    }
  }

  return {
    package: { name, version, ecosystem },
    vulnerabilities: vulns,
  };
}

/**
 * Queries the OSV API using the official /v1/querybatch endpoint.
 * Splits large inventories into safe chunks (max 1000 queries per batch),
 * respects Retry-After headers, and applies bounded exponential backoff.
 *
 * @param {Array<{ name: string, version: string, ecosystem?: string }>} packages - Packages to query.
 * @param {object} [options={}] - Options (batchSize, timeoutMs, maxRetries, etc.).
 * @returns {Promise<Array<{ package: object, vulnerabilities: object[], error?: { code: string, message: string } }>>}
 */
export async function queryBatch(packages, options = {}) {
  if (!Array.isArray(packages) || packages.length === 0) {
    return [];
  }

  const batchSize = normalizeInteger(options.batchSize, DEFAULT_BATCH_SIZE, 1, 1000);
  const timeoutMs = normalizeInteger(options.timeoutMs ?? options.timeout, DEFAULT_TIMEOUT_MS, 1);
  const apiUrl = options.batchApiUrl ?? options.apiUrl ?? OSV_BATCH_API_URL;
  const maxRetries = normalizeInteger(options.maxRetries, DEFAULT_MAX_RETRIES, 0, 100);
  const initialBackoff = normalizeInteger(options.initialBackoffMs, DEFAULT_INITIAL_BACKOFF_MS, 1);
  const maxDelay = normalizeInteger(options.maxDelayMs ?? options.maxBackoffMs, DEFAULT_MAX_DELAY_MS, 0);

  const results = new Array(packages.length);

  for (let batchStart = 0; batchStart < packages.length; batchStart += batchSize) {
    const batchEnd = Math.min(batchStart + batchSize, packages.length);
    const slice = packages.slice(batchStart, batchEnd);

    const validQueries = [];
    const validIndices = [];

    for (let i = 0; i < slice.length; i++) {
      const originalIndex = batchStart + i;
      const pkg = slice[i];
      try {
        const validated = validatePackageInput(pkg);
        validQueries.push({
          version: validated.version,
          package: {
            name: validated.name,
            ecosystem: validated.ecosystem,
          },
        });
        validIndices.push(originalIndex);
      } catch (err) {
        results[originalIndex] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: err instanceof OsvError ? err.code : 'INVALID_INPUT',
            message: err.message || 'Invalid package input',
          },
        };
      }
    }

    if (validQueries.length === 0) {
      continue;
    }

    let attempt = 0;
    let response;
    let batchError = null;

    while (true) {
      try {
        response = await fetch(apiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ queries: validQueries }),
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (err) {
        const code = err.name === 'TimeoutError' ? 'REQUEST_TIMEOUT' : 'NETWORK_ERROR';
        batchError = new OsvError(code, `OSV batch request failed: ${err.message}`);
        break;
      }

      if (response.status === 429) {
        if (attempt < maxRetries) {
          const backoffMs = calculateRetryDelay(
            response.headers?.get?.('retry-after'),
            attempt,
            initialBackoff,
            maxDelay
          );
          attempt++;
          await sleep(backoffMs);
          continue;
        }
        batchError = new OsvError('RATE_LIMITED', 'OSV API batch rate limit exceeded (HTTP 429)');
        break;
      }

      if (!response.ok) {
        batchError = new OsvError('API_ERROR', `OSV API batch returned HTTP ${response.status}`);
        break;
      }

      break;
    }

    if (batchError) {
      for (const idx of validIndices) {
        const pkg = packages[idx];
        results[idx] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: batchError.code,
            message: batchError.message,
          },
        };
      }
      continue;
    }

    let data;
    try {
      data = await response.json();
    } catch {
      for (const idx of validIndices) {
        const pkg = packages[idx];
        results[idx] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: 'INVALID_RESPONSE',
            message: 'OSV API returned invalid JSON for batch request',
          },
        };
      }
      continue;
    }

    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      for (const idx of validIndices) {
        const pkg = packages[idx];
        results[idx] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: 'INVALID_RESPONSE',
            message: 'OSV API batch response is not a valid object',
          },
        };
      }
      continue;
    }

    if (!Array.isArray(data.results)) {
      for (const idx of validIndices) {
        const pkg = packages[idx];
        results[idx] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: 'INVALID_RESPONSE',
            message: 'OSV API batch response missing results array',
          },
        };
      }
      continue;
    }

    if (data.results.length !== validQueries.length) {
      for (const idx of validIndices) {
        const pkg = packages[idx];
        results[idx] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: 'INVALID_RESPONSE',
            message: `OSV batch result count mismatch: expected ${validQueries.length}, received ${data.results.length}`,
          },
        };
      }
      continue;
    }

    for (let q = 0; q < validIndices.length; q++) {
      const originalIndex = validIndices[q];
      const pkg = packages[originalIndex];
      const resItem = data.results[q];

      if (!resItem || typeof resItem !== 'object' || Array.isArray(resItem)) {
        results[originalIndex] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: 'INVALID_RESPONSE',
            message: 'OSV API batch returned invalid result entry',
          },
        };
        continue;
      }

      if (resItem.vulns !== undefined && !Array.isArray(resItem.vulns)) {
        results[originalIndex] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: 'INVALID_RESPONSE',
            message: 'OSV API batch result contains malformed vulns property',
          },
        };
        continue;
      }

      let hasMalformedVuln = false;
      const formattedVulns = [];
      if (Array.isArray(resItem.vulns)) {
        for (const v of resItem.vulns) {
          const formatted = formatVulnerability(v);
          if (!formatted) {
            hasMalformedVuln = true;
            break;
          }
          formattedVulns.push(formatted);
        }
      }

      if (hasMalformedVuln) {
        results[originalIndex] = {
          package: {
            name: pkg?.name || 'unknown',
            version: pkg?.version || 'unknown',
            ecosystem: pkg?.ecosystem || 'npm',
          },
          vulnerabilities: [],
          error: {
            code: 'INVALID_RESPONSE',
            message: 'OSV API batch response contains malformed vulnerability entry',
          },
        };
        continue;
      }

      results[originalIndex] = {
        package: {
          name: pkg.name.trim(),
          version: pkg.version.trim(),
          ecosystem: (pkg.ecosystem || 'npm').trim(),
        },
        vulnerabilities: formattedVulns,
      };
    }
  }

  return results;
}

/**
 * Queries the OSV API for vulnerabilities affecting multiple packages concurrently.
 * Implements bounded concurrency control to prevent network exhaustion and rate limiting.
 * Individual failures do not fail the entire batch.
 *
 * @param {Array<{ name: string, version: string, ecosystem?: string }>} packages - Packages to query.
 * @param {object} [options={}] - Options (e.g., concurrency, timeoutMs, batch).
 * @returns {Promise<Array<{ package: object, vulnerabilities?: object[], error?: { code: string, message: string } }>>}
 */
export async function queryPackages(packages, options = {}) {
  if (!Array.isArray(packages) || packages.length === 0) {
    return [];
  }

  if (options.batch === true || options.useBatch === true) {
    return queryBatch(packages, options);
  }

  const concurrency = normalizeInteger(options.concurrency, DEFAULT_CONCURRENCY, 1);
  const results = new Array(packages.length);
  let currentIndex = 0;

  async function worker() {
    while (currentIndex < packages.length) {
      const idx = currentIndex++;
      const pkg = packages[idx];

      try {
        const val = await queryPackage(pkg, options);
        results[idx] = {
          status: 'fulfilled',
          value: val,
        };
      } catch (err) {
        results[idx] = {
          status: 'rejected',
          reason: err,
        };
      }
    }
  }

  const workerCount = Math.min(concurrency, packages.length);
  const workers = Array.from({ length: workerCount }, () => worker());
  await Promise.all(workers);

  return results.map((result, i) => {
    const pkg = packages[i];
    const pkgName = pkg?.name || 'unknown';
    const pkgVersion = pkg?.version || 'unknown';
    const pkgEcosystem = pkg?.ecosystem || 'npm';

    if (result.status === 'fulfilled') {
      return result.value;
    }
    const err = result.reason;
    return {
      package: { name: pkgName, version: pkgVersion, ecosystem: pkgEcosystem },
      vulnerabilities: [],
      error: {
        code: err instanceof OsvError ? err.code : 'UNKNOWN_ERROR',
        message: err?.message || 'Unknown error occurred',
      },
    };
  });
}

/**
 * Extracts and normalizes relevant fields from a raw OSV vulnerability object.
 * Preserves all metadata required for accurate vulnerability matching and reporting.
 * Safely validates inputs and handles malformed vulnerability records explicitly.
 *
 * @param {object} vuln - Raw vulnerability from OSV API.
 * @returns {object|null} Formatted vulnerability or null if malformed.
 */
function formatVulnerability(vuln) {
  if (!vuln || typeof vuln !== 'object' || Array.isArray(vuln)) {
    return null;
  }

  // 1. Validate ID (required non-empty string)
  if (typeof vuln.id !== 'string' || vuln.id.trim() === '') {
    return null;
  }

  // 2. Validate summary (optional string)
  if (vuln.summary !== undefined && vuln.summary !== null) {
    if (typeof vuln.summary !== 'string') return null;
  }

  // 3. Validate details (optional string)
  if (vuln.details !== undefined && vuln.details !== null) {
    if (typeof vuln.details !== 'string') return null;
  }

  // 4. Validate aliases (optional array of strings)
  let normalizedAliases = [];
  if (vuln.aliases !== undefined && vuln.aliases !== null) {
    if (!Array.isArray(vuln.aliases)) return null;
    for (const a of vuln.aliases) {
      if (typeof a !== 'string' || a.trim() === '') return null;
    }
    normalizedAliases = [...vuln.aliases];
  }

  // 5. Validate published, modified, schema_version (optional strings)
  if (vuln.published !== undefined && vuln.published !== null && typeof vuln.published !== 'string') {
    return null;
  }
  if (vuln.modified !== undefined && vuln.modified !== null && typeof vuln.modified !== 'string') {
    return null;
  }
  if (vuln.schema_version !== undefined && vuln.schema_version !== null && typeof vuln.schema_version !== 'string') {
    return null;
  }

  // 6. Validate database_specific (optional plain object)
  if (vuln.database_specific !== undefined && vuln.database_specific !== null) {
    if (typeof vuln.database_specific !== 'object' || Array.isArray(vuln.database_specific)) {
      return null;
    }
  }

  // 7. Validate ecosystem_specific (optional plain object)
  if (vuln.ecosystem_specific !== undefined && vuln.ecosystem_specific !== null) {
    if (typeof vuln.ecosystem_specific !== 'object' || Array.isArray(vuln.ecosystem_specific)) {
      return null;
    }
  }

  // 8. Validate references (optional array of valid objects)
  let normalizedReferences = [];
  if (vuln.references !== undefined && vuln.references !== null) {
    if (!Array.isArray(vuln.references)) return null;
    for (const ref of vuln.references) {
      if (!ref || typeof ref !== 'object' || Array.isArray(ref)) return null;
      if (typeof ref.url !== 'string' || ref.url.trim() === '') return null;
      if (ref.type !== undefined && ref.type !== null && typeof ref.type !== 'string') return null;
    }
    normalizedReferences = [...vuln.references];
  }

  // 9. Validate severity (optional array of valid objects)
  let normalizedSeverity = [];
  if (vuln.severity !== undefined && vuln.severity !== null) {
    if (!Array.isArray(vuln.severity)) return null;
    for (const s of vuln.severity) {
      if (!s || typeof s !== 'object' || Array.isArray(s)) return null;
      if (typeof s.type !== 'string' || s.type.trim() === '') return null;
      if (typeof s.score !== 'string' && typeof s.score !== 'number') return null;
    }
    normalizedSeverity = [...vuln.severity];
  }

  // 10. Validate affected (optional array of valid objects)
  let normalizedAffected = [];
  if (vuln.affected !== undefined && vuln.affected !== null) {
    if (!Array.isArray(vuln.affected)) return null;
    for (const aff of vuln.affected) {
      if (!aff || typeof aff !== 'object' || Array.isArray(aff)) return null;

      // Validate nested package descriptor
      if (aff.package !== undefined && aff.package !== null) {
        if (typeof aff.package !== 'object' || Array.isArray(aff.package)) return null;
        if (typeof aff.package.name !== 'string' || aff.package.name.trim() === '') return null;
        if (aff.package.ecosystem !== undefined && aff.package.ecosystem !== null && typeof aff.package.ecosystem !== 'string') {
          return null;
        }
      }

      // Validate nested ranges
      if (aff.ranges !== undefined && aff.ranges !== null) {
        if (!Array.isArray(aff.ranges)) return null;
        for (const r of aff.ranges) {
          if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
          if (typeof r.type !== 'string' || r.type.trim() === '') return null;

          if (r.events !== undefined && r.events !== null) {
            if (!Array.isArray(r.events)) return null;
            for (const ev of r.events) {
              if (!ev || typeof ev !== 'object' || Array.isArray(ev)) return null;
            }
          }
        }
      }

      // Validate nested versions
      if (aff.versions !== undefined && aff.versions !== null) {
        if (!Array.isArray(aff.versions)) return null;
        for (const v of aff.versions) {
          if (typeof v !== 'string' || v.trim() === '') return null;
        }
      }

      // Validate nested database_specific and ecosystem_specific
      if (aff.database_specific !== undefined && aff.database_specific !== null) {
        if (typeof aff.database_specific !== 'object' || Array.isArray(aff.database_specific)) return null;
      }
      if (aff.ecosystem_specific !== undefined && aff.ecosystem_specific !== null) {
        if (typeof aff.ecosystem_specific !== 'object' || Array.isArray(aff.ecosystem_specific)) return null;
      }
    }
    normalizedAffected = [...vuln.affected];
  }

  return {
    id: vuln.id.trim(),
    summary: typeof vuln.summary === 'string' ? vuln.summary : null,
    details: typeof vuln.details === 'string' ? vuln.details : null,
    aliases: normalizedAliases,
    published: typeof vuln.published === 'string' ? vuln.published : null,
    modified: typeof vuln.modified === 'string' ? vuln.modified : null,
    affected: normalizedAffected,
    severity: normalizedSeverity,
    references: normalizedReferences,
    database_specific: vuln.database_specific && typeof vuln.database_specific === 'object' && !Array.isArray(vuln.database_specific) ? vuln.database_specific : null,
    ecosystem_specific: vuln.ecosystem_specific && typeof vuln.ecosystem_specific === 'object' && !Array.isArray(vuln.ecosystem_specific) ? vuln.ecosystem_specific : null,
    schema_version: typeof vuln.schema_version === 'string' ? vuln.schema_version : null,
  };
}
