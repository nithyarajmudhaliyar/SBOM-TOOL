import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { queryPackage, queryPackages, queryBatch, OsvError } from '../src/osvClient.js';

// Helper to create a mock Response
function mockResponse(body, { status = 200, ok = true } = {}) {
  return {
    ok,
    status,
    json: async () => body,
  };
}

// Helper to create a mock Response with invalid JSON
function mockInvalidJsonResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => { throw new SyntaxError('Unexpected token'); },
  };
}

describe('osvClient', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('queryPackage', () => {
    it('returns empty vulnerabilities for a clean package', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({ vulns: [] }));

      const result = await queryPackage({ name: 'express', version: '4.18.2' });

      assert.deepEqual(result.package, { name: 'express', version: '4.18.2', ecosystem: 'npm' });
      assert.deepEqual(result.vulnerabilities, []);

      // Verify the request was made correctly
      const call = globalThis.fetch.mock.calls[0];
      assert.equal(call.arguments[0], 'https://api.osv.dev/v1/query');
      const body = JSON.parse(call.arguments[1].body);
      assert.equal(body.package.name, 'express');
      assert.equal(body.package.ecosystem, 'npm');
      assert.equal(body.version, '4.18.2');
    });

    it('returns empty vulnerabilities when API returns no vulns key', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({}));

      const result = await queryPackage({ name: 'safe-pkg', version: '1.0.0' });

      assert.deepEqual(result.vulnerabilities, []);
    });

    it('returns a single vulnerability with all fields', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        vulns: [{
          id: 'GHSA-1234-5678-abcd',
          summary: 'Prototype pollution in lodash',
          details: 'Detailed description here.',
          aliases: ['CVE-2021-23337'],
          published: '2021-02-19T00:00:00Z',
          modified: '2021-03-01T00:00:00Z',
          affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [] }],
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
          references: [{ type: 'ADVISORY', url: 'https://example.com/advisory' }],
        }],
      }));

      const result = await queryPackage({ name: 'lodash', version: '4.17.20' });

      assert.equal(result.vulnerabilities.length, 1);
      const vuln = result.vulnerabilities[0];
      assert.equal(vuln.id, 'GHSA-1234-5678-abcd');
      assert.equal(vuln.summary, 'Prototype pollution in lodash');
      assert.equal(vuln.details, 'Detailed description here.');
      assert.deepEqual(vuln.aliases, ['CVE-2021-23337']);
      assert.equal(vuln.published, '2021-02-19T00:00:00Z');
      assert.equal(vuln.modified, '2021-03-01T00:00:00Z');
      assert.equal(vuln.affected.length, 1);
      assert.equal(vuln.severity.length, 1);
      assert.equal(vuln.references.length, 1);
    });

    it('returns multiple vulnerabilities', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        vulns: [
          { id: 'GHSA-aaaa', summary: 'Vuln 1' },
          { id: 'GHSA-bbbb', summary: 'Vuln 2' },
          { id: 'GHSA-cccc', summary: 'Vuln 3' },
        ],
      }));

      const result = await queryPackage({ name: 'vulnerable-pkg', version: '1.0.0' });

      assert.equal(result.vulnerabilities.length, 3);
      assert.equal(result.vulnerabilities[0].id, 'GHSA-aaaa');
      assert.equal(result.vulnerabilities[1].id, 'GHSA-bbbb');
      assert.equal(result.vulnerabilities[2].id, 'GHSA-cccc');
      // Missing fields default to null or empty arrays
      assert.equal(result.vulnerabilities[0].details, null);
      assert.deepEqual(result.vulnerabilities[0].aliases, []);
      assert.deepEqual(result.vulnerabilities[0].severity, []);
    });

    it('throws NETWORK_ERROR on fetch failure', async () => {
      globalThis.fetch = mock.fn(async () => { throw new TypeError('fetch failed'); });

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'NETWORK_ERROR');
          assert.ok(err.message.includes('pkg@1.0.0'));
          return true;
        }
      );
    });

    it('throws REQUEST_TIMEOUT on timeout', async () => {
      const timeoutErr = new DOMException('The operation was aborted due to timeout', 'TimeoutError');
      globalThis.fetch = mock.fn(async () => { throw timeoutErr; });

      await assert.rejects(
        () => queryPackage({ name: 'slow-pkg', version: '2.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'REQUEST_TIMEOUT');
          assert.ok(err.message.includes('slow-pkg@2.0.0'));
          return true;
        }
      );
    });

    it('throws API_ERROR on non-200 response', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse(null, { status: 500, ok: false }));

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'API_ERROR');
          assert.ok(err.message.includes('500'));
          return true;
        }
      );
    });

    it('throws INVALID_RESPONSE on malformed JSON', async () => {
      globalThis.fetch = mock.fn(async () => mockInvalidJsonResponse());

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_RESPONSE');
          return true;
        }
      );
    });

    it('throws INVALID_RESPONSE when API returns non-object', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse('not an object'));

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_RESPONSE');
          return true;
        }
      );
    });

    it('throws RATE_LIMITED on HTTP 429 response', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse(null, { status: 429, ok: false }));

      await assert.rejects(
        () => queryPackage({ name: 'rate-limited-pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'RATE_LIMITED');
          assert.ok(err.message.includes('rate limit exceeded'));
          return true;
        }
      );
    });

    it('throws INVALID_INPUT when package object is missing or invalid', async () => {
      await assert.rejects(
        () => queryPackage(null),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_INPUT');
          return true;
        }
      );

      await assert.rejects(
        () => queryPackage('not an object'),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_INPUT');
          return true;
        }
      );
    });

    it('throws INVALID_INPUT when name, version, or ecosystem are empty or missing', async () => {
      await assert.rejects(
        () => queryPackage({ name: '', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_INPUT');
          assert.match(err.message, /name/);
          return true;
        }
      );

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_INPUT');
          assert.match(err.message, /version/);
          return true;
        }
      );

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0', ecosystem: '   ' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_INPUT');
          assert.match(err.message, /ecosystem/);
          return true;
        }
      );
    });

    it('preserves database_specific and ecosystem_specific fields in normalized response', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        vulns: [{
          id: 'GHSA-with-db-specific',
          summary: 'DB specific vuln',
          database_specific: { severity: 'HIGH' },
          ecosystem_specific: { custom: 'data' },
          schema_version: '1.4.0',
        }],
      }));

      const result = await queryPackage({ name: 'pkg-db', version: '1.0.0' });
      assert.equal(result.vulnerabilities.length, 1);
      assert.deepEqual(result.vulnerabilities[0].database_specific, { severity: 'HIGH' });
      assert.deepEqual(result.vulnerabilities[0].ecosystem_specific, { custom: 'data' });
      assert.equal(result.vulnerabilities[0].schema_version, '1.4.0');
    });
  });

  describe('queryPackages', () => {
    it('queries multiple packages concurrently', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.package.name === 'lodash') {
          return mockResponse({ vulns: [{ id: 'GHSA-lodash', summary: 'Lodash vuln' }] });
        }
        return mockResponse({ vulns: [] });
      });

      const results = await queryPackages([
        { name: 'lodash', version: '4.17.20' },
        { name: 'express', version: '4.18.2' },
      ]);

      assert.equal(results.length, 2);
      assert.equal(results[0].vulnerabilities.length, 1);
      assert.equal(results[0].vulnerabilities[0].id, 'GHSA-lodash');
      assert.equal(results[1].vulnerabilities.length, 0);
      assert.equal(results[0].error, undefined);
      assert.equal(results[1].error, undefined);
    });

    it('handles individual failures without failing the batch', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.package.name === 'fail-pkg') {
          throw new TypeError('fetch failed');
        }
        return mockResponse({ vulns: [] });
      });

      const results = await queryPackages([
        { name: 'good-pkg', version: '1.0.0' },
        { name: 'fail-pkg', version: '2.0.0' },
      ]);

      assert.equal(results.length, 2);
      // First package succeeds
      assert.equal(results[0].error, undefined);
      assert.deepEqual(results[0].vulnerabilities, []);
      // Second package has error but doesn't throw
      assert.ok(results[1].error);
      assert.equal(results[1].error.code, 'NETWORK_ERROR');
      assert.deepEqual(results[1].package, { name: 'fail-pkg', version: '2.0.0', ecosystem: 'npm' });
      assert.deepEqual(results[1].vulnerabilities, []);
    });

    it('records INVALID_INPUT error for malformed package entry without failing others', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({ vulns: [] }));

      const results = await queryPackages([
        { name: 'valid-pkg', version: '1.0.0' },
        { name: '', version: '1.0.0' },
      ]);

      assert.equal(results.length, 2);
      assert.equal(results[0].error, undefined);
      assert.ok(results[1].error);
      assert.equal(results[1].error.code, 'INVALID_INPUT');
    });

    it('returns empty array for empty or non-array input', async () => {
      assert.deepEqual(await queryPackages([]), []);
      assert.deepEqual(await queryPackages(null), []);
      assert.deepEqual(await queryPackages(undefined), []);
    });

    it('respects concurrency limit option', async () => {
      let activeRequests = 0;
      let maxActiveRequests = 0;

      globalThis.fetch = mock.fn(async () => {
        activeRequests++;
        maxActiveRequests = Math.max(maxActiveRequests, activeRequests);
        await new Promise(r => setTimeout(r, 10));
        activeRequests--;
        return mockResponse({ vulns: [] });
      });

      const pkgList = Array.from({ length: 6 }, (_, i) => ({
        name: `pkg-${i}`,
        version: '1.0.0',
      }));

      const results = await queryPackages(pkgList, { concurrency: 2 });
      assert.equal(results.length, 6);
      assert.ok(maxActiveRequests <= 2, `maxActiveRequests ${maxActiveRequests} should be <= 2`);
    });
  });

  describe('queryBatch', () => {
    it('returns empty array for empty inventory', async () => {
      assert.deepEqual(await queryBatch([]), []);
      assert.deepEqual(await queryBatch(null), []);
      assert.deepEqual(await queryBatch(undefined), []);
    });

    it('queries OSV via /v1/querybatch and normalizes results', async () => {
      globalThis.fetch = mock.fn(async (url, opts) => {
        assert.equal(url, 'https://api.osv.dev/v1/querybatch');
        const body = JSON.parse(opts.body);
        assert.equal(body.queries.length, 2);
        assert.equal(body.queries[0].package.name, 'lodash');
        assert.equal(body.queries[1].package.name, 'express');

        return mockResponse({
          results: [
            { vulns: [{ id: 'GHSA-lodash-01', summary: 'Lodash vuln' }] },
            { vulns: [] },
          ],
        });
      });

      const results = await queryBatch([
        { name: 'lodash', version: '4.17.20' },
        { name: 'express', version: '4.18.2' },
      ]);

      assert.equal(results.length, 2);
      assert.equal(results[0].package.name, 'lodash');
      assert.equal(results[0].vulnerabilities.length, 1);
      assert.equal(results[0].vulnerabilities[0].id, 'GHSA-lodash-01');
      assert.equal(results[1].package.name, 'express');
      assert.equal(results[1].vulnerabilities.length, 0);
    });

    it('splits large package inventory across multiple batches', async () => {
      let callCount = 0;
      globalThis.fetch = mock.fn(async (_url, opts) => {
        callCount++;
        const body = JSON.parse(opts.body);
        return mockResponse({
          results: body.queries.map(() => ({ vulns: [] })),
        });
      });

      const packages = Array.from({ length: 5 }, (_, i) => ({
        name: `pkg-${i}`,
        version: '1.0.0',
      }));

      const results = await queryBatch(packages, { batchSize: 2 });
      assert.equal(results.length, 5);
      assert.equal(callCount, 3); // 2 + 2 + 1
    });

    it('handles partial batch failure for malformed package entry', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        assert.equal(body.queries.length, 1);
        return mockResponse({
          results: [{ vulns: [] }],
        });
      });

      const results = await queryBatch([
        { name: 'valid-pkg', version: '1.0.0' },
        { name: '', version: '1.0.0' }, // invalid name
      ]);

      assert.equal(results.length, 2);
      assert.equal(results[0].vulnerabilities.length, 0);
      assert.ok(results[1].error);
      assert.equal(results[1].error.code, 'INVALID_INPUT');
    });

    it('retries on HTTP 429 and succeeds when subsequent request succeeds', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        if (attempts === 1) {
          return {
            status: 429,
            ok: false,
            headers: {
              get: (header) => (header.toLowerCase() === 'retry-after' ? '0' : null),
            },
          };
        }
        return mockResponse({
          results: [{ vulns: [] }],
        });
      });

      const results = await queryBatch(
        [{ name: 'pkg-retry', version: '1.0.0' }],
        { initialBackoffMs: 10, maxRetries: 2 }
      );

      assert.equal(attempts, 2);
      assert.equal(results.length, 1);
      assert.equal(results[0].error, undefined);
    });

    it('records error when HTTP 429 retries are exhausted', async () => {
      globalThis.fetch = mock.fn(async () => ({
        status: 429,
        ok: false,
        headers: { get: () => null },
      }));

      const results = await queryBatch(
        [{ name: 'pkg-exhausted', version: '1.0.0' }],
        { initialBackoffMs: 5, maxRetries: 1 }
      );

      assert.equal(results.length, 1);
      assert.ok(results[0].error);
      assert.equal(results[0].error.code, 'RATE_LIMITED');
    });

    it('handles network timeout in batch request gracefully', async () => {
      const timeoutErr = new Error('The operation was aborted');
      timeoutErr.name = 'TimeoutError';
      globalThis.fetch = mock.fn(async () => { throw timeoutErr; });

      const results = await queryBatch(
        [{ name: 'pkg-timeout', version: '1.0.0' }],
        { timeoutMs: 50 }
      );

      assert.equal(results.length, 1);
      assert.ok(results[0].error);
      assert.equal(results[0].error.code, 'REQUEST_TIMEOUT');
    });

    it('handles malformed JSON and missing results array in API response', async () => {
      globalThis.fetch = mock.fn(async () => mockInvalidJsonResponse());

      const results = await queryBatch([{ name: 'pkg-badjson', version: '1.0.0' }]);
      assert.equal(results.length, 1);
      assert.ok(results[0].error);
      assert.equal(results[0].error.code, 'INVALID_RESPONSE');

      // Non-array results in response
      globalThis.fetch = mock.fn(async () => mockResponse({ results: 'not-an-array' }));
      const results2 = await queryBatch([{ name: 'pkg-nonarray', version: '1.0.0' }]);
      assert.equal(results2.length, 1);
      assert.ok(results2[0].error);
      assert.equal(results2[0].error.code, 'INVALID_RESPONSE');
    });

    it('supports queryPackages with options.batch = true', async () => {
      globalThis.fetch = mock.fn(async (url) => {
        assert.equal(url, 'https://api.osv.dev/v1/querybatch');
        return mockResponse({ results: [{ vulns: [] }] });
      });

      const results = await queryPackages(
        [{ name: 'batch-delegated', version: '1.0.0' }],
        { batch: true }
      );

      assert.equal(results.length, 1);
      assert.equal(results[0].package.name, 'batch-delegated');
    });

    it('clamps very large Retry-After values to maxDelayMs to prevent unbounded waits', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        if (attempts === 1) {
          return {
            status: 429,
            ok: false,
            headers: {
              get: (header) => (header.toLowerCase() === 'retry-after' ? '99999999' : null),
            },
          };
        }
        return mockResponse({
          results: [{ vulns: [] }],
        });
      });

      const startTime = Date.now();
      const results = await queryBatch(
        [{ name: 'pkg-huge-delay', version: '1.0.0' }],
        { maxDelayMs: 25, maxRetries: 2 }
      );
      const elapsed = Date.now() - startTime;

      assert.equal(attempts, 2);
      assert.equal(results.length, 1);
      assert.equal(results[0].error, undefined);
      // Confirms delay was clamped (finished in under 200ms, not 99,999,999 seconds)
      assert.ok(elapsed < 1000, `Elapsed time ${elapsed}ms should be under 1s due to clamping`);
    });

    it('clamps exponential backoff to maxDelayMs', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        if (attempts <= 2) {
          return {
            status: 429,
            ok: false,
            headers: { get: () => null },
          };
        }
        return mockResponse({
          results: [{ vulns: [] }],
        });
      });

      const startTime = Date.now();
      const results = await queryBatch(
        [{ name: 'pkg-backoff-cap', version: '1.0.0' }],
        { initialBackoffMs: 200, maxDelayMs: 20, maxRetries: 3 }
      );
      const elapsed = Date.now() - startTime;

      assert.equal(attempts, 3);
      assert.equal(results.length, 1);
      assert.ok(elapsed < 500, `Elapsed time ${elapsed}ms should be bounded`);
    });
  });

  describe('Final Review Bug Fixes: OSV Client Hardening & Batch Validation', () => {
    it('individual query retries after HTTP 429 and respects maxRetries', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        if (attempts === 1) {
          return {
            status: 429,
            ok: false,
            headers: { get: () => '0' },
          };
        }
        return mockResponse({ vulns: [] });
      });

      const res = await queryPackage({ name: 'pkg-retry-single', version: '1.0.0' }, { initialBackoffMs: 5, maxRetries: 2 });
      assert.equal(attempts, 2);
      assert.deepEqual(res.vulnerabilities, []);
    });

    it('batch query retries after HTTP 429 and respects maxRetries', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        if (attempts === 1) {
          return {
            status: 429,
            ok: false,
            headers: { get: () => '0' },
          };
        }
        return mockResponse({ results: [{ vulns: [] }] });
      });

      const res = await queryBatch([{ name: 'pkg-retry-batch', version: '1.0.0' }], { initialBackoffMs: 5, maxRetries: 2 });
      assert.equal(attempts, 2);
      assert.equal(res[0].error, undefined);
    });

    it('caps large Retry-After values to maxDelayMs for individual query', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        if (attempts === 1) {
          return {
            status: 429,
            ok: false,
            headers: { get: () => '99999999' },
          };
        }
        return mockResponse({ vulns: [] });
      });

      const start = Date.now();
      const res = await queryPackage({ name: 'pkg-delay', version: '1.0.0' }, { maxDelayMs: 20, maxRetries: 2 });
      const elapsed = Date.now() - start;
      assert.equal(attempts, 2);
      assert.ok(elapsed < 500);
      assert.deepEqual(res.vulnerabilities, []);
    });

    it('caps exponential backoff to maxDelayMs for individual query', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        if (attempts <= 2) {
          return {
            status: 429,
            ok: false,
            headers: { get: () => null },
          };
        }
        return mockResponse({ vulns: [] });
      });

      const start = Date.now();
      await queryPackage({ name: 'pkg-exp-cap', version: '1.0.0' }, { initialBackoffMs: 300, maxDelayMs: 25, maxRetries: 3 });
      const elapsed = Date.now() - start;
      assert.equal(attempts, 3);
      assert.ok(elapsed < 600);
    });

    it('bounds retry count and throws RATE_LIMITED when individual query retries are exhausted', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        return {
          status: 429,
          ok: false,
          headers: { get: () => null },
        };
      });

      await assert.rejects(
        () => queryPackage({ name: 'pkg-unbounded', version: '1.0.0' }, { initialBackoffMs: 5, maxRetries: 2 }),
        (err) => err instanceof OsvError && err.code === 'RATE_LIMITED'
      );
      assert.equal(attempts, 3); // initial attempt (0) + 2 retries (1, 2)
    });

    it('bounds retry count and returns RATE_LIMITED when batch query retries are exhausted', async () => {
      let attempts = 0;
      globalThis.fetch = mock.fn(async () => {
        attempts++;
        return {
          status: 429,
          ok: false,
          headers: { get: () => null },
        };
      });

      const res = await queryBatch([{ name: 'pkg-batch-unbounded', version: '1.0.0' }], { initialBackoffMs: 5, maxRetries: 2 });
      assert.equal(attempts, 3);
      assert.equal(res[0].error?.code, 'RATE_LIMITED');
    });

    it('batch requests contain the correct query structure', async () => {
      let capturedBody = null;
      globalThis.fetch = mock.fn(async (_url, opts) => {
        capturedBody = JSON.parse(opts.body);
        return mockResponse({ results: [{ vulns: [] }] });
      });

      await queryBatch([{ name: 'foo', version: '1.2.3', ecosystem: 'npm' }]);
      assert.ok(capturedBody);
      assert.ok(Array.isArray(capturedBody.queries));
      assert.equal(capturedBody.queries.length, 1);
      assert.deepEqual(capturedBody.queries[0], {
        version: '1.2.3',
        package: { name: 'foo', ecosystem: 'npm' },
      });
    });

    it('batch size is capped at 1000 and clamped to minimum 1', async () => {
      let batchCalls = 0;
      globalThis.fetch = mock.fn(async (_url, opts) => {
        batchCalls++;
        const body = JSON.parse(opts.body);
        assert.ok(body.queries.length <= 1000);
        return mockResponse({ results: body.queries.map(() => ({ vulns: [] })) });
      });

      // Pass batchSize 5000 (should be clamped to 1000)
      const pkgs = Array.from({ length: 3 }, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0' }));
      const res = await queryBatch(pkgs, { batchSize: 5000 });
      assert.equal(res.length, 3);
      assert.equal(batchCalls, 1);

      // Pass batchSize 0 or negative (clamped to minimum 1)
      batchCalls = 0;
      const resZero = await queryBatch(pkgs, { batchSize: 0 });
      assert.equal(resZero.length, 3);
      assert.equal(batchCalls, 3, 'When batchSize is clamped to 1, 3 packages result in 3 batches');
    });

    it('multiple chunks preserve package order and index mapping', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        return mockResponse({
          results: body.queries.map(q => ({
            vulns: [{ id: `GHSA-${q.package.name}`, summary: q.package.name }],
          })),
        });
      });

      const pkgs = [
        { name: 'p0', version: '1.0.0' },
        { name: 'p1', version: '1.0.0' },
        { name: 'p2', version: '1.0.0' },
        { name: 'p3', version: '1.0.0' },
        { name: 'p4', version: '1.0.0' },
      ];

      const res = await queryBatch(pkgs, { batchSize: 2 });
      assert.equal(res.length, 5);
      for (let i = 0; i < 5; i++) {
        assert.equal(res[i].package.name, `p${i}`);
        assert.equal(res[i].vulnerabilities[0].id, `GHSA-p${i}`);
      }
    });

    it('invalid package inputs are handled individually without aborting batch', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        assert.equal(body.queries.length, 2);
        return mockResponse({ results: [{ vulns: [] }, { vulns: [] }] });
      });

      const res = await queryBatch([
        { name: 'good-1', version: '1.0.0' },
        null,
        { name: 'good-2', version: '2.0.0' },
      ]);

      assert.equal(res.length, 3);
      assert.equal(res[0].package.name, 'good-1');
      assert.equal(res[0].error, undefined);
      assert.equal(res[1].error?.code, 'INVALID_INPUT');
      assert.equal(res[2].package.name, 'good-2');
      assert.equal(res[2].error, undefined);
    });

    it('missing results produces INVALID_RESPONSE', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({ unexpected: 'format' }));

      const res = await queryBatch([{ name: 'pkg-noresults', version: '1.0.0' }]);
      assert.equal(res.length, 1);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
      assert.match(res[0].error.message, /missing results array/);
    });

    it('fewer results than requested produces INVALID_RESPONSE', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [] }], // 1 result returned for 2 queries
      }));

      const res = await queryBatch([
        { name: 'pkg-req1', version: '1.0.0' },
        { name: 'pkg-req2', version: '1.0.0' },
      ]);

      assert.equal(res.length, 2);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
      assert.match(res[0].error.message, /result count mismatch/);
      assert.equal(res[1].error?.code, 'INVALID_RESPONSE');
      assert.match(res[1].error.message, /result count mismatch/);
    });

    it('more results than requested produces INVALID_RESPONSE', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [] }, { vulns: [] }], // 2 results returned for 1 query
      }));

      const res = await queryBatch([{ name: 'pkg-req-single', version: '1.0.0' }]);
      assert.equal(res.length, 1);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
      assert.match(res[0].error.message, /result count mismatch/);
    });

    it('malformed result entries produce structured errors', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [
          'not-an-object',
          { vulns: 'not-an-array' },
        ],
      }));

      const res = await queryBatch([
        { name: 'pkg-baditem1', version: '1.0.0' },
        { name: 'pkg-baditem2', version: '1.0.0' },
      ]);

      assert.equal(res.length, 2);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
      assert.match(res[0].error.message, /invalid result entry/);
      assert.equal(res[1].error?.code, 'INVALID_RESPONSE');
      assert.match(res[1].error.message, /malformed vulns property/);
    });

    it('malformed vulnerability entries are handled safely without crashing', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [
          {
            vulns: [
              null,
              { id: '' },
              { missingId: true },
            ],
          },
        ],
      }));

      const res = await queryBatch([{ name: 'pkg-bad-vulns', version: '1.0.0' }]);
      assert.equal(res.length, 1);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
      assert.match(res[0].error.message, /malformed vulnerability entry/);
    });

    it('a failed batch does not corrupt successful earlier batches', async () => {
      let callCount = 0;
      globalThis.fetch = mock.fn(async () => {
        callCount++;
        if (callCount === 1) {
          return mockResponse({ results: [{ vulns: [{ id: 'GHSA-batch1', summary: 'ok' }] }] });
        }
        throw new Error('Batch 2 connection dropped');
      });

      const pkgs = [
        { name: 'b1-pkg', version: '1.0.0' },
        { name: 'b2-pkg', version: '1.0.0' },
      ];

      const res = await queryBatch(pkgs, { batchSize: 1 });
      assert.equal(res.length, 2);
      assert.equal(res[0].error, undefined);
      assert.equal(res[0].vulnerabilities[0].id, 'GHSA-batch1');
      assert.equal(res[1].error?.code, 'NETWORK_ERROR');
    });

    it('no automatic individual-query fallback occurs for malformed batch responses', async () => {
      let fetchCalls = 0;
      globalThis.fetch = mock.fn(async (url) => {
        fetchCalls++;
        assert.equal(url, 'https://api.osv.dev/v1/querybatch');
        return mockResponse({ results: 'not-an-array' });
      });

      const res = await queryBatch([
        { name: 'no-fallback-1', version: '1.0.0' },
        { name: 'no-fallback-2', version: '1.0.0' },
      ]);

      assert.equal(fetchCalls, 1, 'Must NOT fall back to individual queryPackage calls');
      assert.equal(res.length, 2);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
      assert.equal(res[1].error?.code, 'INVALID_RESPONSE');
    });

    it('partial failures preserve correct package mapping', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        assert.equal(body.queries.length, 2);
        return mockResponse({
          results: [
            { vulns: [{ id: 'GHSA-pkg-a' }] },
            { vulns: [{ id: 'GHSA-pkg-c' }] },
          ],
        });
      });

      const res = await queryBatch([
        { name: 'pkg-a', version: '1.0.0' },
        { name: '', version: '1.0.0' }, // invalid input
        { name: 'pkg-c', version: '3.0.0' },
      ]);

      assert.equal(res.length, 3);
      assert.equal(res[0].package.name, 'pkg-a');
      assert.equal(res[0].vulnerabilities[0].id, 'GHSA-pkg-a');
      assert.equal(res[1].error?.code, 'INVALID_INPUT');
      assert.equal(res[2].package.name, 'pkg-c');
      assert.equal(res[2].vulnerabilities[0].id, 'GHSA-pkg-c');
    });

    it('rejects malformed affected entries with INVALID_RESPONSE', async () => {
      // 1. affected with non-object entry
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [{ id: 'GHSA-bad-aff-1', affected: ['not-an-object'] }] }],
      }));
      const res1 = await queryBatch([{ name: 'pkg-aff1', version: '1.0.0' }]);
      assert.equal(res1[0].error?.code, 'INVALID_RESPONSE');

      // 2. affected with malformed package descriptor
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [{ id: 'GHSA-bad-aff-2', affected: [{ package: 'not-an-object' }] }] }],
      }));
      const res2 = await queryBatch([{ name: 'pkg-aff2', version: '1.0.0' }]);
      assert.equal(res2[0].error?.code, 'INVALID_RESPONSE');

      // 3. affected with malformed ranges
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [{ id: 'GHSA-bad-aff-3', affected: [{ ranges: 'not-an-array' }] }] }],
      }));
      const res3 = await queryBatch([{ name: 'pkg-aff3', version: '1.0.0' }]);
      assert.equal(res3[0].error?.code, 'INVALID_RESPONSE');
    });

    it('rejects malformed severity entries with INVALID_RESPONSE', async () => {
      // severity with missing score
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [{ id: 'GHSA-bad-sev', severity: [{ type: 'CVSS_V3' }] }] }],
      }));
      const res = await queryBatch([{ name: 'pkg-sev', version: '1.0.0' }]);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
    });

    it('rejects malformed references entries with INVALID_RESPONSE', async () => {
      // reference missing url
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [{ id: 'GHSA-bad-ref', references: [{ type: 'ADVISORY' }] }] }],
      }));
      const res = await queryBatch([{ name: 'pkg-ref', version: '1.0.0' }]);
      assert.equal(res[0].error?.code, 'INVALID_RESPONSE');
    });

    it('rejects invalid database_specific and ecosystem_specific fields', async () => {
      // database_specific not a plain object
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [{ id: 'GHSA-bad-db', database_specific: 'string-not-object' }] }],
      }));
      const resDb = await queryBatch([{ name: 'pkg-db', version: '1.0.0' }]);
      assert.equal(resDb[0].error?.code, 'INVALID_RESPONSE');

      // ecosystem_specific not a plain object (e.g. array)
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{ vulns: [{ id: 'GHSA-bad-eco', ecosystem_specific: [1, 2, 3] }] }],
      }));
      const resEco = await queryBatch([{ name: 'pkg-eco', version: '1.0.0' }]);
      assert.equal(resEco[0].error?.code, 'INVALID_RESPONSE');
    });

    it('accepts valid vulnerability records with optional fields omitted', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [{
          vulns: [{
            id: 'GHSA-minimal-valid',
            // all optional fields omitted
          }],
        }],
      }));

      const res = await queryBatch([{ name: 'pkg-min', version: '1.0.0' }]);
      assert.equal(res[0].error, undefined);
      assert.equal(res[0].vulnerabilities.length, 1);
      assert.equal(res[0].vulnerabilities[0].id, 'GHSA-minimal-valid');
      assert.deepEqual(res[0].vulnerabilities[0].affected, []);
      assert.deepEqual(res[0].vulnerabilities[0].severity, []);
      assert.deepEqual(res[0].vulnerabilities[0].references, []);
      assert.equal(res[0].vulnerabilities[0].database_specific, null);
      assert.equal(res[0].vulnerabilities[0].ecosystem_specific, null);
    });

    it('exhibits same validation behavior for individual and batch queries', async () => {
      const malformedVulnPayload = {
        vulns: [{ id: 'GHSA-malformed-both', severity: 'NOT_AN_ARRAY' }],
      };

      // 1. Batch query
      globalThis.fetch = mock.fn(async () => mockResponse({
        results: [malformedVulnPayload],
      }));
      const batchRes = await queryBatch([{ name: 'pkg-parity', version: '1.0.0' }]);
      assert.equal(batchRes[0].error?.code, 'INVALID_RESPONSE');

      // 2. Individual query
      globalThis.fetch = mock.fn(async () => mockResponse(malformedVulnPayload));
      await assert.rejects(
        () => queryPackage({ name: 'pkg-parity', version: '1.0.0' }),
        (err) => err instanceof OsvError && err.code === 'INVALID_RESPONSE'
      );
    });
  });
});

