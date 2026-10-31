import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { runEngine, generateSbom } from '../src/index.js';

describe('SBOM Engine - Initial Entry Point', () => {
  it('accepts a target path and returns structured data', async () => {
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

  it('accepts custom options and preserves them in structured output', async () => {
    const options = { includeDev: true };
    const result = await runEngine('.', options);

    assert.deepEqual(result.options, { includeDev: true });
  });

  it('aliases generateSbom to runEngine', async () => {
    const result = await generateSbom('.');
    assert.equal(result.status, 'initialized');
    assert.equal(result.targetPath, path.resolve('.'));
  });

  it('validates that targetPath is a non-empty string', async () => {
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
});

