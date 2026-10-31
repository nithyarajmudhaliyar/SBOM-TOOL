import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePackageJson, parsePackageLock } from '../src/parser.js';
import { resolveDependencies } from '../src/dependencyResolver.js';
import { generateCycloneDX } from '../src/cyclonedxGenerator.js';
import { validateStructure } from '../src/validator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');

/**
 * Helper to generate a CycloneDX BOM from a fixture.
 */
function generateBomFromFixture(fixtureName) {
  const pkgResult = parsePackageJson(path.join(fixturesDir, fixtureName, 'package.json'));
  const lockResult = parsePackageLock(path.join(fixturesDir, fixtureName, 'package-lock.json'));
  assert.equal(pkgResult.errors.length, 0);
  assert.equal(lockResult.errors.length, 0);

  const resolution = resolveDependencies(pkgResult.data, lockResult.data);
  return generateCycloneDX({
    rootRef: resolution.rootRef,
    components: resolution.components,
    dependencyEdges: resolution.dependencyEdges,
    projectMetadata: pkgResult.data,
  });
}

describe('CycloneDX Generator', () => {
  describe('BOM structure', () => {
    it('generates valid top-level CycloneDX fields', () => {
      const bom = generateBomFromFixture('simple-project');

      assert.equal(bom.bomFormat, 'CycloneDX');
      assert.equal(bom.specVersion, '1.7');
      assert.equal(bom.version, 1);
      assert.ok(bom.serialNumber.startsWith('urn:uuid:'), 'serialNumber should be a URN UUID');
      assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    });

    it('includes metadata with timestamp and tool info', () => {
      const bom = generateBomFromFixture('simple-project');

      assert.ok(bom.metadata);
      assert.ok(bom.metadata.timestamp);
      assert.ok(bom.metadata.tools);
      assert.ok(bom.metadata.tools.components);
      assert.equal(bom.metadata.tools.components[0].name, 'npm-sbom-tool');
    });

    it('includes root application component in metadata', () => {
      const bom = generateBomFromFixture('simple-project');

      assert.ok(bom.metadata.component);
      assert.equal(bom.metadata.component.type, 'application');
      assert.equal(bom.metadata.component.name, 'simple-project');
      assert.equal(bom.metadata.component.version, '1.0.0');
      assert.ok(bom.metadata.component['bom-ref']);
      assert.ok(bom.metadata.component.purl);
    });

    it('includes lifecycle phase', () => {
      const bom = generateBomFromFixture('simple-project');

      assert.ok(bom.metadata.lifecycles);
      assert.equal(bom.metadata.lifecycles[0].phase, 'build');
    });
  });

  describe('Components', () => {
    it('represents npm packages as library components', () => {
      const bom = generateBomFromFixture('simple-project');

      assert.ok(bom.components.length > 0);
      for (const comp of bom.components) {
        assert.equal(comp.type, 'library');
      }
    });

    it('includes correct component details', () => {
      const bom = generateBomFromFixture('simple-project');

      const isOdd = bom.components.find(c => c.name === 'is-odd');
      assert.ok(isOdd);
      assert.equal(isOdd.version, '3.0.1');
      assert.ok(isOdd['bom-ref']);
      assert.ok(isOdd.purl);
    });

    it('does not include root component in components array', () => {
      const bom = generateBomFromFixture('simple-project');

      const root = bom.components.find(c => c.name === 'simple-project');
      assert.equal(root, undefined, 'Root should not be in components array');
    });

    it('includes hashes from integrity information', () => {
      const bom = generateBomFromFixture('simple-project');

      const isOdd = bom.components.find(c => c.name === 'is-odd');
      assert.ok(isOdd.hashes, 'is-odd should have hashes');
      assert.ok(isOdd.hashes.length > 0);
      assert.ok(isOdd.hashes[0].alg);
      assert.ok(isOdd.hashes[0].content);
    });

    it('includes external references for resolved URLs', () => {
      const bom = generateBomFromFixture('simple-project');

      const isOdd = bom.components.find(c => c.name === 'is-odd');
      assert.ok(isOdd.externalReferences, 'is-odd should have external references');
      assert.equal(isOdd.externalReferences[0].type, 'distribution');
      assert.ok(isOdd.externalReferences[0].url.includes('registry.npmjs.org'));
    });
  });

  describe('Dependencies', () => {
    it('generates dependency relationship entries for all components', () => {
      const bom = generateBomFromFixture('simple-project');

      assert.ok(bom.dependencies.length > 0);
      // Each component + root should have a dependency entry
      assert.equal(bom.dependencies.length, 3); // root, is-odd, is-number
    });

    it('root depends on direct dependencies', () => {
      const bom = generateBomFromFixture('simple-project');

      const rootDep = bom.dependencies.find(d => d.ref.includes('simple-project'));
      assert.ok(rootDep, 'Root dependency entry should exist');
      assert.ok(rootDep.dependsOn.length > 0);
      assert.ok(rootDep.dependsOn.some(r => r.includes('is-odd')));
    });

    it('transitive dependencies are represented through parent edges', () => {
      const bom = generateBomFromFixture('simple-project');

      const isOddDep = bom.dependencies.find(d => d.ref.includes('is-odd'));
      assert.ok(isOddDep);
      assert.ok(isOddDep.dependsOn.some(r => r.includes('is-number')));
    });

    it('leaf nodes have empty dependsOn arrays', () => {
      const bom = generateBomFromFixture('simple-project');

      const isNumberDep = bom.dependencies.find(d => d.ref.includes('is-number'));
      assert.ok(isNumberDep);
      assert.deepEqual(isNumberDep.dependsOn, []);
    });

    it('does NOT add custom direct/transitive fields to CycloneDX components', () => {
      const bom = generateBomFromFixture('simple-project');

      for (const comp of bom.components) {
        assert.equal(comp.dependencyType, undefined, 'dependencyType should not be in CycloneDX output');
        assert.equal(comp.dependencyGroups, undefined, 'dependencyGroups should not be in CycloneDX output');
      }
    });
  });

  describe('Complex fixtures', () => {
    it('generates correct BOM for transitive-project', () => {
      const bom = generateBomFromFixture('transitive-project');

      // 4 library components: accepts, mime-types, mime-db, negotiator
      assert.equal(bom.components.length, 4);

      // Verify accepts → mime-types edge
      const acceptsDep = bom.dependencies.find(d => d.ref.includes('accepts'));
      assert.ok(acceptsDep);
      assert.ok(acceptsDep.dependsOn.some(r => r.includes('mime-types')));
      assert.ok(acceptsDep.dependsOn.some(r => r.includes('negotiator')));
    });

    it('generates correct BOM for scoped packages', () => {
      const bom = generateBomFromFixture('scoped-package-project');

      const babelCore = bom.components.find(c => c.name === '@babel/core');
      assert.ok(babelCore);
      assert.ok(babelCore.purl.includes('%40babel'));
    });

    it('generates BOM with multiple versions of same package', () => {
      const bom = generateBomFromFixture('multiple-versions-project');

      const sharedDeps = bom.components.filter(c => c.name === 'shared-dep');
      assert.equal(sharedDeps.length, 2, 'Both versions should be in components');
    });
  });

  describe('Structural validation', () => {
    it('passes structural validation for simple-project', () => {
      const bom = generateBomFromFixture('simple-project');
      const validation = validateStructure(bom);
      assert.ok(validation.valid, `Validation errors: ${validation.errors.join(', ')}`);
    });

    it('passes structural validation for transitive-project', () => {
      const bom = generateBomFromFixture('transitive-project');
      const validation = validateStructure(bom);
      assert.ok(validation.valid, `Validation errors: ${validation.errors.join(', ')}`);
    });

    it('passes structural validation for mixed-dependencies-project', () => {
      const bom = generateBomFromFixture('mixed-dependencies-project');
      const validation = validateStructure(bom);
      assert.ok(validation.valid, `Validation errors: ${validation.errors.join(', ')}`);
    });
  });
});
