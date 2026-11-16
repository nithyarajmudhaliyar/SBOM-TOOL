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

  describe('API flexibility & metadata versioning', () => {
    it('supports backward-compatible positional arguments generateCycloneDX(components, edges, metadata)', () => {
      const pkgResult = parsePackageJson(path.join(fixturesDir, 'simple-project', 'package.json'));
      const lockResult = parsePackageLock(path.join(fixturesDir, 'simple-project', 'package-lock.json'));
      const resolution = resolveDependencies(pkgResult.data, lockResult.data);

      const bom = generateCycloneDX(resolution.components, resolution.dependencyEdges, pkgResult.data);

      assert.equal(bom.bomFormat, 'CycloneDX');
      assert.equal(bom.specVersion, '1.7');
      assert.equal(bom.metadata.component.name, 'simple-project');
      assert.ok(bom.components.length > 0);
      const validation = validateStructure(bom);
      assert.ok(validation.valid);
    });

    it('matches tool version with package.json dynamically', () => {
      const bom = generateBomFromFixture('simple-project');
      assert.equal(bom.metadata.tools.components[0].version, '0.1.0');
    });

    it('selects explicit rootRef even when the first component in the Map is a third-party library', () => {
      const components = new Map([
        ['pkg:npm/lodash@4.17.21', { name: 'lodash', version: '4.17.21', type: 'library', bomRef: 'pkg:npm/lodash@4.17.21', isRoot: false }],
        ['root-app', { name: 'my-app', version: '1.0.0', type: 'application', bomRef: 'root-app', isRoot: true }],
      ]);
      const edges = new Map([
        ['root-app', new Set(['pkg:npm/lodash@4.17.21'])],
      ]);

      const bom = generateCycloneDX({
        rootRef: 'root-app',
        components,
        dependencyEdges: edges,
        projectMetadata: { name: 'my-app', version: '1.0.0' },
      });

      assert.equal(bom.metadata.component.name, 'my-app');
      assert.equal(bom.metadata.component['bom-ref'], 'root-app');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0].name, 'lodash');
    });

    it('identifies root via isRoot: true when first component in Map is not the root', () => {
      const components = new Map([
        ['dep-1', { name: 'dep-first', version: '1.0.0', type: 'library', bomRef: 'dep-1', isRoot: false }],
        ['my-root', { name: 'actual-root', version: '2.0.0', type: 'application', bomRef: 'my-root', isRoot: true }],
      ]);
      const edges = new Map([
        ['my-root', new Set(['dep-1'])],
      ]);

      const bom = generateCycloneDX(components, edges);

      assert.equal(bom.metadata.component.name, 'actual-root');
      assert.equal(bom.metadata.component['bom-ref'], 'my-root');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0].name, 'dep-first');
    });

    it('identifies root via projectMetadata.name when isRoot is not present on components', () => {
      const components = new Map([
        ['dep-x', { name: 'dep-x', version: '1.0.0', type: 'library', bomRef: 'dep-x' }],
        ['proj-ref', { name: 'named-project', version: '3.0.0', type: 'application', bomRef: 'proj-ref' }],
      ]);

      const bom = generateCycloneDX({
        components,
        dependencyEdges: new Map(),
        projectMetadata: { name: 'named-project', version: '3.0.0' },
      });

      assert.equal(bom.metadata.component.name, 'named-project');
      assert.equal(bom.metadata.component['bom-ref'], 'proj-ref');
    });

    it('throws a clear error when root component is ambiguous among multiple components', () => {
      const components = new Map([
        ['comp-1', { name: 'alpha', version: '1.0.0', type: 'library', bomRef: 'comp-1' }],
        ['comp-2', { name: 'beta', version: '1.0.0', type: 'library', bomRef: 'comp-2' }],
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: new Map() }),
        /Ambiguous root component/
      );
    });

    it('throws error when multiple components declare isRoot: true', () => {
      const components = new Map([
        ['root-1', { name: 'app-1', version: '1.0.0', type: 'application', bomRef: 'root-1', isRoot: true }],
        ['root-2', { name: 'app-2', version: '1.0.0', type: 'application', bomRef: 'root-2', isRoot: true }],
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: new Map() }),
        /Ambiguous root component: multiple components marked with isRoot/
      );
    });
  });

  describe('Final Review Bug Fixes: CycloneDX Root Component Handling & Map Validation', () => {
    it('positional invocation detects the root correctly when rootRef is omitted', () => {
      const components = new Map([
        ['pkg-1', { name: 'dep-1', version: '1.0.0', type: 'library', bomRef: 'pkg-1', isRoot: false }],
        ['app-root', { name: 'my-pos-app', version: '2.0.0', type: 'application', bomRef: 'app-root', isRoot: true }],
      ]);
      const edges = new Map([['app-root', new Set(['pkg-1'])]]);

      const bom = generateCycloneDX(components, edges);
      assert.equal(bom.metadata.component['bom-ref'], 'app-root');
      assert.equal(bom.metadata.component.name, 'my-pos-app');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0].name, 'dep-1');
    });

    it('positional invocation with explicit rootRef works', () => {
      const components = new Map([
        ['lib-1', { name: 'lib-1', version: '1.0.0', type: 'library', bomRef: 'lib-1' }],
        ['app-explicit', { name: 'explicit-app', version: '1.0.0', type: 'application', bomRef: 'app-explicit' }],
      ]);
      const edges = new Map([['app-explicit', new Set(['lib-1'])]]);

      const bom = generateCycloneDX(components, edges, { name: 'explicit-app', version: '1.0.0' }, 'app-explicit');
      assert.equal(bom.metadata.component['bom-ref'], 'app-explicit');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0].name, 'lib-1');
    });

    it('positional invocation without explicit rootRef works and preserves detected root', () => {
      const components = new Map([
        ['dep-a', { name: 'dep-a', version: '1.0.0', type: 'library', bomRef: 'dep-a' }],
        ['dep-b', { name: 'named-root', version: '3.0.0', type: 'application', bomRef: 'dep-b' }],
      ]);
      const edges = new Map([['dep-b', new Set(['dep-a'])]]);

      // 3 arguments provided (4th omitted)
      const bom = generateCycloneDX(components, edges, { name: 'named-root', version: '3.0.0' });
      assert.equal(bom.metadata.component['bom-ref'], 'dep-b');
      assert.equal(bom.metadata.component.name, 'named-root');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0].name, 'dep-a');
    });

    it('destructured invocation works', () => {
      const components = new Map([
        ['lib-c', { name: 'lib-c', version: '1.0.0', type: 'library', bomRef: 'lib-c', isRoot: false }],
        ['root-c', { name: 'app-c', version: '1.0.0', type: 'application', bomRef: 'root-c', isRoot: true }],
      ]);
      const edges = new Map([['root-c', new Set(['lib-c'])]]);

      const bom = generateCycloneDX({
        rootRef: 'root-c',
        components,
        dependencyEdges: edges,
        projectMetadata: { name: 'app-c', version: '1.0.0' },
      });

      assert.equal(bom.metadata.component['bom-ref'], 'root-c');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0].name, 'lib-c');
    });

    it('root marked isRoot is excluded from bom.components', () => {
      const components = new Map([
        ['r-1', { name: 'root-app', version: '1.0.0', type: 'application', bomRef: 'r-1', isRoot: true }],
        ['l-1', { name: 'lib-1', version: '1.0.0', type: 'library', bomRef: 'l-1', isRoot: false }],
      ]);

      const bom = generateCycloneDX({ components, dependencyEdges: new Map() });
      assert.equal(bom.metadata.component['bom-ref'], 'r-1');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components.some(c => c['bom-ref'] === 'r-1'), false);
    });

    it('root identified through projectMetadata.name is excluded from bom.components', () => {
      const components = new Map([
        ['r-name', { name: 'app-by-name', version: '1.0.0', type: 'application', bomRef: 'r-name' }],
        ['l-2', { name: 'lib-2', version: '1.0.0', type: 'library', bomRef: 'l-2' }],
      ]);

      const bom = generateCycloneDX({
        components,
        dependencyEdges: new Map(),
        projectMetadata: { name: 'app-by-name', version: '1.0.0' },
      });

      assert.equal(bom.metadata.component['bom-ref'], 'r-name');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0]['bom-ref'], 'l-2');
      assert.equal(bom.components.some(c => c['bom-ref'] === 'r-name'), false);
    });

    it('root identified through the root key is excluded from bom.components', () => {
      const components = new Map([
        ['root', { name: 'key-root-app', version: '1.0.0', type: 'application', bomRef: 'root' }],
        ['l-3', { name: 'lib-3', version: '1.0.0', type: 'library', bomRef: 'l-3' }],
      ]);

      const bom = generateCycloneDX({ components, dependencyEdges: new Map() });
      assert.equal(bom.metadata.component['bom-ref'], 'root');
      assert.equal(bom.components.length, 1);
      assert.equal(bom.components[0]['bom-ref'], 'l-3');
      assert.equal(bom.components.some(c => c['bom-ref'] === 'root'), false);
    });

    it('root appears exactly once in the generated SBOM (in metadata.component only)', () => {
      const components = new Map([
        ['my-app', { name: 'singleton-app', version: '1.0.0', type: 'application', bomRef: 'my-app', isRoot: true }],
        ['lib-x', { name: 'lib-x', version: '1.0.0', type: 'library', bomRef: 'lib-x' }],
        ['lib-y', { name: 'lib-y', version: '2.0.0', type: 'library', bomRef: 'lib-y' }],
      ]);

      const bom = generateCycloneDX({ components, dependencyEdges: new Map() });
      assert.equal(bom.metadata.component.name, 'singleton-app');
      assert.equal(bom.metadata.component['bom-ref'], 'my-app');

      const matchesInComponents = bom.components.filter(c => c.name === 'singleton-app' || c['bom-ref'] === 'my-app');
      assert.equal(matchesInComponents.length, 0, 'Root must not appear in bom.components');
      assert.equal(bom.components.length, 2);
    });

    it('empty projects work and return valid BOM with synthetic root', () => {
      const bom = generateCycloneDX(new Map(), new Map(), { name: 'empty-app', version: '0.1.0' });
      assert.equal(bom.bomFormat, 'CycloneDX');
      assert.equal(bom.specVersion, '1.7');
      assert.equal(bom.metadata.component.name, 'empty-app');
      assert.equal(bom.metadata.component['bom-ref'], 'pkg:npm/empty-app@0.1.0');
      assert.equal(bom.components.length, 0);
      assert.equal(bom.dependencies.length, 0);
      const validation = validateStructure(bom);
      assert.equal(validation.valid, true);
    });

    it('empty projects without name use "root" as deterministic synthetic root reference', () => {
      const bom = generateCycloneDX(new Map(), new Map(), {});
      assert.equal(bom.bomFormat, 'CycloneDX');
      assert.equal(bom.metadata.component['bom-ref'], 'root');
      const validation = validateStructure(bom);
      assert.equal(validation.valid, true);
    });

    it('ambiguous roots throw a clear error', () => {
      const components = new Map([
        ['c1', { name: 'unrelated-1', version: '1.0.0', type: 'library', bomRef: 'c1' }],
        ['c2', { name: 'unrelated-2', version: '1.0.0', type: 'library', bomRef: 'c2' }],
      ]);

      assert.throws(
        () => generateCycloneDX(components, new Map()),
        (err) => err instanceof Error && err.message.includes('Ambiguous root component')
      );
    });

    it('the first dependency is never incorrectly selected as root', () => {
      const components = new Map([
        ['pkg:npm/first-dep@1.0.0', { name: 'first-dep', version: '1.0.0', type: 'library', bomRef: 'pkg:npm/first-dep@1.0.0' }],
        ['pkg:npm/second-dep@2.0.0', { name: 'second-dep', version: '2.0.0', type: 'library', bomRef: 'pkg:npm/second-dep@2.0.0' }],
      ]);

      // No root metadata or marker -> must throw ambiguity error, NEVER select first-dep as root
      assert.throws(
        () => generateCycloneDX(components, new Map()),
        /Ambiguous root component/
      );
    });

    it('invalid Map inputs produce clear errors', () => {
      assert.throws(
        () => generateCycloneDX('not-a-map'),
        (err) => err instanceof TypeError && err.message.includes('Invalid input')
      );

      assert.throws(
        () => generateCycloneDX({ components: 'not-a-map' }),
        (err) => err instanceof TypeError && err.message.includes('components must be an instance of Map')
      );

      assert.throws(
        () => generateCycloneDX({ components: new Map(), dependencyEdges: 'not-a-map' }),
        (err) => err instanceof TypeError && err.message.includes('dependencyEdges must be an instance of Map')
      );
    });

    it('handles root without BOM reference by using rootRef or deterministic synthetic fallback', () => {
      const components = new Map([
        ['my-app-ref', { name: 'app-no-bomref', version: '1.0.0', type: 'application', isRoot: true, bomRef: '' }],
        ['dep-1', { name: 'dep-1', version: '1.0.0', type: 'library', bomRef: 'dep-1' }],
      ]);

      const bom = generateCycloneDX(components, new Map());
      assert.ok(bom.metadata.component['bom-ref'], 'Root must have a non-empty bom-ref');
      assert.equal(bom.metadata.component['bom-ref'], 'my-app-ref');
      assert.notEqual(bom.metadata.component['bom-ref'], '');
    });

    it('generates synthetic root reference when root component and rootRef lack BOM reference', () => {
      const bom = generateCycloneDX({
        components: new Map(),
        dependencyEdges: new Map(),
        projectMetadata: { name: 'manifest-only', version: '1.2.3' },
      });

      assert.ok(bom.metadata.component['bom-ref']);
      assert.equal(bom.metadata.component['bom-ref'], 'pkg:npm/manifest-only@1.2.3');
    });

    it('throws clear error when dependency component is missing name', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
        ['bad-comp', { version: '1.0.0', type: 'library', bomRef: 'bad-comp' }], // missing name
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: new Map() }),
        (err) => err instanceof Error && err.message.includes('missing a valid non-empty name')
      );
    });

    it('throws clear error when dependency component is missing version', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
        ['bad-comp', { name: 'dep-no-ver', version: '   ', type: 'library', bomRef: 'bad-comp' }], // empty version
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: new Map() }),
        (err) => err instanceof Error && err.message.includes('missing a valid non-empty version')
      );
    });

    it('throws clear error when dependency component is missing BOM reference', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
        ['', { name: 'dep-no-ref', version: '1.0.0', type: 'library', bomRef: '' }], // empty BOM ref
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: new Map() }),
        (err) => err instanceof Error && err.message.includes('missing a valid non-empty BOM reference')
      );
    });

    it('throws clear error when duplicate component BOM references exist', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
        ['dep-1', { name: 'dep-1', version: '1.0.0', type: 'library', bomRef: 'duplicate-ref' }],
        ['dep-2', { name: 'dep-2', version: '2.0.0', type: 'library', bomRef: 'duplicate-ref' }],
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: new Map() }),
        (err) => err instanceof Error && err.message.includes('Duplicate component BOM reference')
      );
    });

    it('throws clear error when dependency edge key is invalid', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
      ]);
      const edges = new Map([
        ['', new Set(['dep-1'])], // empty edge key
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: edges }),
        (err) => err instanceof Error && err.message.includes('Invalid dependency edge key')
      );
    });

    it('throws clear error when dependency collection is not iterable', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
      ]);
      const edges = new Map([
        ['root-x', 'not-iterable-collection'],
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: edges }),
        (err) => err instanceof TypeError && err.message.includes('must be iterable')
      );
    });

    it('throws clear error when child dependency reference is invalid', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
      ]);
      const edges = new Map([
        ['root-x', new Set(['valid-ref', '   '])], // invalid child ref
      ]);

      assert.throws(
        () => generateCycloneDX({ components, dependencyEdges: edges }),
        (err) => err instanceof Error && err.message.includes('Invalid dependency reference in edge')
      );
    });

    it('preserves valid dependency relationships with deterministic sorting', () => {
      const components = new Map([
        ['root-x', { name: 'app', version: '1.0.0', type: 'application', isRoot: true, bomRef: 'root-x' }],
        ['dep-b', { name: 'dep-b', version: '1.0.0', type: 'library', bomRef: 'dep-b' }],
        ['dep-a', { name: 'dep-a', version: '1.0.0', type: 'library', bomRef: 'dep-a' }],
      ]);
      const edges = new Map([
        ['root-x', new Set(['dep-b', 'dep-a'])],
        ['dep-b', new Set(['dep-a'])],
      ]);

      const bom = generateCycloneDX({ components, dependencyEdges: edges });
      assert.equal(bom.dependencies.length, 2);
      assert.equal(bom.dependencies[0].ref, 'dep-b');
      assert.deepEqual(bom.dependencies[0].dependsOn, ['dep-a']);
      assert.equal(bom.dependencies[1].ref, 'root-x');
      assert.deepEqual(bom.dependencies[1].dependsOn, ['dep-a', 'dep-b']);
    });
  });
});
