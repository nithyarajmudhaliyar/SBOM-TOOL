import crypto from 'node:crypto';
import fs from 'node:fs';

let cachedToolVersion = null;
function getToolVersion() {
  if (cachedToolVersion !== null) return cachedToolVersion;
  try {
    const pkgJsonPath = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    cachedToolVersion = pkg.version || '0.1.0';
  } catch {
    cachedToolVersion = '0.1.0';
  }
  return cachedToolVersion;
}

/**
 * Generates a CycloneDX 1.7 compliant JSON SBOM from the internal scan result.
 *
 * Supports both destructured object input:
 *   generateCycloneDX({ rootRef, components, dependencyEdges, projectMetadata })
 * and backward-compatible positional input:
 *   generateCycloneDX(components, dependencyEdges, projectMetadata, rootRef)
 *
 * @param {object|Map<string, object>} scanResultOrComponents - Scan result object or Map of components.
 * @param {Map<string, Set<string>>} [maybeDependencyEdges] - Dependency edges when called positionally.
 * @param {object} [maybeProjectMetadata] - Project metadata when called positionally.
 * @param {string} [maybeRootRef] - Root ref when called positionally.
 * @returns {object} A CycloneDX 1.7 JSON BOM object.
 */
export function generateCycloneDX(scanResultOrComponents, maybeDependencyEdges, maybeProjectMetadata, maybeRootRef) {
  let rootRef;
  let explicitRootRef = null;
  let components;
  let dependencyEdges;
  let projectMetadata;
  let toolVersionOverride;

  if (scanResultOrComponents instanceof Map) {
    // Positional invocation: (components, dependencyEdges, projectMetadata, rootRef)
    components = scanResultOrComponents;
    dependencyEdges = maybeDependencyEdges || new Map();
    projectMetadata = maybeProjectMetadata || {};
    if (typeof maybeRootRef === 'string' && maybeRootRef.trim() !== '') {
      rootRef = maybeRootRef.trim();
      explicitRootRef = rootRef;
    }
  } else if (scanResultOrComponents && typeof scanResultOrComponents === 'object') {
    // Destructured options invocation: { rootRef, components, dependencyEdges, projectMetadata }
    const input = scanResultOrComponents;
    if (typeof input.rootRef === 'string' && input.rootRef.trim() !== '') {
      rootRef = input.rootRef.trim();
      explicitRootRef = rootRef;
    }
    components = input.components || new Map();
    dependencyEdges = input.dependencyEdges || new Map();
    projectMetadata = input.projectMetadata || {};
    toolVersionOverride = input.toolVersion;
  } else if (scanResultOrComponents === undefined || scanResultOrComponents === null) {
    components = new Map();
    dependencyEdges = new Map();
    projectMetadata = {};
  } else {
    throw new TypeError('Invalid input: components must be an instance of Map or an options object');
  }

  if (!(components instanceof Map)) {
    throw new TypeError('Invalid input: components must be an instance of Map');
  }

  if (!(dependencyEdges instanceof Map)) {
    throw new TypeError('Invalid input: dependencyEdges must be an instance of Map');
  }

  if (!projectMetadata || typeof projectMetadata !== 'object') {
    projectMetadata = {};
  }

  // Identify rootRef if not explicitly provided
  if (!rootRef) {
    // 1. Identify components marked explicitly with isRoot === true
    const isRootCandidates = [];
    for (const [ref, comp] of components.entries()) {
      if (comp && comp.isRoot === true) {
        isRootCandidates.push(ref);
      }
    }

    if (isRootCandidates.length === 1) {
      rootRef = isRootCandidates[0];
    } else if (isRootCandidates.length > 1) {
      throw new Error(`Ambiguous root component: multiple components marked with isRoot (${isRootCandidates.join(', ')}).`);
    } else {
      // 2. Identify candidate matching reliable projectMetadata name
      const metaName = typeof projectMetadata?.name === 'string' ? projectMetadata.name.trim() : null;
      if (metaName) {
        const nameCandidates = [];
        for (const [ref, comp] of components.entries()) {
          if (comp && comp.name === metaName) {
            nameCandidates.push(ref);
          }
        }
        if (nameCandidates.length === 1) {
          rootRef = nameCandidates[0];
        } else if (nameCandidates.length > 1) {
          throw new Error(`Ambiguous root component: multiple components match project name "${metaName}".`);
        }
      }

      // 3. Fallback to component with ref === 'root'
      if (!rootRef && components.has('root')) {
        rootRef = 'root';
      }

      // 4. If components is empty, default rootRef remains null/synthetic
      // 5. If multiple components exist and no root could be reliably identified, do NOT guess the first component
      if (!rootRef && components.size > 0) {
        throw new Error('Ambiguous root component: unable to identify root component. Please provide an explicit rootRef or ensure a component is marked with isRoot.');
      }
    }
  }

  const existingRoot = components && rootRef ? components.get(rootRef) : null;
  const rootComponent = existingRoot || {
    name: projectMetadata?.name || 'unknown',
    version: projectMetadata?.version || '0.0.0',
    bomRef: rootRef || (projectMetadata?.name ? `pkg:npm/${projectMetadata.name}@${projectMetadata.version || '0.0.0'}` : 'root'),
    purl: projectMetadata?.name ? `pkg:npm/${projectMetadata.name}@${projectMetadata.version || '0.0.0'}` : undefined,
  };

  // Ensure root component always has a non-empty string bom-ref
  // Priority: 1. rootComponent.bomRef, 2. rootRef, 3. synthetic root reference
  let finalRootBomRef = null;
  if (existingRoot && typeof existingRoot.bomRef === 'string' && existingRoot.bomRef.trim() !== '') {
    finalRootBomRef = existingRoot.bomRef.trim();
  } else if (existingRoot && typeof existingRoot['bom-ref'] === 'string' && existingRoot['bom-ref'].trim() !== '') {
    finalRootBomRef = existingRoot['bom-ref'].trim();
  } else if (typeof explicitRootRef === 'string' && explicitRootRef.trim() !== '') {
    finalRootBomRef = explicitRootRef.trim();
  } else if (typeof rootRef === 'string' && rootRef.trim() !== '' && components.has(rootRef)) {
    finalRootBomRef = rootRef.trim();
  } else if (typeof projectMetadata?.name === 'string' && projectMetadata.name.trim() !== '') {
    finalRootBomRef = `pkg:npm/${projectMetadata.name.trim()}@${projectMetadata.version || '0.0.0'}`;
  } else {
    finalRootBomRef = 'root';
  }

  const toolVersion = toolVersionOverride || getToolVersion();

  // Generate a unique serial number conforming to RFC 4122
  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'npm-sbom-tool',
            version: toolVersion,
          },
        ],
      },
      component: {
        type: 'application',
        name: rootComponent.name,
        version: rootComponent.version,
        'bom-ref': finalRootBomRef,
        purl: rootComponent.purl,
      },
      lifecycles: [
        {
          phase: 'build',
        },
      ],
    },
    components: [],
    dependencies: [],
  };

  // Add project description if available
  if (projectMetadata.description) {
    bom.metadata.component.description = projectMetadata.description;
  }

  // Build the components array (excluding the root — it goes in metadata.component)
  const seenComponentBomRefs = new Set();
  seenComponentBomRefs.add(finalRootBomRef);

  for (const [bomRefKey, comp] of components) {
    if (bomRefKey === rootRef || comp?.isRoot || comp?.bomRef === rootRef || comp?.bomRef === finalRootBomRef) {
      continue;
    }

    if (!comp || typeof comp !== 'object' || Array.isArray(comp)) {
      throw new Error(`Invalid component: component entry for "${bomRefKey}" must be an object.`);
    }

    if (typeof comp.name !== 'string' || comp.name.trim() === '') {
      throw new Error(`Invalid component: component "${bomRefKey}" is missing a valid non-empty name.`);
    }

    if (typeof comp.version !== 'string' || comp.version.trim() === '') {
      throw new Error(`Invalid component: component "${comp.name.trim()}" is missing a valid non-empty version.`);
    }

    const compBomRef =
      (typeof comp.bomRef === 'string' && comp.bomRef.trim() !== '') ? comp.bomRef.trim() :
      (typeof comp['bom-ref'] === 'string' && comp['bom-ref'].trim() !== '') ? comp['bom-ref'].trim() :
      (typeof bomRefKey === 'string' && bomRefKey.trim() !== '') ? bomRefKey.trim() :
      null;

    if (!compBomRef) {
      throw new Error(`Invalid component: component "${comp.name.trim()}" is missing a valid non-empty BOM reference.`);
    }

    if (seenComponentBomRefs.has(compBomRef)) {
      throw new Error(`Duplicate component BOM reference: "${compBomRef}" is used by multiple components.`);
    }
    seenComponentBomRefs.add(compBomRef);

    const cdxComponent = {
      type: 'library',
      name: comp.name.trim(),
      version: comp.version.trim(),
      'bom-ref': compBomRef,
    };

    // Add purl if available
    if (comp.purl) {
      cdxComponent.purl = comp.purl;
    }

    // Add hashes from integrity field (subresource integrity format: algorithm-base64hash)
    if (comp.integrity) {
      const hashes = parseIntegrity(comp.integrity);
      if (hashes.length > 0) {
        cdxComponent.hashes = hashes;
      }
    }

    // Add external references (resolved URL)
    if (comp.resolved) {
      cdxComponent.externalReferences = [
        {
          type: 'distribution',
          url: comp.resolved,
        },
      ];
    }

    bom.components.push(cdxComponent);
  }

  // Sort components by bom-ref for deterministic output
  bom.components.sort((a, b) => a['bom-ref'].localeCompare(b['bom-ref']));

  // Build the dependencies array
  for (const [edgeKey, deps] of dependencyEdges) {
    if (typeof edgeKey !== 'string' || edgeKey.trim() === '') {
      throw new Error(`Invalid dependency edge key: edge key must be a non-empty string, got "${edgeKey}".`);
    }

    if (!deps || typeof deps !== 'object' || typeof deps[Symbol.iterator] !== 'function') {
      throw new TypeError(`Invalid dependency edge: dependency collection for "${edgeKey}" must be iterable.`);
    }

    const trimmedDeps = [];
    for (const depRef of deps) {
      if (typeof depRef !== 'string' || depRef.trim() === '') {
        throw new Error(`Invalid dependency reference in edge "${edgeKey}": reference must be a non-empty string.`);
      }
      trimmedDeps.push(depRef.trim());
    }

    const depEntry = {
      ref: edgeKey.trim(),
      dependsOn: Array.from(new Set(trimmedDeps)).sort(),
    };
    bom.dependencies.push(depEntry);
  }

  // Sort dependencies by ref for deterministic output
  bom.dependencies.sort((a, b) => a.ref.localeCompare(b.ref));

  return bom;
}

/**
 * Parses an npm subresource integrity string into CycloneDX hash entries.
 *
 * Integrity strings look like: "sha512-abc123..." or "sha1-xyz... sha512-abc..."
 *
 * @param {string} integrity - The integrity string from the lockfile.
 * @returns {Array<{alg: string, content: string}>} CycloneDX-compatible hash entries.
 */
function parseIntegrity(integrity) {
  const hashes = [];
  const parts = integrity.split(/\s+/);

  const algMap = {
    'sha1': 'SHA-1',
    'sha256': 'SHA-256',
    'sha384': 'SHA-384',
    'sha512': 'SHA-512',
  };

  for (const part of parts) {
    const dashIndex = part.indexOf('-');
    if (dashIndex === -1) continue;

    const algorithm = part.substring(0, dashIndex).toLowerCase();
    const hash = part.substring(dashIndex + 1);
    const cdxAlg = algMap[algorithm];

    if (cdxAlg && hash) {
      // Convert base64 hash to hex for CycloneDX
      const hexHash = Buffer.from(hash, 'base64').toString('hex');
      hashes.push({ alg: cdxAlg, content: hexHash });
    }
  }

  return hashes;
}
