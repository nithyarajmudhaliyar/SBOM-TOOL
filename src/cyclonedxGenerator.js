import crypto from 'node:crypto';

/**
 * Generates a CycloneDX 1.7 compliant JSON SBOM from the internal scan result.
 *
 * @param {object} scanResult - The internal scan result containing components, edges, and metadata.
 * @param {string} scanResult.rootRef - The bom-ref of the root application component.
 * @param {Map<string, object>} scanResult.components - Map of bomRef → component data.
 * @param {Map<string, Set<string>>} scanResult.dependencyEdges - Map of bomRef → Set of child bomRefs.
 * @param {object} scanResult.projectMetadata - The parsed package.json data of the scanned project.
 * @returns {object} A CycloneDX 1.7 JSON BOM object.
 */
export function generateCycloneDX(scanResult) {
  const { rootRef, components, dependencyEdges, projectMetadata } = scanResult;

  const rootComponent = components.get(rootRef);

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
            version: '0.1.0',
          },
        ],
      },
      component: {
        type: 'application',
        name: rootComponent.name,
        version: rootComponent.version,
        'bom-ref': rootComponent.bomRef,
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
  for (const [bomRef, comp] of components) {
    if (comp.isRoot) continue;

    const cdxComponent = {
      type: 'library',
      name: comp.name,
      version: comp.version,
      'bom-ref': comp.bomRef,
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
  for (const [bomRef, deps] of dependencyEdges) {
    const depEntry = {
      ref: bomRef,
      dependsOn: [...deps].sort(),
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
