/**
 * Validates a generated CycloneDX BOM against structural requirements.
 * For full JSON Schema validation, the ajv library with the official schema is used.
 *
 * This module provides both a basic structural validator and a full schema validator.
 */

/**
 * Performs basic structural validation of a CycloneDX BOM object.
 * This does not replace full JSON Schema validation but catches common issues.
 *
 * @param {object} bom - The CycloneDX BOM object to validate.
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateStructure(bom) {
  const errors = [];

  if (!bom || typeof bom !== 'object') {
    errors.push('BOM must be a non-null object.');
    return { valid: false, errors };
  }

  // Required top-level fields
  if (bom.bomFormat !== 'CycloneDX') {
    errors.push(`bomFormat must be "CycloneDX", got "${bom.bomFormat}".`);
  }

  if (!bom.specVersion || typeof bom.specVersion !== 'string') {
    errors.push('specVersion is required and must be a string.');
  }

  if (bom.version !== undefined && (typeof bom.version !== 'number' || bom.version < 1)) {
    errors.push('version must be an integer >= 1.');
  }

  if (bom.serialNumber !== undefined) {
    const uuidPattern = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    if (!uuidPattern.test(bom.serialNumber)) {
      errors.push(`serialNumber must match RFC 4122 URN format, got "${bom.serialNumber}".`);
    }
  }

  // Components validation
  if (bom.components !== undefined) {
    if (!Array.isArray(bom.components)) {
      errors.push('components must be an array.');
    } else {
      const bomRefs = new Set();
      for (let i = 0; i < bom.components.length; i++) {
        const comp = bom.components[i];
        if (!comp.type) {
          errors.push(`components[${i}] is missing required field "type".`);
        }
        if (!comp.name) {
          errors.push(`components[${i}] is missing required field "name".`);
        }
        if (comp['bom-ref']) {
          if (bomRefs.has(comp['bom-ref'])) {
            errors.push(`Duplicate bom-ref: "${comp['bom-ref']}".`);
          }
          bomRefs.add(comp['bom-ref']);
        }
      }
    }
  }

  // Dependencies validation
  if (bom.dependencies !== undefined) {
    if (!Array.isArray(bom.dependencies)) {
      errors.push('dependencies must be an array.');
    } else {
      for (let i = 0; i < bom.dependencies.length; i++) {
        const dep = bom.dependencies[i];
        if (!dep.ref) {
          errors.push(`dependencies[${i}] is missing required field "ref".`);
        }
        if (!Array.isArray(dep.dependsOn)) {
          errors.push(`dependencies[${i}] must have a "dependsOn" array.`);
        }
      }
    }
  }

  // Metadata validation
  if (bom.metadata) {
    if (bom.metadata.component) {
      if (!bom.metadata.component.type) {
        errors.push('metadata.component is missing required field "type".');
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validates a CycloneDX BOM against the official CycloneDX 1.7 JSON Schema
 * using the ajv JSON Schema validator.
 *
 * @param {object} bom - The CycloneDX BOM object to validate.
 * @param {object} schema - The CycloneDX JSON Schema object.
 * @returns {Promise<{ valid: boolean, errors: Array<object|string> }>}
 */
export async function validateAgainstSchema(bom, schema) {
  try {
    // Dynamic import of ajv — only needed when schema validation is requested
    const { default: Ajv2020 } = await import('ajv/dist/2020.js');
    const { default: addFormats } = await import('ajv-formats');

    const ajv = new Ajv2020({
      strict: false,
      allErrors: true,
      validateFormats: true,
    });
    addFormats(ajv);

    const validate = ajv.compile(schema);
    const valid = validate(bom);

    return {
      valid,
      errors: valid ? [] : validate.errors.map(e => ({
        path: e.instancePath,
        message: e.message,
        params: e.params,
      })),
    };
  } catch (err) {
    return {
      valid: false,
      errors: [`Schema validation failed: ${err.message}`],
    };
  }
}
