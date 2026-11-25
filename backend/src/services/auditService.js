const FORBIDDEN_METADATA_KEYS = new Set([
  'password',
  'newpassword',
  'currentpassword',
  'passwordhash',
  'password_hash',
  'token',
  'rawtoken',
  'resettoken',
  'csrftoken',
  'secret',
  'totpsecret',
  'mfasecret',
  'cookie',
  'cookies',
  'key',
  'encryptionkey',
  'content',
  'decryptedcontent',
  'phone',
  'authorization'
]);

/**
 * Elimina recursivamente campos sensibles antes de persistir o loguear metadatos.
 * @param {unknown} value
 * @returns {unknown}
 */
export function sanitizeAuditMetadata(value) {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeAuditMetadata(item));
  }
  if (typeof value === 'object') {
    const clean = {};
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN_METADATA_KEYS.has(k.toLowerCase())) {
        clean[k] = '[REDACTED]';
      } else {
        clean[k] = sanitizeAuditMetadata(v);
      }
    }
    return clean;
  }
  if (typeof value === 'string') {
    return value.slice(0, 300);
  }
  return value;
}

/**
 * Servicio centralizado de auditoría de eventos de seguridad (MySQL + Pino JSON).
 */
export function createAuditService(securityEventRepository, logger) {
  async function recordEvent({
    actorId = null,
    eventType,
    severity = 'INFO',
    description,
    metadata = null,
    ipAddress = null
  }) {
    const safeMetadata = sanitizeAuditMetadata(metadata);
    const safeDescription = String(description || eventType).slice(0, 500);

    logger?.info(
      {
        audit: true,
        actorId,
        eventType,
        severity,
        ipAddress,
        metadata: safeMetadata
      },
      safeDescription
    );

    try {
      await securityEventRepository.create({
        actorId,
        eventType,
        severity,
        description: safeDescription,
        metadata: safeMetadata,
        ipAddress
      });
    } catch (err) {
      logger?.error(
        { errCode: err?.code, eventType },
        'No se pudo persistir el evento de seguridad en MySQL'
      );
    }
  }

  return {
    recordEvent
  };
}
