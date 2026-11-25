import { timingSafeCompare } from '../services/tokenService.js';
import { forbidden } from '../utils/errors.js';
import { extractClientIp } from '../utils/sanitize.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Protege operaciones mutantes contra CSRF verificando el token ligado a la sesión
 * mediante comparación en tiempo constante (`X-CSRF-Token`).
 */
export function createCsrfProtection({ auditService }) {
  return async function csrfProtection(req, res, next) {
    if (SAFE_METHODS.has(req.method)) {
      return next();
    }

    const sessionToken = req.session?.csrfToken;
    const headerToken = req.get('X-CSRF-Token') || '';

    if (!sessionToken || !timingSafeCompare(String(headerToken), String(sessionToken))) {
      await auditService?.recordEvent({
        actorId: req.session?.userId || null,
        eventType: 'CSRF_VALIDATION_FAILED',
        severity: 'WARNING',
        description: `Fallo de validación CSRF en ${req.method} ${req.originalUrl}`,
        metadata: { hasSessionToken: Boolean(sessionToken) },
        ipAddress: extractClientIp(req)
      });

      return next(forbidden('Token CSRF inválido o ausente.', 'CSRF_INVALID'));
    }

    return next();
  };
}

/**
 * Exige cabecera Content-Type application/json en endpoints públicos de autenticación
 * para prevenir envío directo mediante formularios HTML cross-origin simples.
 */
export function requireJsonContentType(req, res, next) {
  if (SAFE_METHODS.has(req.method)) {
    return next();
  }
  if (!req.is('application/json')) {
    return next(forbidden('Content-Type application/json requerido.', 'JSON_CONTENT_TYPE_REQUIRED'));
  }
  return next();
}
