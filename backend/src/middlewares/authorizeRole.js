import { forbidden, unauthorized } from '../utils/errors.js';
import { extractClientIp } from '../utils/sanitize.js';

/**
 * Middleware de autorización por rol (RBAC) con denegación por defecto y auditoría.
 */
export function createAuthorizeRole({ auditService }) {
  function authorizeRole(...allowedRoles) {
    return async (req, res, next) => {
      if (!req.user) {
        return next(unauthorized('Debes iniciar sesión.', 'UNAUTHENTICATED'));
      }

      if (!allowedRoles.includes(req.user.role)) {
        await auditService.recordEvent({
          actorId: req.user.id,
          eventType: 'ADMIN_ACCESS_DENIED',
          severity: 'HIGH',
          description: `Acceso denegado a ruta protegida (${req.method} ${req.originalUrl})`,
          metadata: { requiredRoles: allowedRoles, actualRole: req.user.role },
          ipAddress: extractClientIp(req)
        });

        return next(forbidden('No tienes permisos para realizar esta acción.', 'FORBIDDEN_ROLE'));
      }

      return next();
    };
  }

  const requireAdmin = authorizeRole('admin');

  return {
    authorizeRole,
    requireAdmin
  };
}
