import { destroySession, isSessionExpired } from '../services/sessionService.js';
import { unauthorized } from '../utils/errors.js';

/**
 * Autentica al usuario exclusivamente a partir de la sesión persistida en MySQL.
 * Valida expiración por inactividad, duración máxima absoluta y `session_version`.
 */
export function createAuthenticateUser({ userRepository, config }) {
  return async function authenticateUser(req, res, next) {
    try {
      if (!req.session) {
        return next(unauthorized('Sesión no iniciada.', 'SESSION_MISSING'));
      }

      if (!req.session.userId) {
        if (req.session.pendingMfaUserId) {
          return next(unauthorized('Verificación MFA requerida.', 'MFA_REQUIRED'));
        }
        return next(unauthorized('Debes iniciar sesión para acceder a este recurso.', 'UNAUTHENTICATED'));
      }

      if (isSessionExpired(req.session, config.session)) {
        await destroySession(req).catch(() => {});
        res.clearCookie('secvault.sid', { path: '/' });
        return next(unauthorized('Tu sesión ha expirado. Inicia sesión nuevamente.', 'SESSION_EXPIRED'));
      }

      const user = await userRepository.findById(req.session.userId);
      if (!user || Number(user.session_version) !== Number(req.session.sessionVersion)) {
        await destroySession(req).catch(() => {});
        res.clearCookie('secvault.sid', { path: '/' });
        return next(unauthorized('Sesión invalidada. Inicia sesión nuevamente.', 'SESSION_REVOKED'));
      }

      req.session.lastActivityAt = Date.now();
      req.user = {
        id: Number(user.id),
        name: user.name,
        email: user.email,
        role: user.role,
        sessionVersion: Number(user.session_version),
        mfaEnabled: Boolean(user.mfa_enabled),
        createdAt: user.created_at,
        updatedAt: user.updated_at
      };

      return next();
    } catch (err) {
      return next(err);
    }
  };
}
