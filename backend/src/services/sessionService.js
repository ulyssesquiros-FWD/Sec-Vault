import { generateSecureToken } from './tokenService.js';

/**
 * Regenera el identificador de sesión para prevenir Session Fixation.
 * @param {import('express').Request} req
 * @returns {Promise<void>}
 */
export function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      return resolve();
    });
  });
}

/**
 * Guarda explícitamente los cambios de la sesión en el almacenamiento MySQL.
 * @param {import('express').Request} req
 * @returns {Promise<void>}
 */
export function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) return reject(err);
      return resolve();
    });
  });
}

/**
 * Destruye completamente la sesión actual en el almacenamiento MySQL.
 * @param {import('express').Request} req
 * @returns {Promise<void>}
 */
export function destroySession(req) {
  return new Promise((resolve, reject) => {
    if (!req.session) return resolve();
    req.session.destroy((err) => {
      if (err) return reject(err);
      return resolve();
    });
  });
}

/**
 * Regenera y establece la sesión autenticada completa con token CSRF nuevo.
 * @param {import('express').Request} req
 * @param {{ id: number, role: string, sessionVersion: number }} user
 */
export async function establishAuthenticatedSession(req, user) {
  await regenerateSession(req);
  const now = Date.now();
  req.session.userId = Number(user.id);
  req.session.role = user.role;
  req.session.sessionVersion = Number(user.sessionVersion ?? 1);
  req.session.csrfToken = generateSecureToken(32);
  req.session.createdAt = now;
  req.session.lastActivityAt = now;
  await saveSession(req);
  return req.session.csrfToken;
}

/**
 * Establece una sesión temporal previa al segundo factor MFA (sin acceso a la API protegida).
 * @param {import('express').Request} req
 * @param {number} userId
 */
export async function establishPendingMfaSession(req, userId) {
  await regenerateSession(req);
  const now = Date.now();
  req.session.pendingMfaUserId = Number(userId);
  req.session.pendingMfaExpiresAt = now + 5 * 60 * 1000;
  req.session.csrfToken = generateSecureToken(32);
  req.session.createdAt = now;
  req.session.lastActivityAt = now;
  await saveSession(req);
  return req.session.csrfToken;
}

/**
 * Verifica si la sesión expiró por inactividad o por límite absoluto de vida.
 * @param {import('express-session').Session & Record<string, any>} session
 * @param {{ idleTimeoutMs: number, absoluteTimeoutMs: number }} sessionConfig
 * @param {number} [now]
 */
export function isSessionExpired(session, sessionConfig, now = Date.now()) {
  if (!session) return true;
  const createdAt = Number(session.createdAt || 0);
  const lastActivityAt = Number(session.lastActivityAt || 0);

  if (!createdAt || !lastActivityAt) return true;
  if (now - createdAt > sessionConfig.absoluteTimeoutMs) return true;
  if (now - lastActivityAt > sessionConfig.idleTimeoutMs) return true;
  return false;
}
