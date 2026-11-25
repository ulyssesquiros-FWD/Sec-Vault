import crypto from 'node:crypto';

/**
 * Genera un token criptográfico aleatorio de 32 bytes (64 caracteres hexadecimales).
 * @returns {string}
 */
export function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Calcula el hash SHA-256 en formato hexadecimal de un token.
 * Nunca se almacena el token plano en MySQL.
 * @param {string} rawToken
 * @returns {string}
 */
export function hashToken(rawToken) {
  if (typeof rawToken !== 'string' || !rawToken.length) {
    throw new Error('Token inválido para hash SHA-256.');
  }
  return crypto.createHash('sha256').update(rawToken, 'utf8').digest('hex');
}

/**
 * Comparación en tiempo constante para tokens/hashes de igual longitud.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length || bufA.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}
