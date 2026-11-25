import bcrypt from 'bcrypt';
import { AppError } from '../utils/errors.js';

export const MIN_SALT_ROUNDS = 12;
export const MAX_BCRYPT_BYTES = 72;

// Hash bcrypt sintético válido (costo 12) para igualar tiempos ante correos inexistentes
const DUMMY_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKxGhu6D6rYx0C/rO4k8rQ5H1j6H0qS0L9V6.';

/**
 * Genera un hash seguro con bcrypt (mínimo 12 rondas).
 * Rechaza contraseñas vacías o que superen el límite de 72 bytes UTF-8 sin truncamiento silencioso.
 * @param {string} password
 * @param {number} [rounds]
 * @returns {Promise<string>}
 */
export async function hashPassword(password, rounds = MIN_SALT_ROUNDS) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new AppError('Contraseña inválida.', 400, 'INVALID_PASSWORD');
  }

  const byteLength = Buffer.byteLength(password, 'utf8');
  if (byteLength > MAX_BCRYPT_BYTES) {
    throw new AppError(
      'La contraseña excede el límite máximo de 72 bytes UTF-8 permitido por bcrypt.',
      400,
      'PASSWORD_TOO_LONG'
    );
  }

  const cost = Number(rounds);
  if (!Number.isInteger(cost) || cost < MIN_SALT_ROUNDS || cost > 15) {
    throw new Error(`El factor de costo de bcrypt debe ser un entero entre ${MIN_SALT_ROUNDS} y 15.`);
  }

  return bcrypt.hash(password, cost);
}

/**
 * Verifica una contraseña contra un hash bcrypt en tiempo constante.
 * @param {string} password
 * @param {string} passwordHash
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, passwordHash) {
  if (typeof password !== 'string' || typeof passwordHash !== 'string' || !passwordHash) {
    return false;
  }

  if (Buffer.byteLength(password, 'utf8') > MAX_BCRYPT_BYTES) {
    return false;
  }

  return bcrypt.compare(password, passwordHash);
}

/**
 * Extrae el factor de costo de un hash bcrypt ($2a$12$..., $2b$12$...).
 * @param {string} passwordHash
 * @returns {number | null}
 */
export function getHashRounds(passwordHash) {
  if (typeof passwordHash !== 'string') return null;
  const match = passwordHash.match(/^\$2[abxy]\$(\d{2})\$/);
  return match ? Number(match[1]) : null;
}

/**
 * Ejecuta una comparación bcrypt ficticia para mitigar enumeración de usuarios por tiempo.
 * @param {string} candidatePassword
 */
export async function dummyVerify(candidatePassword = 'DummyPassword#123') {
  const safeInput =
    typeof candidatePassword === 'string' && Buffer.byteLength(candidatePassword, 'utf8') <= MAX_BCRYPT_BYTES
      ? candidatePassword
      : 'DummyPassword#123';
  await bcrypt.compare(safeInput, DUMMY_HASH);
}
