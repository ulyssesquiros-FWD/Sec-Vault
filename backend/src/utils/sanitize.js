/**
 * Normaliza un correo electrónico para almacenamiento y búsqueda consistente.
 * @param {string} email
 * @returns {string}
 */
export function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

/**
 * Extrae la IP del cliente respetando la configuración `trust proxy` de Express.
 * @param {import('express').Request} req
 * @returns {string}
 */
export function extractClientIp(req) {
  const rawIp = req?.ip || req?.socket?.remoteAddress || 'unknown';
  return String(rawIp).slice(0, 45);
}

/**
 * Elimina caracteres de control ASCII excepto saltos de línea y tabuladores estándar.
 * @param {string} value
 * @returns {string}
 */
export function stripControlChars(value) {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

/**
 * Enmascara un número telefónico dejando visibles únicamente los últimos 4 dígitos.
 * Ejemplo: "+506 8812-3456" -> "***-***-3456"
 * @param {string | null | undefined} phone
 * @returns {string}
 */
export function maskPhone(phone) {
  if (typeof phone !== 'string' || !phone.trim()) {
    return '***';
  }
  const digits = phone.replace(/\D/g, '');
  if (digits.length < 4) {
    return '***';
  }
  const last4 = digits.slice(-4);
  return `***-***-${last4}`;
}
