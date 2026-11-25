const encoder = new TextEncoder();

export function getUtf8ByteLength(value) {
  return encoder.encode(value || '').length;
}

/**
 * Evalúa las reglas de contraseña alineadas con backend Zod y bcrypt (<= 72 bytes UTF-8).
 */
export function evaluatePasswordPolicy(password) {
  const str = typeof password === 'string' ? password : '';
  const byteLength = getUtf8ByteLength(str);

  const checks = {
    minLength: str.length >= 12,
    maxBytes: byteLength <= 72,
    hasUpper: /[A-Z]/.test(str),
    hasLower: /[a-z]/.test(str),
    hasNumber: /[0-9]/.test(str),
    hasSymbol: /[^A-Za-z0-9]/.test(str)
  };

  const valid =
    checks.minLength &&
    checks.maxBytes &&
    checks.hasUpper &&
    checks.hasLower &&
    checks.hasNumber &&
    checks.hasSymbol;

  return {
    checks,
    byteLength,
    valid
  };
}
