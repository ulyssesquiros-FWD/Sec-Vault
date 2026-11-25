import crypto from 'node:crypto';
import QRCode from 'qrcode';
import { hashToken, timingSafeCompare } from './tokenService.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;

/**
 * Codifica un Buffer a Base32 (RFC 4648 sin padding).
 * @param {Buffer} buffer
 * @returns {string}
 */
export function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decodifica una cadena Base32 a Buffer.
 * @param {string} base32
 * @returns {Buffer}
 */
export function base32Decode(base32) {
  const clean = String(base32).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error('Secreto TOTP Base32 inválido.');
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Genera un secreto TOTP criptográfico de 160 bits en Base32.
 * @returns {string}
 */
export function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/**
 * Construye la URI estándar otpauth:// para apps autenticadoras.
 */
export function buildOtpAuthUri({ secret, email, issuer = 'SecureVault' }) {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_STEP_SECONDS)
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Genera una imagen QR en Data URL (PNG base64) compatible con CSP `img-src 'self' data:`.
 * @param {string} otpAuthUri
 * @returns {Promise<string>}
 */
export async function generateQrDataUrl(otpAuthUri) {
  return QRCode.toDataURL(otpAuthUri, {
    width: 220,
    margin: 2,
    errorCorrectionLevel: 'M'
  });
}

/**
 * Calcula un código TOTP RFC 6238 de 6 dígitos para un instante determinado.
 */
export function generateTotpCode(secretBase32, timestampMs = Date.now(), stepOffset = 0) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(timestampMs / 1000 / TOTP_STEP_SECONDS) + stepOffset;
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 10 ** TOTP_DIGITS;
  return String(otp).padStart(TOTP_DIGITS, '0');
}

/**
 * Verifica un código TOTP permitiendo ventana de deriva de ±1 paso (±30 segundos).
 */
export function verifyTotpCode(secretBase32, candidateCode, window = 1, timestampMs = Date.now()) {
  const normalized = String(candidateCode || '').trim();
  if (!/^\d{6}$/.test(normalized)) {
    return false;
  }

  for (let offset = -window; offset <= window; offset += 1) {
    const expected = generateTotpCode(secretBase32, timestampMs, offset);
    if (timingSafeCompare(normalized, expected)) {
      return true;
    }
  }
  return false;
}

/**
 * Genera códigos de recuperación de un solo uso y sus hashes SHA-256.
 * @param {number} [count]
 */
export function generateRecoveryCodes(count = 8) {
  const plainCodes = [];
  const hashedCodes = [];

  for (let i = 0; i < count; i += 1) {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase();
    const formatted = `${raw.slice(0, 5)}-${raw.slice(5)}`;
    plainCodes.push(formatted);
    hashedCodes.push(hashToken(formatted));
  }

  return { plainCodes, hashedCodes };
}

/**
 * Normaliza y valida un código de recuperación contra la lista de hashes almacenados.
 * @param {string} candidateCode
 * @param {string[]} storedHashes
 * @returns {{ matched: boolean, remainingHashes: string[] }}
 */
export function consumeRecoveryCode(candidateCode, storedHashes) {
  if (!Array.isArray(storedHashes) || storedHashes.length === 0) {
    return { matched: false, remainingHashes: [] };
  }
  const normalized = String(candidateCode || '').trim().toUpperCase();
  if (!/^[A-F0-9]{5}-[A-F0-9]{5}$/.test(normalized)) {
    return { matched: false, remainingHashes: storedHashes };
  }
  const candidateHash = hashToken(normalized);
  let matchedIdx = -1;

  for (let i = 0; i < storedHashes.length; i += 1) {
    if (timingSafeCompare(candidateHash, storedHashes[i])) {
      matchedIdx = i;
      break;
    }
  }

  if (matchedIdx === -1) {
    return { matched: false, remainingHashes: storedHashes };
  }

  const remainingHashes = storedHashes.filter((_, idx) => idx !== matchedIdx);
  return { matched: true, remainingHashes };
}
