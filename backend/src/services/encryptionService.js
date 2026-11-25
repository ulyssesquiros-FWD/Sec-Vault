import crypto from 'node:crypto';
import { AppError } from '../utils/errors.js';

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const VERSION_REGEX = /^v[1-9]\d*$/;

/**
 * Crea el servicio criptográfico AES-256-GCM con soporte de AAD y versionado de llaves.
 * Formato de salida: `version.ivBase64.tagBase64.ciphertextBase64`
 * @param {{ activeKeyVersion: string, keyRing: Map<string, Buffer> }} cryptoConfig
 */
export function createEncryptionService({ activeKeyVersion, keyRing }) {
  if (!VERSION_REGEX.test(activeKeyVersion)) {
    throw new Error(`Versión de llave activa inválida: "${activeKeyVersion}"`);
  }
  if (!(keyRing instanceof Map) || !keyRing.has(activeKeyVersion)) {
    throw new Error(`El keyRing no contiene la llave activa "${activeKeyVersion}".`);
  }

  for (const [version, keyBuf] of keyRing.entries()) {
    if (!VERSION_REGEX.test(version)) {
      throw new Error(`Versión de llave inválida en keyRing: "${version}".`);
    }
    if (!Buffer.isBuffer(keyBuf) || keyBuf.length !== KEY_BYTES) {
      throw new Error(`La llave "${version}" debe ser un Buffer de exactamente ${KEY_BYTES} bytes.`);
    }
  }

  /**
   * Cifra un texto UTF-8 usando AES-256-GCM con IV aleatorio único de 12 bytes.
   * @param {string} plaintext
   * @param {string} [aad] Datos autenticados adicionales (ej. "note:12:owner:5")
   * @returns {string}
   */
  function encryptData(plaintext, aad) {
    if (typeof plaintext !== 'string') {
      throw new AppError('El contenido a cifrar debe ser texto.', 400, 'ENCRYPTION_INPUT_INVALID');
    }

    const activeKey = keyRing.get(activeKeyVersion);
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, activeKey, iv, { authTagLength: AUTH_TAG_BYTES });

    if (aad !== undefined && aad !== null && aad !== '') {
      cipher.setAAD(Buffer.from(String(aad), 'utf8'));
    }

    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return [
      activeKeyVersion,
      iv.toString('base64'),
      authTag.toString('base64'),
      encrypted.toString('base64')
    ].join('.');
  }

  /**
   * Analiza y valida la estructura de un payload cifrado `version.iv.tag.ciphertext`.
   * @param {string} payload
   */
  function parsePayload(payload) {
    if (typeof payload !== 'string' || !payload.trim()) {
      throw new AppError('Datos cifrados inválidos o vacíos.', 500, 'DECRYPTION_INVALID_PAYLOAD');
    }

    const parts = payload.split('.');
    if (parts.length !== 4) {
      throw new AppError('Formato de datos cifrados inválido.', 500, 'DECRYPTION_INVALID_FORMAT');
    }

    const [version, ivB64, tagB64, ciphertextB64] = parts;
    if (!VERSION_REGEX.test(version)) {
      throw new AppError('Versión de llave criptográfica inválida.', 500, 'DECRYPTION_INVALID_VERSION');
    }

    const key = keyRing.get(version);
    if (!key) {
      throw new AppError('Llave de descifrado no autorizada o faltante.', 500, 'DECRYPTION_KEY_MISSING');
    }

    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const ciphertext = Buffer.from(ciphertextB64, 'base64');

    if (iv.length !== IV_BYTES || tag.length !== AUTH_TAG_BYTES) {
      throw new AppError('Parámetros criptográficos adulterados.', 500, 'DECRYPTION_INVALID_PARAMS');
    }

    return { version, key, iv, tag, ciphertext };
  }

  /**
   * Descifra y verifica integridad/autenticidad de un payload AES-256-GCM.
   * Rechaza cualquier contenido alterado, truncado, con tag corrupto o AAD distinto.
   * @param {string} payload
   * @param {string} [aad]
   * @returns {string}
   */
  function decryptData(payload, aad) {
    const { key, iv, tag, ciphertext } = parsePayload(payload);

    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_BYTES });
      decipher.setAuthTag(tag);

      if (aad !== undefined && aad !== null && aad !== '') {
        decipher.setAAD(Buffer.from(String(aad), 'utf8'));
      }

      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return decrypted.toString('utf8');
    } catch {
      throw new AppError(
        'No fue posible autenticar o descifrar los datos protegidos.',
        500,
        'DECRYPTION_AUTH_FAILED'
      );
    }
  }

  /**
   * Extrae la versión de llave utilizada para un payload.
   * @param {string} payload
   * @returns {string | null}
   */
  function extractKeyVersion(payload) {
    if (typeof payload !== 'string') return null;
    const dotIdx = payload.indexOf('.');
    if (dotIdx <= 0) return null;
    const version = payload.slice(0, dotIdx);
    return VERSION_REGEX.test(version) ? version : null;
  }

  /**
   * Indica si el payload fue cifrado con una versión anterior a la llave activa.
   * @param {string} payload
   * @returns {boolean}
   */
  function needsReencryption(payload) {
    const version = extractKeyVersion(payload);
    return Boolean(version && version !== activeKeyVersion);
  }

  return {
    activeKeyVersion,
    encryptData,
    decryptData,
    parsePayload,
    extractKeyVersion,
    needsReencryption
  };
}
