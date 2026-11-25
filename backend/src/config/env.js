import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_ENV_PATH = path.resolve(__dirname, '../../../.env');
const BACKEND_ENV_PATH = path.resolve(__dirname, '../../.env');

const PLACEHOLDER_PATTERNS = [
  'changeme',
  'change-me',
  'replace-me',
  'replace_me',
  'example',
  'placeholder',
  'secret-key',
  'super-secret',
  'password',
  '12345678'
];

function looksLikePlaceholder(value) {
  if (!value) return true;
  const lower = value.toLowerCase();
  if (/^(.)\1{15,}$/.test(lower)) return true; // Ej. "0000000000000000..."
  return PLACEHOLDER_PATTERNS.some((pattern) => lower.includes(pattern));
}

function parseBooleanEnv(val, defaultValue = false) {
  if (val === undefined || val === null || val === '') return defaultValue;
  const norm = String(val).trim().toLowerCase();
  if (norm === 'true' || norm === '1') return true;
  if (norm === 'false' || norm === '0') return false;
  throw new Error(`Valor booleano inválido en variable de entorno: "${val}"`);
}

function parseTrustProxy(val, isProduction) {
  if (val === undefined || val === null || val === '') {
    return isProduction ? 1 : false;
  }
  const norm = String(val).trim().toLowerCase();
  if (norm === 'false') return false;
  if (norm === 'true') return true;
  const num = Number(norm);
  if (Number.isInteger(num) && num >= 0 && num <= 10) {
    return num;
  }
  throw new Error(`TRUST_PROXY inválido: "${val}". Usa false, true o un entero entre 0 y 10.`);
}

function parsePreviousEncryptionKeys(raw, activeVersion) {
  const keys = new Map();
  if (!raw || !String(raw).trim()) {
    return keys;
  }

  const entries = String(raw)
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  for (const entry of entries) {
    const sepIdx = entry.indexOf(':');
    if (sepIdx === -1) {
      throw new Error('DATA_ENCRYPTION_PREVIOUS_KEYS debe tener formato "v1:<64hex>,v2:<64hex>".');
    }
    const version = entry.slice(0, sepIdx).trim();
    const hexKey = entry.slice(sepIdx + 1).trim();

    if (!/^v[1-9]\d*$/.test(version)) {
      throw new Error(`Versión de llave previa inválida: "${version}".`);
    }
    if (version === activeVersion) {
      throw new Error(`La versión "${version}" no puede repetirse entre activa y previas.`);
    }
    if (!/^[0-9a-fA-F]{64}$/.test(hexKey)) {
      throw new Error(`La llave previa "${version}" debe tener exactamente 64 caracteres hexadecimales (32 bytes).`);
    }
    keys.set(version, Buffer.from(hexKey, 'hex'));
  }

  return keys;
}

const rawEnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  TRUST_PROXY: z.string().optional(),
  APP_URL: z.string().url().default('http://localhost:5173'),
  ALLOWED_ORIGIN: z.preprocess((val) => (val === '' ? undefined : val), z.string().url().optional()),

  DB_HOST: z.string().min(1).default('127.0.0.1'),
  DB_PORT: z.coerce.number().int().min(1).max(65535).default(3306),
  DB_NAME: z.string().min(1).default('securevault'),
  DB_USER: z.string().min(1).default('securevault_app'),
  DB_PASSWORD: z.string().default(''),
  DB_SSL: z.string().optional(),
  DB_SSL_CA: z.string().optional(),
  DB_CONNECTION_LIMIT: z.coerce.number().int().min(2).max(100).default(10),

  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET debe tener al menos 32 caracteres.'),
  SESSION_IDLE_TIMEOUT_MS: z.coerce.number().int().min(1000).default(1800000),
  SESSION_ABSOLUTE_TIMEOUT_MS: z.coerce.number().int().min(5000).default(43200000),
  COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).default('lax'),

  DATA_ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'DATA_ENCRYPTION_KEY debe tener exactamente 64 caracteres hexadecimales (32 bytes).'),
  ENCRYPTION_KEY_VERSION: z
    .string()
    .regex(/^v[1-9]\d*$/, 'ENCRYPTION_KEY_VERSION debe seguir el formato v1, v2, ...')
    .default('v1'),
  DATA_ENCRYPTION_PREVIOUS_KEYS: z.string().optional(),

  BCRYPT_ROUNDS: z.coerce
    .number()
    .int()
    .min(12, 'BCRYPT_ROUNDS debe ser como mínimo 12 por política de seguridad.')
    .max(15)
    .default(12),

  SMTP_HOST: z.string().optional().default(''),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  SMTP_SECURE: z.string().optional(),
  SMTP_USER: z.string().optional().default(''),
  SMTP_PASSWORD: z.string().optional().default(''),
  SMTP_FROM: z.string().optional().default('SecureVault <no-reply@securevault.local>'),

  SECURITY_ALERT_WEBHOOK_URL: z.string().optional().default(''),
  SECURITY_ALERT_EMAIL: z.string().optional().default('')
});

/**
 * Carga y valida la configuración del entorno en modo fail-closed.
 * @param {NodeJS.ProcessEnv} [envInput]
 * @param {{ loadDotenv?: boolean }} [options]
 */
export function loadConfig(envInput = process.env, options = {}) {
  const { loadDotenv = envInput === process.env && process.env.NODE_ENV !== 'test' } = options;

  if (loadDotenv) {
    if (fs.existsSync(BACKEND_ENV_PATH)) {
      dotenv.config({ path: BACKEND_ENV_PATH, override: false });
    }
    if (fs.existsSync(ROOT_ENV_PATH)) {
      dotenv.config({ path: ROOT_ENV_PATH, override: false });
    }
  }

  const parsed = rawEnvSchema.safeParse(envInput);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join(' | ');
    throw new Error(`Configuración de entorno inválida (fail-closed): ${details}`);
  }

  const data = parsed.data;
  const isProduction = data.NODE_ENV === 'production';
  const dbSsl = parseBooleanEnv(data.DB_SSL, isProduction);
  const smtpSecure = parseBooleanEnv(data.SMTP_SECURE, data.SMTP_PORT === 465);
  const trustProxy = parseTrustProxy(data.TRUST_PROXY, isProduction);
  const previousKeys = parsePreviousEncryptionKeys(
    data.DATA_ENCRYPTION_PREVIOUS_KEYS,
    data.ENCRYPTION_KEY_VERSION
  );

  if (isProduction) {
    if (looksLikePlaceholder(data.SESSION_SECRET)) {
      throw new Error('SESSION_SECRET no puede usar valores de ejemplo en producción.');
    }
    if (looksLikePlaceholder(data.DATA_ENCRYPTION_KEY)) {
      throw new Error('DATA_ENCRYPTION_KEY no puede usar valores de ejemplo en producción.');
    }
    if (!data.DB_PASSWORD) {
      throw new Error('DB_PASSWORD es obligatorio en producción.');
    }
    if (data.DB_USER.toLowerCase() === 'root') {
      throw new Error('Por seguridad, DB_USER no debe ser root en producción.');
    }
    if (!dbSsl) {
      throw new Error('DB_SSL=true es obligatorio en producción para validar TLS hacia MySQL.');
    }
    if (!data.APP_URL.startsWith('https://')) {
      throw new Error('APP_URL debe utilizar HTTPS en producción.');
    }
    if (data.ALLOWED_ORIGIN && !data.ALLOWED_ORIGIN.startsWith('https://')) {
      throw new Error('ALLOWED_ORIGIN debe utilizar HTTPS en producción.');
    }
  }

  if (data.COOKIE_SAME_SITE === 'none' && !isProduction) {
    throw new Error('COOKIE_SAME_SITE=none requiere cookies Secure sobre HTTPS (NODE_ENV=production).');
  }

  const keyRing = new Map(previousKeys);
  keyRing.set(data.ENCRYPTION_KEY_VERSION, Buffer.from(data.DATA_ENCRYPTION_KEY, 'hex'));

  return {
    nodeEnv: data.NODE_ENV,
    isProduction,
    isTest: data.NODE_ENV === 'test',
    port: data.PORT,
    trustProxy,
    appUrl: data.APP_URL.replace(/\/+$/, ''),
    allowedOrigin: (data.ALLOWED_ORIGIN || data.APP_URL).replace(/\/+$/, ''),
    db: {
      host: data.DB_HOST,
      port: data.DB_PORT,
      database: data.DB_NAME,
      user: data.DB_USER,
      password: data.DB_PASSWORD,
      ssl: dbSsl,
      sslCa: data.DB_SSL_CA || '',
      connectionLimit: data.DB_CONNECTION_LIMIT
    },
    session: {
      secret: data.SESSION_SECRET,
      idleTimeoutMs: data.SESSION_IDLE_TIMEOUT_MS,
      absoluteTimeoutMs: data.SESSION_ABSOLUTE_TIMEOUT_MS,
      sameSite: data.COOKIE_SAME_SITE
    },
    crypto: {
      activeKeyVersion: data.ENCRYPTION_KEY_VERSION,
      activeKey: Buffer.from(data.DATA_ENCRYPTION_KEY, 'hex'),
      keyRing,
      bcryptRounds: data.BCRYPT_ROUNDS
    },
    smtp: {
      host: data.SMTP_HOST,
      port: data.SMTP_PORT,
      secure: smtpSecure,
      user: data.SMTP_USER,
      password: data.SMTP_PASSWORD,
      from: data.SMTP_FROM
    },
    alerts: {
      webhookUrl: data.SECURITY_ALERT_WEBHOOK_URL.trim(),
      email: data.SECURITY_ALERT_EMAIL.trim()
    }
  };
}
