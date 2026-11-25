import fs from 'node:fs';
import tls from 'node:tls';
import mysql from 'mysql2/promise';

const PRIVATE_KEY_MARKERS = [
  'BEGIN PRIVATE KEY',
  'BEGIN RSA PRIVATE KEY',
  'BEGIN EC PRIVATE KEY',
  'BEGIN OPENSSH PRIVATE KEY',
  'BEGIN ENCRYPTED PRIVATE KEY',
  'BEGIN DSA PRIVATE KEY'
];

function stripSurroundingQuotes(value) {
  const trimmed = String(value).trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

function assertNoPrivateKeyMaterial(pemContent) {
  const upper = pemContent.toUpperCase();
  if (PRIVATE_KEY_MARKERS.some((marker) => upper.includes(marker))) {
    throw new Error(
      'Error de configuración: DB_SSL_CA solo debe contener certificados CA públicos, nunca llaves privadas.'
    );
  }
}

/**
 * Elimina cadenas de conexión con credenciales, bloques PEM y posibles secretos de mensajes de error.
 * @param {string} rawMessage
 */
export function sanitizeDatabaseErrorMessage(rawMessage) {
  if (!rawMessage) {
    return 'Error desconocido en base de datos.';
  }
  return String(rawMessage)
    .replace(/mysqls?:\/\/[^@\s]+@/gi, 'mysql://[REDACTED]@')
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[PEM REDACTED]')
    .replace(/(password|secret|key|ca)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .trim();
}

/**
 * Clasifica fallos de inicio o conexión MySQL sin filtrar secretos ni cadenas completas.
 * @param {unknown} err
 * @returns {{ category: 'CONFIGURATION_ERROR' | 'TLS_CERTIFICATE_ERROR' | 'MYSQL_AUTH_ERROR' | 'MYSQL_CONNECTION_ERROR' | 'MYSQL_AVAILABILITY_ERROR', label: string, code: string, message: string, guidance: string }}
 */
export function classifyDatabaseError(err) {
  const code = String(err?.code || '');
  const rawMsg = sanitizeDatabaseErrorMessage(err?.message || String(err || ''));
  const lower = rawMsg.toLowerCase();

  if (
    code === 'HANDSHAKE_SSL_ERROR' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    code === 'CERT_HAS_EXPIRED' ||
    code === 'CERT_NOT_YET_VALID' ||
    code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
    code === 'ERR_TLS_REQUIRED'
  ) {
    return {
      category: 'TLS_CERTIFICATE_ERROR',
      label: 'Error de certificado TLS',
      code,
      message: rawMsg,
      guidance:
        'La conexión cifrada hacia MySQL rechazó un certificado no confiable (rejectUnauthorized=true activo). Configura DB_SSL_CA con el certificado CA raíz del proveedor (PEM o Base64) o utiliza un servidor MySQL gestionado con CA confiable.'
    };
  }

  if (
    lower.includes('configuración') ||
    lower.includes('db_ssl_ca') ||
    lower.includes('db_ssl=true') ||
    lower.includes('db_ssl_verify_identity') ||
    lower.includes('db_user') ||
    lower.includes('db_password') ||
    lower.includes('app_url') ||
    lower.includes('allowed_origin') ||
    lower.includes('session_secret') ||
    lower.includes('data_encryption_key') ||
    lower.includes('trust_proxy')
  ) {
    return {
      category: 'CONFIGURATION_ERROR',
      label: 'Error de configuración',
      code: code || 'CONFIG_ERROR',
      message: rawMsg,
      guidance: 'Revisa las variables de entorno configuradas en el servidor o panel PaaS.'
    };
  }

  if (
    lower.includes('self-signed certificate') ||
    lower.includes('unable to verify') ||
    lower.includes('certificate') ||
    lower.includes('tls') ||
    lower.includes('ssl')
  ) {
    return {
      category: 'TLS_CERTIFICATE_ERROR',
      label: 'Error de certificado TLS',
      code: code || 'TLS_ERROR',
      message: rawMsg,
      guidance:
        'La conexión cifrada hacia MySQL rechazó un certificado no confiable (rejectUnauthorized=true activo). Configura DB_SSL_CA con el certificado CA raíz del proveedor (PEM o Base64) o utiliza un servidor MySQL gestionado con CA confiable.'
    };
  }

  if (
    code === 'ER_ACCESS_DENIED_ERROR' ||
    code === 'ER_DBACCESS_DENIED_ERROR' ||
    code === 'ER_NOT_SUPPORTED_AUTH_MODE' ||
    code === 'ER_ACCESS_DENIED_NO_PASSWORD_ERROR' ||
    lower.includes('access denied for user')
  ) {
    return {
      category: 'MYSQL_AUTH_ERROR',
      label: 'Error de autenticación MySQL',
      code: code || 'AUTH_ERROR',
      message: rawMsg,
      guidance: 'Verifica que DB_USER exista, tenga permisos sobre DB_NAME y coincida con DB_PASSWORD.'
    };
  }

  if (
    code === 'ECONNREFUSED' ||
    code === 'ENOTFOUND' ||
    code === 'ETIMEDOUT' ||
    code === 'EAI_AGAIN' ||
    code === 'EHOSTUNREACH' ||
    code === 'ENETUNREACH' ||
    code === 'ECONNRESET' ||
    code === 'EPIPE'
  ) {
    return {
      category: 'MYSQL_CONNECTION_ERROR',
      label: 'Error de conexión hacia MySQL',
      code,
      message: rawMsg,
      guidance: 'Verifica que DB_HOST y DB_PORT sean alcanzables desde la red del servicio.'
    };
  }

  return {
    category: 'MYSQL_AVAILABILITY_ERROR',
    label: 'Error de disponibilidad de MySQL',
    code: code || 'MYSQL_UNAVAILABLE',
    message: rawMsg,
    guidance: 'Verifica que la instancia MySQL esté iniciada, aceptando conexiones y que DB_NAME exista.'
  };
}

function validateCaPem(pemContent) {
  assertNoPrivateKeyMaterial(pemContent);
  if (!pemContent.includes('BEGIN CERTIFICATE') || !pemContent.includes('END CERTIFICATE')) {
    throw new Error(
      'Error de configuración: DB_SSL_CA no contiene un bloque PEM de certificado válido.'
    );
  }
  try {
    tls.createSecureContext({ ca: pemContent });
  } catch {
    throw new Error(
      'Error de configuración: el certificado CA proporcionado en DB_SSL_CA es inválido o está corrupto.'
    );
  }
  return pemContent;
}

/**
 * Construye las opciones SSL seguras para MySQL.
 * En producción siempre exige verificación estricta del certificado (`rejectUnauthorized: true`).
 * Soporta PEM directo, PEM con `\n` escapados, Base64 de PEM o ruta de archivo.
 * @param {{ ssl: boolean, sslCa?: string, sslVerifyIdentity?: boolean }} dbConfig
 */
export function buildSslOptions(dbConfig) {
  if (!dbConfig.ssl) {
    return undefined;
  }

  const sslOptions = {
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2'
  };

  if (dbConfig.sslVerifyIdentity) {
    sslOptions.verifyIdentity = true;
  }

  if (dbConfig.sslCa) {
    const trimmed = stripSurroundingQuotes(dbConfig.sslCa);
    if (!trimmed) {
      return sslOptions;
    }

    assertNoPrivateKeyMaterial(trimmed);

    if (trimmed.includes('BEGIN CERTIFICATE')) {
      const normalizedPem = trimmed.replace(/\r\n/g, '\n').replace(/\\n/g, '\n');
      sslOptions.ca = validateCaPem(normalizedPem);
    } else if (fs.existsSync(trimmed) && fs.statSync(trimmed).isFile()) {
      const filePem = fs.readFileSync(trimmed, 'utf8').replace(/\r\n/g, '\n');
      sslOptions.ca = validateCaPem(filePem);
    } else {
      const compactBase64 = trimmed.replace(/\s+/g, '');
      const decoded = /^[A-Za-z0-9+/=]+$/.test(compactBase64)
        ? Buffer.from(compactBase64, 'base64').toString('utf8').replace(/\r\n/g, '\n')
        : '';
      if (decoded.includes('BEGIN CERTIFICATE')) {
        sslOptions.ca = validateCaPem(decoded);
      } else {
        throw new Error(
          'DB_SSL_CA especificado no contiene un certificado PEM válido (directo o Base64) ni apunta a un archivo existente.'
        );
      }
    }
  }

  return sslOptions;
}

/**
 * Crea el pool de conexiones mysql2/promise con timeouts y verificación TLS.
 * @param {ReturnType<import('./env.js').loadConfig>} config
 * @param {import('pino').Logger} [logger]
 */
export function createPool(config, logger) {
  const ssl = buildSslOptions(config.db);

  const pool = mysql.createPool({
    host: config.db.host,
    port: config.db.port,
    database: config.db.database,
    user: config.db.user,
    password: config.db.password,
    connectionLimit: config.db.connectionLimit,
    waitForConnections: true,
    queueLimit: 50,
    connectTimeout: 10000,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000,
    charset: 'utf8mb4',
    timezone: 'Z',
    ...(ssl ? { ssl } : {})
  });

  pool.on?.('error', (err) => {
    const classified = classifyDatabaseError(err);
    logger?.error(
      { category: classified.category, code: classified.code, message: classified.message },
      `${classified.label} en el pool de MySQL`
    );
  });

  return pool;
}

/**
 * Obtiene el estado TLS negociado en la conexión activa de MySQL (sin exponer datos sensibles).
 * @param {import('mysql2/promise').Pool} pool
 */
export async function getDatabaseTlsStatus(pool) {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query("SHOW STATUS WHERE Variable_name IN ('Ssl_cipher', 'Ssl_version')");
    const statusMap = Object.fromEntries(rows.map((r) => [r.Variable_name, r.Value || '']));
    return {
      tlsActive: Boolean(statusMap.Ssl_cipher),
      cipher: statusMap.Ssl_cipher || null,
      version: statusMap.Ssl_version || null
    };
  } finally {
    conn.release();
  }
}

/**
 * Verifica conectividad real con MySQL ejecutando ping y comprobando TLS si es obligatorio.
 * @param {import('mysql2/promise').Pool} pool
 * @param {{ requireTls?: boolean }} [options]
 */
export async function checkDatabaseHealth(pool, options = {}) {
  const conn = await pool.getConnection();
  try {
    await conn.ping();
    if (options.requireTls) {
      const [rows] = await conn.query("SHOW STATUS LIKE 'Ssl_cipher'");
      const cipher = rows[0]?.Value || '';
      if (!cipher) {
        const tlsErr = new Error('MySQL no negoció una sesión TLS activa pese a requerirse conexión TLS obligatoria.');
        tlsErr.code = 'ERR_TLS_REQUIRED';
        throw tlsErr;
      }
    }
    return true;
  } finally {
    conn.release();
  }
}

/**
 * Ejecuta una función dentro de una transacción ACID con commit/rollback automático
 * y liberación garantizada de la conexión.
 * @template T
 * @param {import('mysql2/promise').Pool} pool
 * @param {(conn: import('mysql2/promise').PoolConnection) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withTransaction(pool, fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await fn(conn);
    await conn.commit();
    return result;
  } catch (err) {
    try {
      await conn.rollback();
    } catch {
      // Ignorar fallo secundario en rollback para preservar el error original
    }
    throw err;
  } finally {
    conn.release();
  }
}
