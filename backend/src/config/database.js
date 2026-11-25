import fs from 'node:fs';
import mysql from 'mysql2/promise';

/**
 * Construye las opciones SSL seguras para MySQL.
 * En producción siempre exige verificación estricta del certificado (`rejectUnauthorized: true`).
 * Soporta PEM directo, PEM con `\n` escapados, Base64 de PEM o ruta de archivo.
 * @param {{ ssl: boolean, sslCa?: string }} dbConfig
 */
export function buildSslOptions(dbConfig) {
  if (!dbConfig.ssl) {
    return undefined;
  }

  const sslOptions = {
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2'
  };

  if (dbConfig.sslCa) {
    const trimmed = dbConfig.sslCa.trim();
    if (trimmed.includes('BEGIN CERTIFICATE')) {
      sslOptions.ca = trimmed.replace(/\\n/g, '\n');
    } else if (fs.existsSync(trimmed)) {
      sslOptions.ca = fs.readFileSync(trimmed, 'utf8');
    } else {
      const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
      if (decoded.includes('BEGIN CERTIFICATE')) {
        sslOptions.ca = decoded;
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
    logger?.error({ code: err.code, message: err.message }, 'Error inesperado en el pool de MySQL');
  });

  return pool;
}

/**
 * Verifica conectividad real con MySQL ejecutando una consulta mínima con timeout.
 * @param {import('mysql2/promise').Pool} pool
 */
export async function checkDatabaseHealth(pool) {
  const conn = await pool.getConnection();
  try {
    await conn.ping();
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
