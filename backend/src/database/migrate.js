import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import mysql from 'mysql2/promise';
import { loadConfig } from '../config/env.js';
import { createLogger } from '../config/logger.js';
import { buildSslOptions } from '../config/database.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MIGRATIONS_DIR = path.resolve(__dirname, '../../../database/migrations');

/**
 * Ejecuta migraciones SQL versionadas contra MySQL de manera idempotente.
 */
export async function runMigrations(configInput = null) {
  const config = configInput || loadConfig();
  const logger = createLogger(config);

  const ssl = buildSslOptions(config.db);

  const migrationUser =
    !configInput && process.env.MIGRATION_DB_USER?.trim()
      ? process.env.MIGRATION_DB_USER.trim()
      : config.db.user;
  const migrationPassword =
    !configInput && process.env.MIGRATION_DB_USER?.trim()
      ? (process.env.MIGRATION_DB_PASSWORD ?? '')
      : config.db.password;

  const conn = await mysql.createConnection({
    host: config.db.host,
    port: config.db.port,
    database: config.db.database,
    user: migrationUser,
    password: migrationPassword,
    multipleStatements: true,
    charset: 'utf8mb4',
    ...(ssl ? { ssl } : {})
  });

  try {
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(64) NOT NULL,
        applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (version)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    const [appliedRows] = await conn.execute('SELECT version FROM schema_migrations');
    const appliedSet = new Set(appliedRows.map((row) => row.version));

    const files = (await fs.readdir(MIGRATIONS_DIR))
      .filter((file) => file.endsWith('.sql'))
      .sort();

    const executed = [];
    for (const file of files) {
      if (appliedSet.has(file)) {
        continue;
      }
      const sql = await fs.readFile(path.join(MIGRATIONS_DIR, file), 'utf8');
      try {
        await conn.query(sql);
      } catch (sqlErr) {
        // Si las columnas o índices ya existían (ej. por esquema consolidado previo), continuar y registrar versión
        if (sqlErr.errno === 1060 || sqlErr.code === 'ER_DUP_FIELDNAME') {
          logger.warn({ migration: file, warning: sqlErr.message }, 'Columnas ya existentes en tabla; registrando versión en schema_migrations');
        } else {
          throw sqlErr;
        }
      }
      await conn.execute('INSERT INTO schema_migrations (version) VALUES (?)', [file]);
      executed.push(file);
      logger.info({ migration: file }, 'Migración MySQL aplicada correctamente');
    }

    return executed;
  } finally {
    await conn.end();
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMain) {
  runMigrations()
    .then((executed) => {
      console.log(
        executed.length
          ? `Migraciones aplicadas: ${executed.join(', ')}`
          : 'La base de datos ya está actualizada.'
      );
      process.exit(0);
    })
    .catch((err) => {
      console.error('Error ejecutando migraciones:', err.message);
      process.exit(1);
    });
}
