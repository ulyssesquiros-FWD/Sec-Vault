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

  const conn = await mysql.createConnection({
    host: config.db.host,
    port: config.db.port,
    database: config.db.database,
    user: config.db.user,
    password: config.db.password,
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
      await conn.query(sql);
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
