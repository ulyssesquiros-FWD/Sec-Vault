import crypto from 'node:crypto';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../../src/config/env.js';
import { createLogger } from '../../src/config/logger.js';
import { createPool, checkDatabaseHealth, withTransaction } from '../../src/config/database.js';
import { createMySQLSessionStore } from '../../src/config/session.js';
import { runMigrations } from '../../src/database/migrate.js';
import { createEncryptionService } from '../../src/services/encryptionService.js';
import { hashPassword } from '../../src/services/passwordService.js';
import { createUserRepository } from '../../src/repositories/userRepository.js';
import { createNoteRepository } from '../../src/repositories/noteRepository.js';

const REQUIRE_MYSQL = process.env.REQUIRE_MYSQL === 'true';
const MYSQL_ENABLED = REQUIRE_MYSQL || process.env.MYSQL_TEST_ENABLED === 'true';

describe('Pruebas de integración reales contra MySQL (mysql2 + InnoDB + express-mysql-session)', { skip: !MYSQL_ENABLED }, () => {
  let config;
  let pool;
  let sessionStore;

  before(async () => {
    config = loadConfig(
      {
        NODE_ENV: 'test',
        DB_HOST: process.env.TEST_DB_HOST || process.env.DB_HOST || '127.0.0.1',
        DB_PORT: process.env.TEST_DB_PORT || process.env.DB_PORT || '3306',
        DB_NAME: process.env.TEST_DB_NAME || process.env.DB_NAME || 'securevault_test',
        DB_USER: process.env.TEST_DB_USER || process.env.DB_USER || 'root',
        DB_PASSWORD: process.env.TEST_DB_PASSWORD ?? process.env.DB_PASSWORD ?? '',
        DB_SSL: process.env.TEST_DB_SSL || 'false',
        SESSION_SECRET: 'test-session-secret-mysql-integration-32chars',
        DATA_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex')
      },
      { loadDotenv: false }
    );

    await runMigrations(config);
    // Verificar idempotencia ejecutando migraciones por segunda vez
    const secondRun = await runMigrations(config);
    assert.equal(secondRun.length, 0);

    const logger = createLogger(config);
    pool = createPool(config, logger);
    sessionStore = createMySQLSessionStore(pool, config);
    await sessionStore.onReady();
  });

  after(async () => {
    if (sessionStore?.close) await sessionStore.close();
    if (pool) await pool.end();
  });

  it('verifica conectividad, motor InnoDB y charset utf8mb4 en todas las tablas', async () => {
    assert.equal(await checkDatabaseHealth(pool), true);

    const [tables] = await pool.execute(
      `SELECT TABLE_NAME, ENGINE, TABLE_COLLATION
       FROM information_schema.TABLES
       WHERE TABLE_SCHEMA = ?`,
      [config.db.database]
    );

    const expectedTables = [
      'schema_migrations',
      'users',
      'notes',
      'password_resets',
      'security_events',
      'login_attempts',
      'sessions'
    ];

    for (const tableName of expectedTables) {
      const found = tables.find((t) => t.TABLE_NAME === tableName);
      assert.ok(found, `Falta la tabla obligatoria ${tableName}`);
      assert.equal(found.ENGINE, 'InnoDB');
      assert.ok(found.TABLE_COLLATION.startsWith('utf8mb4_'));
    }
  });

  it('persiste usuarios con bcrypt >= 12, teléfono AES-256-GCM, restricción UNIQUE y rollback ACID', async () => {
    const userRepo = createUserRepository(pool);
    const noteRepo = createNoteRepository(pool);
    const encryptionService = createEncryptionService(config.crypto);

    const email = `mysql_test_${Date.now()}@securevault.test`;
    const passwordHash = await hashPassword('ClaveMySQL!2026#', 12);
    const created = await userRepo.createUserWithEncryptedPhone({
      name: 'Prueba MySQL',
      emailNormalized: email,
      passwordHash,
      phone: '+50688001122',
      encryptionService
    });

    const [userRows] = await pool.execute('SELECT password_hash, encrypted_phone FROM users WHERE id = ?', [
      created.id
    ]);
    assert.match(userRows[0].password_hash, /^\$2[abxy]\$12\$/);
    assert.ok(userRows[0].encrypted_phone.startsWith('v1.'));
    assert.equal(userRows[0].encrypted_phone.includes('88001122'), false);

    // Restricción UNIQUE de correo
    await assert.rejects(
      () =>
        userRepo.createUserWithEncryptedPhone({
          name: 'Duplicado',
          emailNormalized: email,
          passwordHash,
          phone: '+50688001122',
          encryptionService
        }),
      { code: 'EMAIL_ALREADY_EXISTS' }
    );

    // Transacción con rollback explícito
    await assert.rejects(() =>
      withTransaction(pool, async (conn) => {
        await conn.execute(
          'INSERT INTO notes (owner_id, title, encrypted_content, key_version) VALUES (?, ?, ?, ?)',
          [created.id, 'Rollback Test', 'v1.a.b.c', 'v1']
        );
        throw new Error('FALLO_FORZADO_ROLLBACK');
      })
    );
    const notesAfterRollback = await noteRepo.findAllByOwner(created.id);
    assert.equal(notesAfterRollback.length, 0);

    // Consulta parametrizada ante intento de SQL Injection
    const injected = await userRepo.findByEmailForAuth("' OR 1=1 --");
    assert.equal(injected, null);

    // Persistencia real de sesiones en MySQL
    await new Promise((resolve, reject) => {
      sessionStore.set(
        'test-sid-mysql-1',
        { cookie: { maxAge: 60000 }, userId: created.id },
        (err) => (err ? reject(err) : resolve())
      );
    });
    const [sessionRows] = await pool.execute('SELECT session_id FROM sessions WHERE session_id = ?', [
      'test-sid-mysql-1'
    ]);
    assert.equal(sessionRows.length, 1);
  });
});
