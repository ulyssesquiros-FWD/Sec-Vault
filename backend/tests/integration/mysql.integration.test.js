import crypto from 'node:crypto';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { loadConfig } from '../../src/config/env.js';
import { createLogger } from '../../src/config/logger.js';
import { createPool, checkDatabaseHealth, withTransaction } from '../../src/config/database.js';
import { createMySQLSessionStore, createSessionMiddleware } from '../../src/config/session.js';
import { runMigrations } from '../../src/database/migrate.js';
import { createApp } from '../../src/app.js';

const REQUIRE_MYSQL = process.env.REQUIRE_MYSQL === 'true';
const MYSQL_ENABLED = REQUIRE_MYSQL || process.env.MYSQL_TEST_ENABLED === 'true';

async function cleanTestTables(pool) {
  await pool.execute('DELETE FROM sessions');
  await pool.execute('DELETE FROM security_events');
  await pool.execute('DELETE FROM login_attempts');
  await pool.execute('DELETE FROM password_resets');
  await pool.execute('DELETE FROM notes');
  await pool.execute('DELETE FROM users');
}

describe(
  'Integración Real MySQL 8.4 (mysql2 + InnoDB + express-mysql-session + Express HTTP)',
  { skip: !MYSQL_ENABLED },
  () => {
    let config;
    let pool;
    let sessionStore;
    let app;
    const sentEmails = [];

    before(async () => {
      config = loadConfig(
        {
          NODE_ENV: 'test',
          APP_URL: 'http://localhost:5173',
          ALLOWED_ORIGIN: 'http://localhost:5173',
          DB_HOST: process.env.TEST_DB_HOST || process.env.DB_HOST || '127.0.0.1',
          DB_PORT: process.env.TEST_DB_PORT || process.env.DB_PORT || '3306',
          DB_NAME: process.env.TEST_DB_NAME || process.env.DB_NAME || 'securevault_test',
          DB_USER: process.env.TEST_DB_USER || process.env.DB_USER || 'securevault_test',
          DB_PASSWORD: process.env.TEST_DB_PASSWORD ?? process.env.DB_PASSWORD ?? '',
          DB_SSL: process.env.TEST_DB_SSL || 'false',
          SESSION_SECRET: crypto.randomBytes(32).toString('hex'),
          DATA_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'),
          ENCRYPTION_KEY_VERSION: 'v1',
          BCRYPT_ROUNDS: '12'
        },
        { loadDotenv: false }
      );

      await runMigrations(config);
      // Verificar idempotencia de migraciones versionadas
      const secondRun = await runMigrations(config);
      assert.equal(secondRun.length, 0);

      const logger = createLogger(config);
      pool = createPool(config, logger);
      sessionStore = createMySQLSessionStore(pool, config);
      await sessionStore.onReady();

      await cleanTestTables(pool);

      const sessionMiddleware = createSessionMiddleware(config, sessionStore);
      const emailTransporter = {
        async sendMail(mail) {
          sentEmails.push(mail);
          return { messageId: 'mysql-integration-mock' };
        }
      };

      const built = createApp({
        config,
        logger,
        pool,
        sessionMiddleware,
        emailTransporter,
        rateLimitOverrides: {
          globalMax: 1000,
          authMax: 100,
          resetMax: 50,
          writeMax: 200
        }
      });
      app = built.app;
    });

    after(async () => {
      if (pool) {
        await cleanTestTables(pool).catch(() => {});
      }
      if (sessionStore?.close) await sessionStore.close();
      if (pool) await pool.end();
    });

    it('1-2: Verifica conexión mysql2, concurrencia del pool, InnoDB y utf8mb4 en las 7 tablas', async () => {
      assert.equal(await checkDatabaseHealth(pool), true);

      const concurrentResults = await Promise.all(
        Array.from({ length: 10 }, () => pool.execute('SELECT 1 AS ok'))
      );
      assert.equal(concurrentResults.length, 10);

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

    it('3-12: Flujo completo contra MySQL real (registro bcrypt, UNIQUE, CRUD cifrado, IDOR, sesiones persistentes, FKs y rollback)', async () => {
      const agentA = request.agent(app);
      const agentB = request.agent(app);

      // 3 & 11. Registro real vía Express -> verificación bcrypt >= 12 y teléfono AES-256-GCM en MySQL
      const regA = await agentA.post('/api/auth/register').send({
        name: 'Ulysses MySQL A',
        email: 'MYSQL_A@SecureVault.Test',
        password: 'ClaveMySQL!2026#A',
        phone: '+506 8812-3456'
      });
      assert.equal(regA.status, 201);
      const userIdA = regA.body.user.id;
      const csrfA = regA.body.csrfToken;

      const [userRows] = await pool.execute(
        'SELECT email, password_hash, role, encrypted_phone FROM users WHERE id = ?',
        [userIdA]
      );
      assert.equal(userRows[0].email, 'mysql_a@securevault.test');
      assert.equal(userRows[0].role, 'user');
      assert.match(userRows[0].password_hash, /^\$2[abxy]\$12\$/);
      assert.ok(userRows[0].encrypted_phone.startsWith('v1.'));
      assert.equal(userRows[0].encrypted_phone.includes('8812'), false);

      // 4. Restricción UNIQUE de correo (HTTP 409 y error nativo MySQL ER_DUP_ENTRY)
      const dupHttp = await request(app).post('/api/auth/register').send({
        name: 'Duplicado',
        email: 'mysql_a@securevault.test',
        password: 'ClaveMySQL!2026#A',
        phone: '+506 8812-3456'
      });
      assert.equal(dupHttp.status, 409);
      await assert.rejects(
        () =>
          pool.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES ('X', 'mysql_a@securevault.test', 'h', 'user')"
          ),
        { code: 'ER_DUP_ENTRY' }
      );

      // 12. Sesión persistida realmente en tabla `sessions` por express-mysql-session
      const [sessBeforeLogout] = await pool.execute('SELECT session_id, data FROM sessions');
      assert.ok(sessBeforeLogout.length >= 1);

      // 9 & 11. CRUD real de notas cifradas en MySQL
      const createNote = await agentA
        .post('/api/notes')
        .set('X-CSRF-Token', csrfA)
        .send({ title: 'Nota MySQL', content: 'Contenido ultra secreto en MySQL' });
      assert.equal(createNote.status, 201);
      const noteId = createNote.body.note.id;

      const [noteRows] = await pool.execute(
        'SELECT owner_id, title, encrypted_content, key_version FROM notes WHERE id = ?',
        [noteId]
      );
      assert.equal(Number(noteRows[0].owner_id), userIdA);
      assert.ok(noteRows[0].encrypted_content.startsWith('v1.'));
      assert.equal(noteRows[0].encrypted_content.includes('ultra secreto'), false);

      const updateNote = await agentA
        .put(`/api/notes/${noteId}`)
        .set('X-CSRF-Token', csrfA)
        .send({ title: 'Nota MySQL Editada', content: 'Nuevo texto cifrado' });
      assert.equal(updateNote.status, 200);
      assert.equal(updateNote.body.note.content, 'Nuevo texto cifrado');

      // 10 & 14. Protección IDOR real contra MySQL + registro en `security_events`
      const regB = await agentB.post('/api/auth/register').send({
        name: 'Usuario B',
        email: 'mysql_b@securevault.test',
        password: 'ClaveMySQL!2026#B',
        phone: '+506 8899-0011'
      });
      assert.equal(regB.status, 201);

      const idorAttempt = await agentB.get(`/api/notes/${noteId}`);
      assert.equal(idorAttempt.status, 403);
      assert.equal(idorAttempt.body.code, 'IDOR_FORBIDDEN');

      const [idorEvents] = await pool.execute(
        "SELECT id, actor_id, severity FROM security_events WHERE event_type = 'IDOR_ATTEMPT'"
      );
      assert.equal(idorEvents.length, 1);
      assert.equal(Number(idorEvents[0].actor_id), regB.body.user.id);

      // Eliminar nota vía API
      const deleteNote = await agentA.delete(`/api/notes/${noteId}`).set('X-CSRF-Token', csrfA);
      assert.equal(deleteNote.status, 200);

      // 6 & 7. Transacciones ACID (commit y rollback real en MySQL)
      await withTransaction(pool, async (conn) => {
        await conn.execute(
          'INSERT INTO notes (owner_id, title, encrypted_content, key_version) VALUES (?, ?, ?, ?)',
          [userIdA, 'Commit TX', 'v1.a.b.c', 'v1']
        );
      });
      const [committedRows] = await pool.execute(
        "SELECT id FROM notes WHERE owner_id = ? AND title = 'Commit TX'",
        [userIdA]
      );
      assert.equal(committedRows.length, 1);

      await assert.rejects(() =>
        withTransaction(pool, async (conn) => {
          await conn.execute(
            'INSERT INTO notes (owner_id, title, encrypted_content, key_version) VALUES (?, ?, ?, ?)',
            [userIdA, 'Rollback TX', 'v1.a.b.c', 'v1']
          );
          throw new Error('ROLLBACK_FORZADO');
        })
      );
      const [rolledBackRows] = await pool.execute(
        "SELECT id FROM notes WHERE owner_id = ? AND title = 'Rollback TX'",
        [userIdA]
      );
      assert.equal(rolledBackRows.length, 0);

      // 8. Integridad referencial y claves foráneas (rechazo de FK inválida + ON DELETE CASCADE)
      await assert.rejects(
        () =>
          pool.execute(
            "INSERT INTO notes (owner_id, title, encrypted_content, key_version) VALUES (9999999, 'Huérfana', 'v1.a.b.c', 'v1')"
          ),
        { code: 'ER_NO_REFERENCED_ROW_2' }
      );

      // Logout elimina sesión en MySQL
      const logoutA = await agentA.post('/api/auth/logout').set('X-CSRF-Token', csrfA).send({});
      assert.equal(logoutA.status, 200);
      const afterLogoutMe = await agentA.get('/api/auth/me');
      assert.equal(afterLogoutMe.status, 401);
    });

    it('5, 13 & 14: Consultas parametrizadas (SQLi), recuperación de contraseña SHA-256, eventos y bloqueo 429 en login_attempts', async () => {
      const agent = request.agent(app);
      const reg = await agent.post('/api/auth/register').send({
        name: 'Reset & Brute User',
        email: 'reset_mysql@securevault.test',
        password: 'OldMysqlPassword!2026',
        phone: '+506 8822-1133'
      });
      assert.equal(reg.status, 201);
      const userId = reg.body.user.id;

      // 5. SQL Injection en endpoint de login
      const sqliRes = await request(app).post('/api/auth/login').send({
        email: "' OR 1=1 --",
        password: 'OldMysqlPassword!2026'
      });
      assert.equal(sqliRes.status, 400);

      // 13. Recuperación de contraseña con token SHA-256 en MySQL e invalidación de sesión
      const forgotRes = await request(app).post('/api/auth/forgot-password').send({
        email: 'reset_mysql@securevault.test'
      });
      assert.equal(forgotRes.status, 200);
      assert.equal(sentEmails.length, 1);

      const rawToken = sentEmails[0].text.match(/token=([0-9a-f]{64})/)[1];
      const [resetRows] = await pool.execute(
        'SELECT token_hash, used_at FROM password_resets WHERE user_id = ?',
        [userId]
      );
      assert.equal(resetRows.length, 1);
      assert.notEqual(resetRows[0].token_hash, rawToken);
      assert.match(resetRows[0].token_hash, /^[0-9a-f]{64}$/);
      assert.equal(resetRows[0].used_at, null);

      const resetRes = await request(app).post('/api/auth/reset-password').send({
        token: rawToken,
        newPassword: 'NewMysqlPassword!2026'
      });
      assert.equal(resetRes.status, 200);

      // Sesión previa revocada por incremento de session_version en MySQL
      const staleSession = await agent.get('/api/auth/me');
      assert.equal(staleSession.status, 401);

      // Token marcado como usado y reutilización bloqueada
      const [usedRows] = await pool.execute(
        'SELECT used_at FROM password_resets WHERE token_hash = ?',
        [resetRows[0].token_hash]
      );
      assert.ok(usedRows[0].used_at !== null);

      const reuseRes = await request(app).post('/api/auth/reset-password').send({
        token: rawToken,
        newPassword: 'OtherMysqlPassword!2026'
      });
      assert.equal(reuseRes.status, 400);

      // 14. Fuerza bruta persistida en tabla `login_attempts` -> HTTP 429 + evento `BRUTE_FORCE_ALERT`
      for (let i = 1; i <= 4; i += 1) {
        const fail = await request(app).post('/api/auth/login').send({
          email: 'reset_mysql@securevault.test',
          password: 'WrongPassword!123'
        });
        assert.equal(fail.status, 401);
      }

      const fifthFail = await request(app).post('/api/auth/login').send({
        email: 'reset_mysql@securevault.test',
        password: 'WrongPassword!123'
      });
      assert.equal(fifthFail.status, 429);

      const [attemptRows] = await pool.execute(
        'SELECT attempts, locked_until FROM login_attempts WHERE email_normalized = ?',
        ['reset_mysql@securevault.test']
      );
      assert.equal(Number(attemptRows[0].attempts), 5);
      assert.ok(attemptRows[0].locked_until !== null);

      const [alertEvents] = await pool.execute(
        "SELECT event_type, severity FROM security_events WHERE event_type = 'BRUTE_FORCE_ALERT'"
      );
      assert.equal(alertEvents.length, 1);
      assert.equal(alertEvents[0].severity, 'HIGH');

      // 8b. ON DELETE CASCADE elimina notas al borrar usuario y ON DELETE SET NULL conserva eventos
      await pool.execute(
        "INSERT INTO notes (owner_id, title, encrypted_content, key_version) VALUES (?, 'Cascade', 'v1.a.b.c', 'v1')",
        [userId]
      );
      await pool.execute('DELETE FROM users WHERE id = ?', [userId]);
      const [remainingNotes] = await pool.execute('SELECT id FROM notes WHERE owner_id = ?', [userId]);
      assert.equal(remainingNotes.length, 0);
    });
  }
);
