import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import session from 'express-session';
import { loadConfig } from '../../src/config/env.js';
import { createLogger } from '../../src/config/logger.js';
import { createSessionMiddleware } from '../../src/config/session.js';
import { createApp } from '../../src/app.js';
import { hashPassword } from '../../src/services/passwordService.js';
import { createEncryptionService } from '../../src/services/encryptionService.js';
import { generateTotpCode } from '../../src/services/totpService.js';
import { validateSafeWebhookUrl } from '../../src/services/alertService.js';
import { createInMemoryRepositories } from '../helpers/inMemoryRepos.js';

const KEY_V1_HEX = crypto.randomBytes(32).toString('hex');
const KEY_V2_HEX = crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');

function buildTestContext(envOverrides = {}, appOverrides = {}) {
  const config = loadConfig(
    {
      NODE_ENV: 'test',
      APP_URL: 'http://localhost:5173',
      ALLOWED_ORIGIN: 'http://localhost:5173',
      SESSION_SECRET,
      DATA_ENCRYPTION_KEY: KEY_V1_HEX,
      ENCRYPTION_KEY_VERSION: 'v1',
      BCRYPT_ROUNDS: '12',
      ...envOverrides
    },
    { loadDotenv: false }
  );

  const logger = createLogger(config);
  const store = new session.MemoryStore();
  const sessionMiddleware = createSessionMiddleware(config, store);
  const inMemory = appOverrides.inMemory || createInMemoryRepositories();
  const sentEmails = [];
  const webhookCalls = [];

  const emailTransporter = {
    async sendMail(mail) {
      sentEmails.push(mail);
      return { messageId: 'mock-id' };
    }
  };

  const fetchMock = async (url, opts) => {
    webhookCalls.push({ url, opts });
    return { ok: true, status: 200 };
  };

  const { app } = createApp({
    config,
    logger,
    sessionMiddleware,
    repositories: inMemory.repositories,
    emailTransporter,
    fetchImpl: fetchMock,
    rateLimitOverrides: {
      globalMax: 1000,
      authMax: 100,
      resetMax: 50,
      writeMax: 200,
      ...appOverrides.rateLimitOverrides
    }
  });

  return { app, config, inMemory, sentEmails, webhookCalls };
}

async function seedAdmin(inMemory, config, { email = 'admin@securevault.test', password = 'AdminPassword!2026' } = {}) {
  const encryptionService = createEncryptionService(config.crypto);
  const passwordHash = await hashPassword(password, 12);
  return inMemory.repositories.userRepository.createAdminSeedUser({
    name: 'Administrador Principal',
    emailNormalized: email,
    passwordHash,
    phone: '+50688990011',
    encryptionService
  });
}

describe('Suite HTTP de Seguridad OWASP Top 10:2025 & Requisitos Funcionales', () => {
  it('RF-08 & A02: GET /health mínimo y cabeceras Helmet seguras sin X-Powered-By', async () => {
    const { app } = buildTestContext();
    const res = await request(app).get('/health');

    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { status: 'ok' });
    assert.equal(res.headers['x-powered-by'], undefined);
    assert.equal(res.headers['x-frame-options'], 'DENY');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
    assert.ok(res.headers['content-security-policy'].includes("script-src 'self'"));
    assert.ok(res.headers['permissions-policy'].includes('camera=()'));
  });

  it('RF-01, RF-02 & A04/A07: Registro seguro, cookies HttpOnly, regeneración de sesión, CSRF y logout', async () => {
    const { app, inMemory } = buildTestContext();
    const agent = request.agent(app);

    // Intento de mass assignment con role=admin debe rechazarse (400)
    const escalationRes = await agent.post('/api/auth/register').send({
      name: 'Atacante',
      email: 'attacker@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+50688112233',
      role: 'admin'
    });
    assert.equal(escalationRes.status, 400);

    // Registro válido
    const regRes = await agent.post('/api/auth/register').send({
      name: 'Ulysses Quiros',
      email: 'ULYSSES@SecureVault.Test',
      password: 'PasswordSegura!2026',
      phone: '+50688112233'
    });
    assert.equal(regRes.status, 201);
    assert.equal(regRes.body.user.email, 'ulysses@securevault.test');
    assert.equal(regRes.body.user.role, 'user');
    assert.equal(regRes.body.user.password_hash, undefined);
    assert.ok(regRes.body.csrfToken);

    const regCookies = regRes.headers['set-cookie'] || [];
    const sidCookie = regCookies.find((c) => c.startsWith('secvault.sid='));
    assert.ok(sidCookie, 'Debe emitir cookie de sesión secvault.sid');
    assert.ok(sidCookie.includes('HttpOnly'));
    assert.ok(sidCookie.includes('SameSite=Lax'));

    // Verificar almacén real: bcrypt >= 12 y teléfono cifrado con AES-256-GCM
    const storedUser = inMemory.inspect.users.get(regRes.body.user.id);
    assert.match(storedUser.password_hash, /^\$2[abxy]\$12\$/);
    assert.ok(storedUser.encrypted_phone.startsWith('v1.'));
    assert.equal(storedUser.encrypted_phone.includes('88112233'), false);

    // Correo duplicado -> 409
    const dupRes = await request(app).post('/api/auth/register').send({
      name: 'Otro',
      email: 'ulysses@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+50688112233'
    });
    assert.equal(dupRes.status, 409);

    // CSRF obligatorio en operaciones mutantes
    const noCsrfRes = await agent.post('/api/notes').send({ title: 'Nota', content: 'Texto' });
    assert.equal(noCsrfRes.status, 403);

    // Logout con CSRF válido invalida sesión
    const logoutRes = await agent
      .post('/api/auth/logout')
      .set('X-CSRF-Token', regRes.body.csrfToken)
      .send({});
    assert.equal(logoutRes.status, 200);

    const meAfterLogout = await agent.get('/api/auth/me');
    assert.equal(meAfterLogout.status, 401);

    // Nuevo login regenera ID de sesión (anti session-fixation)
    const loginRes = await agent.post('/api/auth/login').send({
      email: 'ulysses@securevault.test',
      password: 'PasswordSegura!2026'
    });
    assert.equal(loginRes.status, 200);
    const loginCookie = (loginRes.headers['set-cookie'] || []).find((c) => c.startsWith('secvault.sid='));
    assert.ok(loginCookie);
    assert.notEqual(loginCookie.split(';')[0], sidCookie.split(';')[0]);
  });

  it('A07: Expiración de sesión por inactividad invalida el acceso con HTTP 401', async () => {
    const { app } = buildTestContext({ SESSION_IDLE_TIMEOUT_MS: '1000', SESSION_ABSOLUTE_TIMEOUT_MS: '5000' });
    const agent = request.agent(app);
    const reg = await agent.post('/api/auth/register').send({
      name: 'Timeout User',
      email: 'timeout@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+50688112233'
    });
    assert.equal(reg.status, 201);
    const rawCookie = (reg.headers['set-cookie'] || [])[0]?.split(';')[0];

    await new Promise((r) => setTimeout(r, 1080));
    const res = await request(app).get('/api/notes').set('Cookie', rawCookie);
    assert.equal(res.status, 401);
    assert.ok(['SESSION_EXPIRED', 'UNAUTHENTICATED'].includes(res.body.code));
  });

  it('RF-04, RF-05 & A01/A05/A06: CRUD de notas cifradas, perfil enmascarado, XSS, no-store e IDOR entre usuarios', async () => {
    const { app, inMemory } = buildTestContext();
    const agentA = request.agent(app);
    const agentB = request.agent(app);

    const regA = await agentA.post('/api/auth/register').send({
      name: 'Usuario A',
      email: 'a@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+506 8812-3456'
    });
    const csrfA = regA.body.csrfToken;

    const regB = await agentB.post('/api/auth/register').send({
      name: 'Usuario B',
      email: 'b@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+506 8899-7766'
    });
    assert.equal(regB.status, 201);

    // Teléfono enmascarado por defecto (RF-05) + cabecera Cache-Control no-store + revelado autorizado
    const profileRes = await agentA.get('/api/users/me');
    assert.equal(profileRes.status, 200);
    assert.ok(String(profileRes.headers['cache-control']).includes('no-store'));
    assert.equal(profileRes.body.profile.maskedPhone, '***-***-3456');

    const badReveal = await agentA
      .post('/api/users/me/reveal-phone')
      .set('X-CSRF-Token', csrfA)
      .send({ currentPassword: 'WrongPassword!123' });
    assert.equal(badReveal.status, 401);

    const okReveal = await agentA
      .post('/api/users/me/reveal-phone')
      .set('X-CSRF-Token', csrfA)
      .send({ currentPassword: 'PasswordSegura!2026' });
    assert.equal(okReveal.status, 200);
    assert.equal(okReveal.body.phone, '+506 8812-3456');

    // Crear nota con carga XSS y verificar almacenamiento cifrado
    const xssText = "<script>alert('XSS')</script> Secreto privado";
    const createRes = await agentA
      .post('/api/notes')
      .set('X-CSRF-Token', csrfA)
      .send({ title: 'Nota Confidencial', content: xssText });
    assert.equal(createRes.status, 201);
    const noteId = createRes.body.note.id;

    const storedNote = inMemory.inspect.notes.get(noteId);
    assert.ok(storedNote.encrypted_content.startsWith('v1.'));
    assert.equal(storedNote.encrypted_content.includes('Secreto privado'), false);

    // Usuario A puede leer y editar su nota
    const updateRes = await agentA
      .put(`/api/notes/${noteId}`)
      .set('X-CSRF-Token', csrfA)
      .send({ title: 'Nota Editada', content: 'Contenido actualizado seguro' });
    assert.equal(updateRes.status, 200);
    assert.equal(updateRes.body.note.content, 'Contenido actualizado seguro');

    // PRUEBA IDOR: Usuario B intenta leer, editar y borrar nota de Usuario A -> HTTP 403
    const idorGet = await agentB.get(`/api/notes/${noteId}`);
    assert.equal(idorGet.status, 403);
    assert.equal(idorGet.body.code, 'IDOR_FORBIDDEN');

    const idorPut = await agentB
      .put(`/api/notes/${noteId}`)
      .set('X-CSRF-Token', regB.body.csrfToken)
      .send({ title: 'Hack', content: 'Hack' });
    assert.equal(idorPut.status, 403);

    const idorDelete = await agentB
      .delete(`/api/notes/${noteId}`)
      .set('X-CSRF-Token', regB.body.csrfToken);
    assert.equal(idorDelete.status, 403);

    const idorEvents = inMemory.inspect.securityEvents.filter((e) => e.event_type === 'IDOR_ATTEMPT');
    assert.equal(idorEvents.length, 3);

    // Nota inexistente -> 404
    const notFoundRes = await agentA.get('/api/notes/99999');
    assert.equal(notFoundRes.status, 404);

    // Usuario A elimina su nota
    const delRes = await agentA.delete(`/api/notes/${noteId}`).set('X-CSRF-Token', csrfA);
    assert.equal(delRes.status, 200);

    // Límite de negocio (A06): máximo 50 notas por usuario
    for (let i = 1; i <= 50; i += 1) {
      const r = await agentA
        .post('/api/notes')
        .set('X-CSRF-Token', csrfA)
        .send({ title: `Nota ${i}`, content: `Contenido ${i}` });
      assert.equal(r.status, 201);
    }
    const overLimit = await agentA
      .post('/api/notes')
      .set('X-CSRF-Token', csrfA)
      .send({ title: 'Nota 51', content: 'Excede límite' });
    assert.equal(overLimit.status, 400);
    assert.equal(overLimit.body.code, 'NOTE_LIMIT_REACHED');
  });

  it('RF-03, RF-07 & A01/A05: RBAC estricto, auditoría, SQLi y prevención de auto-cambio de rol', async () => {
    const { app, config, inMemory } = buildTestContext();
    await seedAdmin(inMemory, config);

    const userAgent = request.agent(app);
    const adminAgent = request.agent(app);

    const regUser = await userAgent.post('/api/auth/register').send({
      name: 'Normal User',
      email: 'user@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+50688001122'
    });
    const userId = regUser.body.user.id;

    // Usuario normal bloqueado al intentar rutas admin -> 403
    const forbiddenStats = await userAgent.get('/api/admin/stats');
    assert.equal(forbiddenStats.status, 403);

    const forbiddenRoleSelf = await userAgent
      .patch(`/api/admin/users/${userId}/role`)
      .set('X-CSRF-Token', regUser.body.csrfToken)
      .send({ role: 'admin' });
    assert.equal(forbiddenRoleSelf.status, 403);

    // SQL Injection en login debe rechazarse sin bypass ni exposición
    const sqliLogin = await request(app).post('/api/auth/login').send({
      email: "' OR 1=1 --",
      password: 'PasswordSegura!2026'
    });
    assert.equal(sqliLogin.status, 400);

    // Login de admin real
    const adminLogin = await adminAgent.post('/api/auth/login').send({
      email: 'admin@securevault.test',
      password: 'AdminPassword!2026'
    });
    assert.equal(adminLogin.status, 200);
    const adminCsrf = adminLogin.body.csrfToken;
    const adminId = adminLogin.body.user.id;

    // Admin consulta estadísticas y usuarios (sin hashes ni contenido de notas)
    const statsRes = await adminAgent.get('/api/admin/stats');
    assert.equal(statsRes.status, 200);
    assert.equal(statsRes.body.stats.totalUsers, 2);

    const sqliSearch = await adminAgent.get("/api/admin/users?search=' OR 1=1 --");
    assert.equal(sqliSearch.status, 200);
    assert.equal(sqliSearch.body.users.length, 0);

    // Admin no puede cambiar su propio rol
    const selfChange = await adminAgent
      .patch(`/api/admin/users/${adminId}/role`)
      .set('X-CSRF-Token', adminCsrf)
      .send({ role: 'user' });
    assert.equal(selfChange.status, 403);

    // Admin cambia rol de usuario normal -> exitoso + auditoría + revocación de sesión previa
    const promoteRes = await adminAgent
      .patch(`/api/admin/users/${userId}/role`)
      .set('X-CSRF-Token', adminCsrf)
      .send({ role: 'admin' });
    assert.equal(promoteRes.status, 200);

    // La sesión vieja del usuario promovido queda revocada automáticamente (session_version++)
    const staleUserSession = await userAgent.get('/api/auth/me');
    assert.equal(staleUserSession.status, 401);
    assert.equal(staleUserSession.body.code, 'SESSION_REVOKED');

    const eventsRes = await adminAgent.get('/api/admin/events');
    assert.equal(eventsRes.status, 200);
    assert.ok(eventsRes.body.events.some((e) => e.eventType === 'ROLE_CHANGED'));
    assert.ok(eventsRes.body.events.some((e) => e.eventType === 'ADMIN_ACCESS_DENIED'));
  });

  it('A07 & Bonificación 5: Fuerza bruta genera HTTP 429, alerta crítica y validación anti-SSRF', async () => {
    const { app, inMemory, webhookCalls } = buildTestContext({
      SECURITY_ALERT_WEBHOOK_URL: 'https://93.184.216.34/webhook'
    });

    await request(app).post('/api/auth/register').send({
      name: 'Target User',
      email: 'target@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+50688001122'
    });

    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const failRes = await request(app).post('/api/auth/login').send({
        email: 'target@securevault.test',
        password: 'ClaveIncorrecta!999'
      });
      assert.equal(failRes.status, 401);
    }

    // Quinto intento dispara bloqueo progresivo HTTP 429 + alerta externa
    const fifthRes = await request(app).post('/api/auth/login').send({
      email: 'target@securevault.test',
      password: 'ClaveIncorrecta!999'
    });
    assert.equal(fifthRes.status, 429);
    assert.ok(fifthRes.headers['retry-after']);

    // Incluso con contraseña correcta, mientras está bloqueado responde 429
    const blockedValidRes = await request(app).post('/api/auth/login').send({
      email: 'target@securevault.test',
      password: 'PasswordSegura!2026'
    });
    assert.equal(blockedValidRes.status, 429);

    assert.ok(
      inMemory.inspect.securityEvents.some((e) => e.event_type === 'BRUTE_FORCE_ALERT')
    );
    assert.equal(webhookCalls.length, 1);

    // Verificación anti-SSRF (OWASP A01:2025)
    await assert.rejects(() => validateSafeWebhookUrl('http://127.0.0.1:4000/internal'));
    await assert.rejects(() => validateSafeWebhookUrl('https://169.254.169.254/latest/meta-data/'));
    await assert.rejects(() => validateSafeWebhookUrl('https://localhost/admin'));
  });

  it('RF-06: Recuperación de contraseña con token SHA-256 de un solo uso e invalidación de sesión', async () => {
    const { app, inMemory, sentEmails } = buildTestContext();
    const agent = request.agent(app);

    await agent.post('/api/auth/register').send({
      name: 'Reset User',
      email: 'reset@securevault.test',
      password: 'OldPassword!2026',
      phone: '+50688001122'
    });

    const forgotUnknown = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'noexiste@securevault.test' });
    const forgotReal = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reset@securevault.test' });

    // Respuesta idéntica sin enumeración ni token expuesto
    assert.equal(forgotUnknown.status, 200);
    assert.equal(forgotReal.status, 200);
    assert.equal(forgotUnknown.body.message, forgotReal.body.message);
    assert.equal(sentEmails.length, 1);

    const tokenMatch = sentEmails[0].text.match(/token=([0-9a-f]{64})/);
    assert.ok(tokenMatch, 'El correo debe incluir token de 64 hex');
    const rawToken = tokenMatch[1];

    // Verificar que en la BD solo existe el hash SHA-256
    assert.equal(inMemory.inspect.passwordResets.length, 1);
    assert.notEqual(inMemory.inspect.passwordResets[0].token_hash, rawToken);
    assert.match(inMemory.inspect.passwordResets[0].token_hash, /^[0-9a-f]{64}$/);

    // Uso válido actualiza contraseña e invalida la sesión anterior
    const resetRes = await request(app).post('/api/auth/reset-password').send({
      token: rawToken,
      newPassword: 'NewStrongPassword!2026'
    });
    assert.equal(resetRes.status, 200);

    const oldSessionCheck = await agent.get('/api/auth/me');
    assert.equal(oldSessionCheck.status, 401);

    // Reutilización del mismo token rechazada (400)
    const reuseRes = await request(app).post('/api/auth/reset-password').send({
      token: rawToken,
      newPassword: 'AnotherPassword!2026'
    });
    assert.equal(reuseRes.status, 400);
    assert.equal(reuseRes.body.code, 'RESET_TOKEN_ALREADY_USED');

    // Token expirado rechazado (400)
    await request(app).post('/api/auth/forgot-password').send({ email: 'reset@securevault.test' });
    const latestMatch = sentEmails[1].text.match(/token=([0-9a-f]{64})/);
    inMemory.inspect.passwordResets[1].expires_at = new Date(Date.now() - 60_000);
    const expiredRes = await request(app).post('/api/auth/reset-password').send({
      token: latestMatch[1],
      newPassword: 'AnotherPassword!2026'
    });
    assert.equal(expiredRes.status, 400);
    assert.equal(expiredRes.body.code, 'RESET_TOKEN_EXPIRED');
  });

  it('Bonificación 1 (MFA TOTP) y Bonificación 2 (Rotación de llaves v1 -> v2)', async () => {
    const inMemory = createInMemoryRepositories();
    const ctx1 = buildTestContext({}, { inMemory });
    const agent = request.agent(ctx1.app);

    const reg = await agent.post('/api/auth/register').send({
      name: 'MFA User',
      email: 'mfa@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+506 8833-4455'
    });
    let csrf = reg.body.csrfToken;

    // Crear nota cifrada bajo v1
    const noteRes = await agent
      .post('/api/notes')
      .set('X-CSRF-Token', csrf)
      .send({ title: 'Nota V1', content: 'Dato cifrado con llave v1' });
    assert.equal(noteRes.status, 201);
    const noteId = noteRes.body.note.id;
    assert.ok(inMemory.inspect.notes.get(noteId).encrypted_content.startsWith('v1.'));

    // Configurar y activar MFA TOTP
    const setupRes = await agent.post('/api/users/me/mfa/setup').set('X-CSRF-Token', csrf).send({});
    assert.equal(setupRes.status, 200);
    assert.ok(setupRes.body.qrDataUrl.startsWith('data:image/png;base64,'));

    const code = generateTotpCode(setupRes.body.secret);
    const enableRes = await agent
      .post('/api/users/me/mfa/enable')
      .set('X-CSRF-Token', csrf)
      .send({ code });
    assert.equal(enableRes.status, 200);
    assert.equal(enableRes.body.recoveryCodes.length, 8);

    // Logout y nuevo login con reto MFA
    await agent.post('/api/auth/logout').set('X-CSRF-Token', csrf).send({});
    const loginChallenge = await agent.post('/api/auth/login').send({
      email: 'mfa@securevault.test',
      password: 'PasswordSegura!2026'
    });
    assert.equal(loginChallenge.status, 200);
    assert.equal(loginChallenge.body.mfaRequired, true);
    csrf = loginChallenge.body.csrfToken;

    // Sin verificar TOTP no accede a notas
    const blockedNotes = await agent.get('/api/notes');
    assert.equal(blockedNotes.status, 401);

    // Verificación con código TOTP
    const validTotp = generateTotpCode(setupRes.body.secret);
    const verifyRes = await agent
      .post('/api/auth/mfa/verify')
      .set('X-CSRF-Token', csrf)
      .send({ code: validTotp });
    assert.equal(verifyRes.status, 200);

    // Ahora simulamos rotación de llaves reiniciando la app con v2 activa y v1 en PREVIOUS_KEYS
    const ctx2 = buildTestContext(
      {
        DATA_ENCRYPTION_KEY: KEY_V2_HEX,
        ENCRYPTION_KEY_VERSION: 'v2',
        DATA_ENCRYPTION_PREVIOUS_KEYS: `v1:${KEY_V1_HEX}`
      },
      { inMemory }
    );

    const agent2 = request.agent(ctx2.app);
    const login2 = await agent2.post('/api/auth/login').send({
      email: 'mfa@securevault.test',
      password: 'PasswordSegura!2026'
    });
    const recoveryVerify = await agent2
      .post('/api/auth/mfa/verify')
      .set('X-CSRF-Token', login2.body.csrfToken)
      .send({ code: enableRes.body.recoveryCodes[0] });
    assert.equal(recoveryVerify.status, 200);

    const readRotated = await agent2.get(`/api/notes/${noteId}`);
    assert.equal(readRotated.status, 200);
    assert.equal(readRotated.body.note.content, 'Dato cifrado con llave v1');
    assert.ok(inMemory.inspect.notes.get(noteId).encrypted_content.startsWith('v2.'));
  });

  it('A10: Error interno inesperado responde 500 genérico sin stack traces ni detalles SQL', async () => {
    const inMemory = createInMemoryRepositories();
    inMemory.repositories.noteRepository.findAllByOwner = async () => {
      throw new Error('ER_ACCESS_DENIED_ERROR: secret_db_host_10.0.0.5');
    };

    const { app } = buildTestContext({}, { inMemory });
    const agent = request.agent(app);

    await agent.post('/api/auth/register').send({
      name: 'Error User',
      email: 'err@securevault.test',
      password: 'PasswordSegura!2026',
      phone: '+50688001122'
    });

    const res = await agent.get('/api/notes');
    assert.equal(res.status, 500);
    assert.equal(res.body.error, 'Error interno del servidor.');
    assert.equal(JSON.stringify(res.body).includes('secret_db_host'), false);
    assert.equal(JSON.stringify(res.body).includes('ER_ACCESS_DENIED'), false);
  });
});
