# Informe Técnico de Seguridad y Cumplimiento OWASP Top 10:2025 — SecureVault

**Autor:** Ulysses Quiros (Proyecto Individual)  
**Repositorio:** https://github.com/ulyssesquiros-FWD/Sec-Vault  
**Fecha de auditoría y actualización:** 25 de noviembre de 2026  

---

## 1. Matriz de Requisitos Funcionales (RF-01 a RF-08 — Numeración Oficial del Laboratorio)

| Requisito | Funcionalidad Oficial | Estado | Verificación Realizada | Observaciones |
|---|---|---|---|---|
| **RF-01** | Registro de usuario | **Implementado y verificado (HTTP + MySQL)** | Suite HTTP (`httpSecurity.test.js`) y suite real `mysql.integration.test.js` contra MySQL local y CI | Validación Zod `.strict()`, correo normalizado + `UNIQUE`, rol forzado `user`, `bcrypt >= 12`. |
| **RF-02** | Inicio y cierre de sesión | **Implementado y verificado (HTTP + MySQL)** | Regeneración de sesión, cookies `HttpOnly`/`SameSite`, expiración `401`, CSRF `403`, logout | Persistencia real `express-mysql-session` verificada en MySQL local (`sessions`). |
| **RF-03** | Roles: usuario y administrador | **Implementado y verificado (HTTP + MySQL)** | Bloqueo `403` a `user` en `/api/admin/*`, prevención de auto-cambio de rol, `session_version++` | Admin no tiene acceso automático a notas privadas ajenas. |
| **RF-04** | CRUD de notas privadas | **Implementado y verificado (HTTP + MySQL)** | Crear, leer, editar, eliminar, límite 50 notas y bloqueo IDOR `403` entre usuarios | Contenido cifrado con AES-256-GCM + AAD `note:<id>:owner:<owner_id>`. |
| **RF-05** | Dato sensible del perfil cifrado y enmascarado | **Implementado y verificado (HTTP + MySQL)** | Teléfono almacenado cifrado (`v1.`), devuelto como `***-***-3456` y revelado solo tras contraseña | Re-autenticación obligatoria para revelar teléfono completo. |
| **RF-06** | Recuperación de contraseña | **Implementado y verificado (HTTP + MySQL)** | Token `randomBytes(32)`, hash SHA-256 en MySQL (`UTC_TIMESTAMP()`), uso único y expiración | Requiere credenciales SMTP reales en producción para envío saliente. |
| **RF-07** | Panel administrativo y bitácora | **Implementado y verificado (HTTP + MySQL + UI)** | Estadísticas, gestión de roles, filtros de bitácora en `security_events` y alertas | Logs Pino JSON con `redact` estricto de secretos. |
| **RF-08** | Endpoint `GET /health` | **Implementado y verificado (HTTP + MySQL)** | Responde `200 OK` `{ "status": "ok" }` sin exponer datos internos | Listo para healthchecks de Docker, Railway y Render. |

**Funcionalidades complementarias (bonificaciones):** MFA TOTP (`totpService.js` + QR + códigos de recuperación), rotación progresiva de llaves (`v1 -> v2`), Docker multi-stage no-root + Compose, Gitleaks en CI y alertas webhook anti-SSRF.

---

## 2. Matriz de Cumplimiento OWASP Top 10:2025 (Tras Auditoría de Seguridad)

| Categoría | Riesgo | Mitigación Implementada | Componente / Archivo | Prueba Ejecutada | Evidencia Real | Estado |
|---|---|---|---|---|---|---|
| **A01 — Broken Access Control** | Acceso indebido a notas ajenas (IDOR), escalación de roles o SSRF. | Middlewares `authenticateUser`, `requireAdmin`, `verifyOwnership`, consultas MySQL con `AND owner_id = ?`, bloqueo de auto-cambio de rol y validador anti-SSRF (`validateSafeWebhookUrl`). | `backend/src/middlewares/authorizeRole.js`, `verifyOwnership.js`, `repositories/noteRepository.js`, `services/alertService.js` | Pruebas HTTP de IDOR (`403`), acceso admin bloqueado a `user` (`403`), auto-cambio de rol (`403`) y bloqueo SSRF (`127.0.0.1`, `169.254.169.254`). | `docs/evidencias/backend-tests.txt` (Subtests 4, 5 y 6) | **Implementado y verificado (local)** |
| **A02 — Security Misconfiguration** | Cabeceras faltantes, `X-Powered-By`, caché de datos sensibles, cookies inconsistentes o fugas en `/health`. | `app.disable('x-powered-by')`, Helmet CSP estricta (`script-src 'self'`), HSTS en producción, `X-Frame-Options: DENY`, `Permissions-Policy`, `Cache-Control: no-store, private` en `/api/*`, `sessionMiddleware` acotado a `/api`, `getClearCookieOptions` consistente, CORS estricto, `/health` mínimo y `env.js` fail-closed. | `backend/src/config/security.js`, `env.js`, `session.js`, `app.js`, `routes/healthRoutes.js` | Prueba HTTP de `/health`, cabeceras Helmet + `Cache-Control: no-store` y rechazo de arranque sin llaves. | `docs/evidencias/backend-tests.txt` (Subtests 1, 4 y Validators); **SecurityHeaders.com pendiente tras deploy** | **Implementado; auditoría externa pendiente post-deploy** |
| **A03 — Software Supply Chain Failures** | Dependencias vulnerables o filtración de secretos. | `package-lock.json` + `npm ci`, `overrides` de `mysql2@^3.24.6`, actualización de `zod@^4.6.7`, `nodemailer@^10.6.1`, `vitest@^5.1.2`, Dependabot semanal, `.gitleaks.toml` y CI de 6 trabajos. | `backend/package.json`, `frontend/package.json`, `.github/workflows/ci.yml`, `.github/dependabot.yml`, `.gitleaks.toml` | `npm ci` + `npm audit --audit-level=high` en backend/frontend y escaneo local de patrones en Git. | `docs/evidencias/npm-audit.txt` (**0 vulnerabilidades** en ambos); **Gitleaks Action pendiente de push a GitHub** | **Implementado; Gitleaks en CI pendiente de push** |
| **A04 — Cryptographic Failures** | Contraseñas débiles, datos privados en texto plano, reutilización de IV o TLS relajado hacia MySQL. | `bcrypt` costo >= 12 y límite <= 72B UTF-8; `AES-256-GCM` (`node:crypto`) con llave 32B, IV aleatorio 12B, tag 16B, AAD contextual y rotación de versiones; TLS estricto (`rejectUnauthorized: true`, CA PEM/Base64) compartido entre pool y migraciones. | `backend/src/services/passwordService.js`, `encryptionService.js`, `config/database.js`, `database/migrate.js` | Pruebas unitarias de hash/salt/72B, cifrado/tag/AAD/rotación y verificación HTTP. | `docs/evidencias/backend-tests.txt` (Suites 2, 3 y Subtests 2, 4, 8); **Qualys SSL Labs pendiente tras deploy** | **Implementado; SSL Labs pendiente post-deploy** |
| **A05 — Injection** | Inyección SQL y Cross-Site Scripting (XSS). | Sentencias parametrizadas `?` en `mysql2/promise`, validación Zod `.strict()`, escape automático en React (cero `dangerouslySetInnerHTML`), `X-Content-Type-Options: nosniff` y CSP `script-src 'self'`. | `backend/src/repositories/*.js`, `validators/*.js`, `middlewares/validateRequest.js`, `frontend/src/Pages/*` | Pruebas con `' OR 1=1 --` en login/búsqueda y `<script>alert('XSS')</script>` en API y DOM React. | `docs/evidencias/backend-tests.txt` (Subtests 4, 5) y `frontend-tests-and-build.txt` | **Implementado y verificado** |
| **A06 — Insecure Design** | Abuso de negocio, falta de modelado de amenazas o escalación masiva. | Modelo STRIDE completo, límite 50 notas/usuario y 20,000 caracteres/nota, payload JSON <= 64kb, denegación por defecto y separación de privilegios admin/usuario. | `docs/modelo-amenazas.md`, `repositories/noteRepository.js`, `validators/noteValidators.js`, `app.js` | Prueba HTTP creando 50 notas y verificando rechazo de la #51 (`400 NOTE_LIMIT_REACHED`). | `docs/evidencias/backend-tests.txt` (Subtest 4) y `docs/modelo-amenazas.md` | **Implementado y verificado** |
| **A07 — Authentication Failures** | Fuerza bruta, session fixation, cookies inseguras o enumeración. | `express-session` + `express-mysql-session`, `HttpOnly`, `SameSite`, `Secure` en prod, `session.regenerate()`, expiración inactividad/absoluta, `session_version`, bloqueo progresivo persistente en MySQL + `express-rate-limit`, respuestas genéricas y MFA TOTP. | `backend/src/config/session.js`, `services/sessionService.js`, `totpService.js`, `repositories/loginAttemptRepository.js`, `controllers/authController.js` | Pruebas de regeneración de sesión, expiración `401`, fuerza bruta `429` y flujo MFA TOTP. | `docs/evidencias/backend-tests.txt` (Subtests 2, 3, 6, 8) | **Implementado y verificado** |
| **A08 — Software or Data Integrity Failures** | Alteración de sesiones/datos, mass assignment o tokens débiles. | Zod `.strict()`, CSRF `timingSafeEqual`, tag AES-GCM + AAD, tokens `randomBytes(32)` guardados como SHA-256 con `UTC_TIMESTAMP()` y CI con `npm ci`. *Nota:* Al usar sesiones en MySQL (no JWT), no aplica validación de firmas JWT. | `backend/src/middlewares/csrfProtection.js`, `services/tokenService.js`, `repositories/passwordResetRepository.js` | Pruebas de rechazo CSRF (`403`), adulteración de tag/AAD, reutilización/expiración de token y mass assignment. | `docs/evidencias/backend-tests.txt` (Suites 2, 4, 6 y Subtests 2, 7) | **Implementado y verificado** |
| **A09 — Security Logging and Alerting Failures** | Ausencia de auditoría, registro de secretos o falta de alertas. | Logs JSON Pino con `redact` estricto, bitácora persistente en `security_events`, alertas ante fuerza bruta/IDOR/escalación con webhook anti-SSRF y vista admin con filtros. | `backend/src/config/logger.js`, `services/auditService.js`, `alertService.js`, `Pages/AdminEventsPage.jsx` | Verificación de creación de eventos `IDOR_ATTEMPT`, `ADMIN_ACCESS_DENIED`, `ROLE_CHANGED` y `BRUTE_FORCE_ALERT` + webhook. | `docs/evidencias/backend-tests.txt` (Subtests 4, 5, 6) | **Implementado y verificado** |
| **A10 — Mishandling of Exceptional Conditions** | Fuga de stack traces/SQL, estado inconsistente tras error o cuelgues. | Manejador global `errorHandler.js` con respuestas `500` genéricas, `withTransaction` con rollback automático, timeouts en HTTP/MySQL/SMTP y `unhandledRejection`/`uncaughtException` fail-closed. | `backend/src/middlewares/errorHandler.js`, `config/database.js`, `server.js` | Prueba HTTP forzando excepción con host SQL interno -> responde `500` genérico sin fugas. | `docs/evidencias/backend-tests.txt` (Subtest 9) | **Implementado y verificado** |

---

## 3. Correcciones Realizadas Durante la Auditoría de Continuación

1. **Alineación exacta de RF-01 a RF-08:** Se corrigió el intercambio previo entre `RF-03` (Roles) y `RF-05` (Dato sensible del perfil cifrado/enmascarado) en documentación y suites de prueba, clasificando MFA, rotación y Docker como funcionalidades complementarias.
2. **Zona horaria UTC en recuperación de contraseña:** `passwordResetRepository.js` ahora usa `UTC_TIMESTAMP()` para guardar `used_at` y comparar expiración en consonancia con `timezone: 'Z'` del pool `mysql2`.
3. **Hardening de caché y sesiones API:** Se añadió `Cache-Control: no-store, no-cache, must-revalidate, private` en `/api/*`, se acotó `sessionMiddleware` exclusivamente a `/api`, y se unificó `getClearCookieOptions(config)` al limpiar la cookie `secvault.sid`.
4. **TLS uniforme entre pool y migraciones:** `migrate.js` reutiliza `buildSslOptions(config.db)` con soporte para certificados CA en PEM directo, archivo o Base64 y `rejectUnauthorized: true`.
5. **Suite MySQL real ampliada a 14 verificaciones + CI separado en 6 trabajos:** `mysql.integration.test.js` verifica pool concurrente, InnoDB/UTF8MB4, registro, `UNIQUE`, SQLi, transacciones, rollback, FKs, CRUD cifrado, IDOR, `bcrypt`, `sessions`, `password_resets`, `security_events` y `login_attempts`; falla obligatoriamente si `REQUIRE_MYSQL=true` y MySQL no está accesible.
6. **Corrección en `docker-compose.yml`:** Se eliminó el montaje de migraciones en `/docker-entrypoint-initdb.d` y se añadió el servicio one-shot `migrate` antes de `app`, dejando valores por defecto de desarrollo local reproducibles sin romper el modo producción del `Dockerfile`.
7. **Limpieza de `package-lock.json` y `npm ci` reproducible:** Se eliminó la referencia espuria `"securevault-monorepo": "file:.."` en `backend/` y `frontend/` y se verificó `npm ci` limpio en ambos subproyectos (0 vulnerabilidades).
8. **Endurecimiento final para Railway y Gitleaks v8.30.1:** Se deshabilitó `createDatabaseTable` de sesiones en producción (compatible con usuario DML-only `securevault_app`), se añadió soporte opcional de `MIGRATION_DB_USER` para migraciones DDL, se impidió reutilizar `SESSION_SECRET === DATA_ENCRYPTION_KEY` en `env.js`, se exigió contraseña >= 12 caracteres en `seed.js`, y se actualizó CI para ejecutar `gitleaks` CLI `v8.30.1` directamente con `[[allowlists]]` explícitos.

---

## 4. Decisiones Criptográficas y de Persistencia

- **Contraseñas (`bcrypt >= 12`):** Derivación lenta con salt automático por usuario y validación explícita del límite de 72 bytes UTF-8 (`passwordService.js`) sin truncamientos silenciosos.
- **Notas y teléfonos (`AES-256-GCM`):** Llave de 256 bits, IV aleatorio único de 12 bytes por cifrado, Authentication Tag de 16 bytes y AAD contextual (`note:<id>:owner:<owner_id>` / `user:<id>:phone`).
- **Tokens de recuperación (`SHA-256`):** `crypto.randomBytes(32)` almacenado solo como digest SHA-256 con un solo uso y expiración de 30 minutos.
- **Rotación de llaves:** Formato `version.ivB64.tagB64.ciphertextB64` permitiendo mantener llaves previas en `DATA_ENCRYPTION_PREVIOUS_KEYS` y migrar progresivamente hacia la versión activa. **Advertencia:** perder una llave sin respaldo implica pérdida irreversible de los datos cifrados con esa versión.
- **Elección de MySQL:** Justificada como alternativa relacional ACID al stack sugerido (PostgreSQL/MongoDB), aprovechando InnoDB, `utf8mb4`, `mysql2/promise` parametrizado y sesiones persistentes `express-mysql-session`.

---

## 5. Resultados Verificados y Pendientes Honestos

- **Backend unitario y HTTP OWASP (`npm --prefix backend test`):** **25/25 pruebas aprobadas (0 fallos)**.
- **Integración MySQL real (`backend/tests/integration/mysql.integration.test.js`):** Ejecutada y aprobada localmente contra MySQL `InnoDB`/`utf8mb4` (**3/3 subtests cubriendo las 14 verificaciones reales, 0 fallos**), verificada en modo fail-closed (`REQUIRE_MYSQL=true` falla si MySQL no responde) y configurada en `.github/workflows/ci.yml` contra `mysql:8.4`.
- **Frontend (`npm --prefix frontend test` y `build`):** **4/4 pruebas aprobadas** y build Vite limpio.
- **Auditoría de dependencias (`npm audit`):** **0 vulnerabilidades** en backend y **0 vulnerabilidades** en frontend.
- **Escaneo de secretos (`gitleaks v8.30.1`):** **0 secretos filtrados (`no leaks found`)** en el historial Git completo.
- **Pendientes externos (Pasos 7–9 de despliegue):** Provisión y secrets en Railway por el autor, despliegue público HTTPS, pruebas E2E en la URL pública, **OWASP ZAP Baseline Scan**, **SecurityHeaders.com** y **Qualys SSL Labs**.
