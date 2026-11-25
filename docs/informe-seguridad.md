# Informe Técnico de Seguridad y Cumplimiento OWASP Top 10:2025 — SecureVault

**Autor:** Josué (Proyecto Individual)  
**Fecha:** 25 de noviembre de 2026  

---

## 1. Matriz de Cumplimiento OWASP Top 10:2025

| Categoría | Riesgo | Mitigación Implementada | Componente / Archivo | Prueba Ejecutada | Evidencia Real | Estado |
|---|---|---|---|---|---|---|
| **A01 — Broken Access Control** | Acceso indebido a notas ajenas (IDOR), escalación de roles o SSRF. | Middlewares `authenticateUser`, `requireAdmin`, `verifyOwnership`, consultas MySQL con `AND owner_id = ?`, bloqueo de auto-cambio de rol y validador anti-SSRF (`validateSafeWebhookUrl`). | `backend/src/middlewares/authorizeRole.js`, `verifyOwnership.js`, `repositories/noteRepository.js`, `services/alertService.js` | Pruebas HTTP de IDOR (`403`), acceso admin bloqueado a `user` (`403`), auto-cambio de rol (`403`) y bloqueo de `127.0.0.1` / `169.254.169.254`. | `docs/evidencias/backend-tests.txt` (Subtests 4, 5 y 6) | **Implementado y verificado (local)** |
| **A02 — Security Misconfiguration** | Cabeceras faltantes, `X-Powered-By`, CORS abierto o fugas en `/health`. | `app.disable('x-powered-by')`, Helmet con CSP estricta (`script-src 'self'`), HSTS en producción, `X-Frame-Options: DENY`, `Permissions-Policy`, CORS estricto por origen, `/health` mínimo y fail-closed en `env.js`. | `backend/src/config/security.js`, `env.js`, `routes/healthRoutes.js` | Prueba HTTP de `/health` (`{"status":"ok"}`), verificación de cabeceras y arranque rechazado sin llaves. | `docs/evidencias/backend-tests.txt` (Subtest 1 y Validators); **SecurityHeaders.com pendiente tras deploy** | **Implementado; verificación externa pendiente post-deploy** |
| **A03 — Software Supply Chain Failures** | Dependencias vulnerables o filtración de secretos. | `package-lock.json` + `npm ci`, `overrides` de `mysql2@^3.24.6`, actualización de `zod@^4.6.7`, `nodemailer@^10.6.1`, `vitest@^5.1.2`, Dependabot semanal, Gitleaks y GitHub Actions CI. | `backend/package.json`, `frontend/package.json`, `.github/workflows/ci.yml`, `.github/dependabot.yml`, `.gitleaks.toml` | Ejecución de `npm audit` en backend y frontend. | `docs/evidencias/npm-audit.txt` (**0 vulnerabilidades** en ambos); **Gitleaks en CI pendiente de push** | **Implementado; Gitleaks en CI pendiente de push** |
| **A04 — Cryptographic Failures** | Contraseñas débiles, datos privados en texto plano o reutilización de IV. | `bcrypt` con costo mínimo 12 y límite explícito <= 72 bytes UTF-8; `AES-256-GCM` (`node:crypto`) con llave 32B, IV aleatorio 12B, tag 16B, AAD contextual y rotación de versiones; TLS estricto hacia MySQL en producción. | `backend/src/services/passwordService.js`, `encryptionService.js`, `config/database.js` | Pruebas unitarias de hash/salt/72B, cifrado/tag/AAD/rotación y verificación de registros en HTTP suite. | `docs/evidencias/backend-tests.txt` (Suites 2, 3 y Subtests 2, 4, 8); **SSL Labs pendiente tras deploy** | **Implementado; SSL Labs pendiente post-deploy** |
| **A05 — Injection** | Inyección SQL y Cross-Site Scripting (XSS). | Sentencias parametrizadas `?` en `mysql2/promise`, validación Zod `.strict()`, escape automático en React (sin `dangerouslySetInnerHTML`), `X-Content-Type-Options: nosniff` y CSP `script-src 'self'`. | `backend/src/repositories/*.js`, `validators/*.js`, `middlewares/validateRequest.js`, `frontend/src/Pages/*` | Pruebas con `' OR 1=1 --` en login/búsqueda y `<script>alert('XSS')</script>` en API y DOM React. | `docs/evidencias/backend-tests.txt` (Subtests 4, 5) y `frontend-tests-and-build.txt` | **Implementado y verificado** |
| **A06 — Insecure Design** | Abuso de negocio, falta de modelado de amenazas o escalación masiva. | Modelo STRIDE completo, límite 50 notas/usuario y 20,000 caracteres/nota, cuerpo JSON <= 64kb, denegación por defecto y separación de privilegios admin/usuario. | `docs/modelo-amenazas.md`, `repositories/noteRepository.js`, `validators/noteValidators.js`, `app.js` | Prueba HTTP creando 50 notas y verificando rechazo de la #51 (`400 NOTE_LIMIT_REACHED`). | `docs/evidencias/backend-tests.txt` (Subtest 4) y `docs/modelo-amenazas.md` | **Implementado y verificado** |
| **A07 — Authentication Failures** | Fuerza bruta, session fixation, cookies inseguras o enumeración. | `express-session` + `express-mysql-session`, `HttpOnly`, `SameSite`, `Secure` en prod, `session.regenerate()`, expiración por inactividad/absoluta, `session_version`, bloqueo progresivo persistente en MySQL + `express-rate-limit`, respuestas genéricas y MFA TOTP. | `backend/src/config/session.js`, `services/sessionService.js`, `totpService.js`, `repositories/loginAttemptRepository.js`, `controllers/authController.js` | Pruebas de regeneración de sesión, expiración `401`, fuerza bruta `429` y flujo MFA TOTP. | `docs/evidencias/backend-tests.txt` (Subtests 2, 3, 6, 8) | **Implementado y verificado** |
| **A08 — Software or Data Integrity Failures** | Alteración de sesiones/datos, mass assignment o tokens débiles. | Zod `.strict()`, protección CSRF con `timingSafeEqual`, tag AES-256-GCM + AAD, tokens `randomBytes(32)` guardados como SHA-256 de un solo uso y CI/CD con `npm ci`. *Nota:* Al usar sesiones en MySQL (no JWT), la integridad se protege mediante firma HMAC de `express-session` + validación contra BD (`session_version`), no aplicando validación de firmas JWT. | `backend/src/middlewares/csrfProtection.js`, `services/tokenService.js`, `repositories/passwordResetRepository.js` | Pruebas de rechazo CSRF (`403`), adulteración de tag/AAD, reutilización/expiración de token y mass assignment. | `docs/evidencias/backend-tests.txt` (Suites 2, 4, 6 y Subtests 2, 7) | **Implementado y verificado** |
| **A09 — Security Logging and Alerting Failures** | Ausencia de auditoría, registro de secretos o falta de alertas. | Logs JSON Pino con `redact` estricto de contraseñas/tokens/notas/cookies, bitácora persistente en `security_events`, alertas ante fuerza bruta/IDOR/escalación con webhook anti-SSRF y panel administrativo con filtros. | `backend/src/config/logger.js`, `services/auditService.js`, `alertService.js`, `Pages/AdminEventsPage.jsx` | Verificación de creación de eventos `IDOR_ATTEMPT`, `ADMIN_ACCESS_DENIED`, `ROLE_CHANGED` y `BRUTE_FORCE_ALERT` + disparo de webhook. | `docs/evidencias/backend-tests.txt` (Subtests 4, 5, 6) | **Implementado y verificado** |
| **A10 — Mishandling of Exceptional Conditions** | Fuga de stack traces/SQL, estado inconsistente tras error o cuelgues. | Manejador global `errorHandler.js` con respuestas `500` genéricas, `withTransaction` con rollback automático, timeouts en HTTP/MySQL/SMTP y captura de `unhandledRejection`/`uncaughtException` fail-closed. | `backend/src/middlewares/errorHandler.js`, `config/database.js`, `server.js` | Prueba HTTP forzando excepción con host interno SQL -> responde `500` genérico sin filtrar detalles. | `docs/evidencias/backend-tests.txt` (Subtest 9) | **Implementado y verificado** |

---

## 2. Decisiones Criptográficas y de Persistencia

### 2.1 Por qué `bcrypt` (costo >= 12) para contraseñas
- `bcrypt` está diseñado específicamente para derivación lenta de contraseñas con *salt* aleatorio automático por registro (resistente a tablas arcoíris y ataques por GPU/ASIC).
- Se exige costo mínimo **12** (`$2b$12$...`) y se valida el límite real de **72 bytes UTF-8** antes del hash (`passwordService.js`), rechazando entradas mayores en lugar de truncarlas silenciosamente.
- Nunca se utiliza `MD5`, `SHA-1`, `SHA-256` simple ni cifrado reversible para almacenar contraseñas.

### 2.2 Por qué `AES-256-GCM` con AAD para notas y datos personales
- A diferencia de notas o teléfonos que el usuario autorizado necesita recuperar, las contraseñas solo se verifican. Para notas y teléfono se emplea **AES-256-GCM** mediante `node:crypto` nativo:
  - Llave de **256 bits** (32 bytes) gestionada fuera del código.
  - **IV aleatorio único de 96 bits (12 bytes)** por cada operación de cifrado, garantizando que dos notas idénticas produzcan textos cifrados totalmente distintos.
  - **Authentication Tag de 128 bits (16 bytes)** + **AAD contextual** (`note:<id>:owner:<owner_id>` o `user:<id>:phone`) que impide copiar un bloque cifrado de un usuario/registro a otro o modificar un solo bit sin invalidar el descifrado.

### 2.3 Tokens de recuperación de contraseña (SHA-256)
- Se generan con `crypto.randomBytes(32)` (256 bits de entropía) y se almacenan únicamente como hash **SHA-256** en `password_resets` con vigencia de **30 minutos**, un solo uso (`used_at`) e invalidación inmediata de todas las sesiones activas al aplicarse (`session_version++`).

### 2.4 Por qué sesiones en MySQL frente a JWT (A08)
- `express-session` + `express-mysql-session` permite **revocación inmediata real en el servidor** (al cerrar sesión, cambiar contraseña, restablecer clave o cambiar el rol de un usuario).
- La cookie `secvault.sid` solo transporta un identificador firmado por `SESSION_SECRET` con banderas `HttpOnly`, `SameSite=Lax` y `Secure` en producción, sin exponer claims en el cliente ni usar `localStorage`.

### 2.5 Elección justificada de MySQL 8.0+/8.4
- Aunque la guía del laboratorio menciona PostgreSQL o MongoDB, el estudiante eligió **MySQL 8.0+/8.4** por requerimiento individual aprovechando InnoDB (transacciones ACID y llaves foráneas), conjunto de caracteres `utf8mb4`, consultas parametrizadas con `mysql2/promise` y persistencia nativa de sesiones con `express-mysql-session`.

### 2.6 Gestión y Rotación de Llaves
- Formato serializado por registro: `version.ivBase64.tagBase64.ciphertextBase64` (`v1....`).
- Para rotar llaves sin pérdida de datos:
  1. Conservar la llave saliente en `DATA_ENCRYPTION_PREVIOUS_KEYS=v1:<hex_anterior>`.
  2. Configurar la nueva llave en `DATA_ENCRYPTION_KEY=<hex_nuevo>` y actualizar `ENCRYPTION_KEY_VERSION=v2`.
  3. Ejecutar `POST /api/admin/crypto/rotate` o `npm run crypto:rotate` (además del re-cifrado progresivo automático en lecturas).
- **Advertencia crítica:** Si se pierde la llave de una versión sin respaldo seguro antes de completar la rotación, los datos cifrados con esa versión **son irrecuperables permanentemente**.

---

## 3. Resultados Verificados y Verificaciones Externas Pendientes

### Ejecuciones locales reales (2026-11-25)
- **Pruebas unitarias y HTTP OWASP Backend (`npm --prefix backend test`):** **24/24 aprobadas (0 fallos, 0 omitidas)**.
- **Pruebas Frontend (`npm --prefix frontend test`):** **4/4 aprobadas (0 fallos)**.
- **Compilación Frontend (`npm --prefix frontend run build`):** **Exitosa** (`frontend/dist` generado en 4.67s).
- **Auditoría de dependencias (`npm audit`):** **0 vulnerabilidades** tanto en backend (162 paquetes) como en frontend (146 paquetes).

### Verificaciones pendientes (requieren entorno MySQL real o URL pública desplegada)
- **Pruebas reales contra MySQL 8.4 (`backend/tests/integration/mysql.integration.test.js`):** Lista y configurada en `.github/workflows/ci.yml` (`mysql:8.4`), pendiente de ejecutarse con una instancia MySQL local o al hacer `git push` a GitHub Actions.
- **Gitleaks en historial completo:** Configurado en `.github/workflows/ci.yml` y `.gitleaks.toml`; pendiente de ejecución en GitHub Actions (binario `gitleaks` no instalado localmente).
- **OWASP ZAP Baseline Scan:** Pendiente de ejecución tras desplegar la URL HTTPS pública:
  ```bash
  docker run --rm -v "$(pwd)/docs/evidencias:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://TU-URL-PUBLICA -r owasp-zap-report.html
  ```
- **SecurityHeaders.com y Qualys SSL Labs:** Pendientes de evaluación sobre el dominio HTTPS público de producción.

---

## 4. Riesgos Residuales Aceptados

1. **Custodia de llaves en PaaS:** La seguridad de los datos cifrados depende de mantener protegidos `DATA_ENCRYPTION_KEY` y `SESSION_SECRET` en el gestor de secretos de la plataforma y contar con respaldo cifrado offline de las llaves.
2. **Disponibilidad ante correos SMTP externos:** Si no se configuran credenciales SMTP válidas, la recuperación de contraseña registra la solicitud de forma segura pero no puede entregar el correo saliente hasta configurar `SMTP_HOST`, `SMTP_USER` y `SMTP_PASSWORD`.
3. **Compromiso del dispositivo final del usuario:** Un malware o extensión maliciosa en el navegador del cliente autenticado podría leer datos visibles en pantalla mientras dure la sesión.
