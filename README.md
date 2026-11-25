# SecureVault

[![SecureVault CI/CD](https://github.com/ulyssesquiros-FWD/Sec-Vault/actions/workflows/ci.yml/badge.svg)](https://github.com/ulyssesquiros-FWD/Sec-Vault/actions/workflows/ci.yml)

**Sistema Full Stack seguro de bóveda de notas privadas** desarrollado de forma individual por **Ulysses Quiros** con **Node.js, Express.js, React + Vite, MySQL 8.4, bcrypt, AES-256-GCM (`node:crypto`) y controles verificables de OWASP Top 10:2025**.  
**Repositorio GitHub:** https://github.com/ulyssesquiros-FWD/Sec-Vault

---

## 1. Objetivos y Funcionalidades (Matriz Oficial RF-01 a RF-08)

| Requisito | Funcionalidad | Implementación en SecureVault |
|---|---|---|
| **RF-01** | **Registro de usuario** | Validación estricta Zod (`.strict()`), normalización de correo, prevención de duplicados (`UNIQUE`), rol forzado `user`, teléfono cifrado con AES-256-GCM y contraseña con **bcrypt (costo >= 12)** controlando el límite de 72 bytes UTF-8. |
| **RF-02** | **Inicio y cierre de sesión** | `express-session` respaldado por MySQL (`express-mysql-session`), cookies `HttpOnly` / `SameSite` / `Secure` en producción, regeneración del ID de sesión tras autenticar, expiración por inactividad y absoluta, revocación por `session_version`, bloqueo progresivo en MySQL (`HTTP 429`) y protección CSRF (`X-CSRF-Token`). |
| **RF-03** | **Roles: usuario y administrador** | Roles `user` y `admin` verificados exclusivamente en servidor (`authorizeRole`, `requireAdmin`). Previene auto-cambio de rol y mantiene separación de privilegios: el administrador no obtiene acceso automático a notas privadas de otros usuarios. |
| **RF-04** | **CRUD de notas privadas** | Límite de 50 notas por usuario y 20,000 caracteres por nota; contenido cifrado con **AES-256-GCM** e IV aleatorio de 12 bytes + AAD ligado al `id` y `owner_id`. Verificación estricta anti-IDOR (`verifyOwnership` + `WHERE id = ? AND owner_id = ?`). |
| **RF-05** | **Dato sensible del perfil cifrado y enmascarado** | Teléfono cifrado con AES-256-GCM y AAD (`user:<id>:phone`) en MySQL; visible por defecto enmascarado (`***-***-1234`) y revelado completo únicamente bajo re-autenticación de contraseña actual (`POST /api/users/me/reveal-phone`). |
| **RF-06** | **Recuperación de contraseña** | Tokens generados con `crypto.randomBytes(32)`, almacenados únicamente como hash **SHA-256** en MySQL (`password_resets`), uso único, expiración de 30 minutos (`UTC_TIMESTAMP()`), respuestas genéricas anti-enumeración, envío vía **Nodemailer** e invalidación automática de sesiones previas. |
| **RF-07** | **Panel administrativo y bitácora** | Dashboard con estadísticas reales, gestión controlada de roles, bitácora persistente en MySQL (`security_events`) + logs JSON estructurados con **Pino** (redacción de secretos) y alertas ante fuerza bruta o intentos IDOR. |
| **RF-08** | **Endpoint `GET /health`** | Responde `200 OK` con `{ "status": "ok" }` sin exponer versiones, credenciales, variables de entorno ni rutas internas. |

### Funcionalidades Complementarias y Bonificaciones Implementadas
- **MFA TOTP (Bonificación 1):** Configuración con código QR (`otpauth://`), verificación RFC 6238 de 6 dígitos y 8 códigos de recuperación de un solo uso guardados como SHA-256.
- **Rotación progresiva de llaves (Bonificación 2):** Soporte multi-versión (`v1`, `v2`, ...) mediante `DATA_ENCRYPTION_PREVIOUS_KEYS`, re-cifrado automático en lecturas, endpoint administrativo `POST /api/admin/crypto/rotate` y CLI `npm run crypto:rotate`.
- **Contenedorización Docker segura (Bonificación 3):** `Dockerfile` multi-stage con usuario no-root `node` y `docker-compose.yml` con MySQL 8.4 aislado y migración automática.
- **Escaneo de secretos Gitleaks (Bonificación 4):** Integrado en GitHub Actions con `.gitleaks.toml`.
- **Alertas externas anti-SSRF (Bonificación 5):** Notificaciones webhook HTTPS/correo con validación DNS/IP anti-SSRF.

---

## 2. Stack Tecnológico

| Capa | Tecnología |
|---|---|
| **Backend** | Node.js 22 LTS (ES Modules), Express.js 5 |
| **Base de datos** | MySQL 8.0+ / 8.4 (InnoDB, UTF8MB4) + `mysql2/promise` |
| **Sesiones** | `express-session` + `express-mysql-session` |
| **Hash de contraseñas** | `bcrypt` (costo mínimo 12) |
| **Cifrado simétrico** | `AES-256-GCM` mediante `node:crypto` + AAD + key versioning |
| **Validación y seguridad** | Zod, Helmet (CSP/HSTS/Frameguard), `express-rate-limit`, `Cache-Control: no-store` en `/api/*`, CSRF `timingSafeEqual` |
| **Logs y correo** | Pino (JSON estructurado) + Nodemailer |
| **Frontend** | React 19, Vite 6, React Router 7, CSS modular, Context API |
| **Pruebas y CI/CD** | `node:test`, Supertest, Vitest, React Testing Library, GitHub Actions (6 jobs + deploy), Gitleaks, Dependabot, Docker |

---

## 3. Arquitectura y Estructura del Proyecto

```text
SecureVault/
├── backend/                  # API REST Express + Servicios Criptográficos + Repositorios MySQL
│   ├── src/
│   │   ├── config/           # env.js (fail-closed), database.js, session.js, security.js, logger.js
│   │   ├── controllers/      # auth, password, user, note, admin
│   │   ├── middlewares/      # authenticateUser, authorizeRole, verifyOwnership, csrfProtection, rateLimiter, validateRequest, errorHandler
│   │   ├── repositories/     # Consultas parametrizadas mysql2/promise y transacciones
│   │   ├── routes/           # Rutas REST y /health
│   │   ├── services/         # passwordService, encryptionService, totpService, tokenService, sessionService, emailService, auditService, alertService
│   │   ├── validators/       # Esquemas Zod .strict()
│   │   ├── database/         # migrate.js y seed.js
│   │   └── jobs/             # rotateKeys.js (re-cifrado controlado)
│   └── tests/                # unit/, security/ (HTTP OWASP) e integration/mysql.integration.test.js
├── frontend/                 # SPA React + Vite (11+ pantallas reales conectadas a la API)
├── database/                 # schema.sql, migrations/*.sql y create-app-user.sql (mínimo privilegio)
├── docs/                     # Investigación de despliegue, arquitectura, STRIDE, informe OWASP, guion y evidencias
├── .github/                  # GitHub Actions CI/CD y Dependabot
├── Dockerfile                # Contenedor multi-stage no-root
├── docker-compose.yml        # Stack local aislado (MySQL 8.4 + migración one-shot + App)
└── PLAN_EJECUCION.md         # Seguimiento detallado de las 20 etapas
```

---

## 4. Requisitos Previos e Instalación Local

- **Node.js** `>= 22.0.0` LTS y **npm** `>= 10.0.0`.
- **MySQL** `8.0+` o `8.4 LTS` (local o vía Docker Compose).

### 4.1 Clonar repositorio e instalar dependencias reproducibles

```bash
git clone https://github.com/ulyssesquiros-FWD/Sec-Vault.git
cd Sec-Vault
npm --prefix backend ci
npm --prefix frontend ci
```

### 4.2 Configurar variables de entorno

Copia `.env.example` como `.env` en la raíz del proyecto (nunca subas `.env` a Git) y genera llaves criptográficas reales:

```bash
cp .env.example .env
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('DATA_ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'))"
```

Completa `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `SESSION_SECRET` y `DATA_ENCRYPTION_KEY` (siempre llaves criptográficas distintas). En producción, utiliza un usuario MySQL de privilegios mínimos solo DML (`securevault_app`, nunca `root`) y `DB_SSL=true` (añadiendo `DB_SSL_CA` en formato PEM, ruta o Base64 si tu proveedor gestionado usa una CA privada). Si deseas separar DDL de runtime durante `preDeployCommand`, define adicionalmente `MIGRATION_DB_USER` y `MIGRATION_DB_PASSWORD` para `npm run db:migrate`.

### 4.3 Crear base de datos, usuario mínimo y ejecutar migraciones

1. Crea la base de datos y el usuario de aplicación con mínimos privilegios (ver [database/create-app-user.sql](database/create-app-user.sql)):
   ```sql
   CREATE DATABASE IF NOT EXISTS securevault CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```
2. Ejecuta las migraciones SQL versionadas:
   ```bash
   npm run db:migrate
   ```
3. *(Opcional)* Inicializa la cuenta administrativa definiendo `SEED_ADMIN_EMAIL` y `SEED_ADMIN_PASSWORD` en `.env`:
   ```bash
   npm run db:seed
   ```

### 4.4 Ejecutar Backend, Frontend y Build

```bash
# Terminal 1: Backend API (puerto 4000)
npm run dev:backend

# Terminal 2: Frontend Vite dev server con proxy hacia /api y /health (puerto 5173)
npm run dev:frontend

# Compilar Frontend para producción (servido por Express en mismo origen)
npm run build
npm start
```

### 4.5 Ejecución Local con Docker Compose (Bonificación 3)

```bash
# Define DB_PASSWORD, MYSQL_ROOT_PASSWORD, SESSION_SECRET y DATA_ENCRYPTION_KEY en .env
docker compose up -d --build
```

El servicio `mysql` (`mysql:8.4`) escucha únicamente en `127.0.0.1:3306` dentro de la red interna `secvault_internal`, el servicio `migrate` aplica las migraciones idempotentes de forma automática antes de levantar `app` (usuario no-root `node`), y la app queda disponible en `http://127.0.0.1:4000`.

---

## 5. Pruebas Automatizadas y Auditoría

**Estado verificado localmente tras la última actualización:** `28/28` pruebas backend (unitarias, TLS estricto MySQL y HTTP OWASP), `3/3` pruebas reales de integración MySQL (`14` verificaciones + rechazo TLS sin CA), `4/4` pruebas frontend + build limpio en `frontend/dist`, `0` secretos en historial (`gitleaks v8.30.1`) y `0` vulnerabilidades en `npm audit`.

```bash
# Pruebas unitarias, validación TLS MySQL y suite HTTP OWASP Top 10:2025 (backend: 28/28 aprobadas)
npm run test:backend

# Pruebas reales de integración contra MySQL 8.4/9.x (requiere MySQL activo y TEST_DB_*: 3/3 suites, 14 checks aprobados)
REQUIRE_MYSQL=true npm run test:integration

# Pruebas de interfaz React y protección anti-XSS (frontend: 4/4 aprobadas)
npm run test:frontend

# Auditoría de dependencias (0 vulnerabilidades verificadas en backend y frontend)
npm run audit
```

---

## 6. Seguridad, Documentación y Despliegue en Producción

- **Investigación de despliegue (Fase 0):** [docs/investigacion-deploy.md](docs/investigacion-deploy.md)
- **Arquitectura y diagramas:** [docs/arquitectura.md](docs/arquitectura.md)
- **Modelo de amenazas STRIDE:** [docs/modelo-amenazas.md](docs/modelo-amenazas.md)
- **Informe OWASP Top 10:2025:** [docs/informe-seguridad.md](docs/informe-seguridad.md)
- **Guion de demostración y presentación (10 ejes):** [docs/demostracion.md](docs/demostracion.md)
- **Evidencias verificadas:** [docs/evidencias/README.md](docs/evidencias/README.md)
- **Plan de ejecución:** [PLAN_EJECUCION.md](PLAN_EJECUCION.md)

### Despliegue en Producción (Railway / Render + MySQL Gestionado)

El proyecto incluye [Dockerfile](Dockerfile), [railway.json](railway.json) y [render.yaml](render.yaml) listos para desplegar Express sirviendo `frontend/dist` en `same-origin` junto con MySQL 8.4 gestionado bajo TLS (`DB_SSL=true`).  
**URL pública:** *Pendiente de publicación en PaaS por el autor (requiere cuenta y secretos personales).*  
Consulta [docs/evidencias/README.md](docs/evidencias/README.md) para ejecutar las verificaciones funcionales (`GET /health`, registro, login, CRUD, IDOR, recuperación) y auditorías externas (**OWASP ZAP**, **SecurityHeaders**, **Qualys SSL Labs**) inmediatamente después de desplegar.
