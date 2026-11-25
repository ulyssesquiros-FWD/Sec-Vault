# SecureVault

**Sistema Full Stack seguro de bóveda de notas privadas** desarrollado de forma individual por **Josué** con **Node.js, Express.js, React + Vite, MySQL, bcrypt, AES-256-GCM (`node:crypto`) y controles verificables de OWASP Top 10:2025**.

---

## 1. Objetivos y Funcionalidades

SecureVault protege información confidencial de usuarios mediante defensa en profundidad en cada capa:

- **RF-01 Registro seguro:** Validación estricta con Zod, normalización de correo, prevención de duplicados, rol forzado `user`, teléfono cifrado con AES-256-GCM y contraseña hasheada con **bcrypt (costo >= 12)** controlando el límite de 72 bytes UTF-8.
- **RF-02 Autenticación y sesiones persistentes:** `express-session` respaldado por MySQL (`express-mysql-session`), cookies `HttpOnly` / `SameSite` / `Secure` en producción, regeneración del ID de sesión tras autenticar, expiración por inactividad/absoluta, revocación por `session_version`, bloqueo progresivo persistente en MySQL (`HTTP 429`) y protección CSRF mediante `X-CSRF-Token`.
- **RF-03 Perfil seguro:** Teléfono enmascarado por defecto (`***-***-1234`), revelado autorizado tras confirmar contraseña actual y actualización segura de contraseña.
- **RF-04 CRUD de notas privadas cifradas:** Máximo 50 notas por usuario y 20,000 caracteres por nota; contenido cifrado con **AES-256-GCM** e IV único de 12 bytes + AAD ligado al `id` y `owner_id`. Verificación estricta anti-IDOR en middleware y consultas SQL (`WHERE id = ? AND owner_id = ?`).
- **RF-05 Control de roles (RBAC):** Roles `user` y `admin` verificados exclusivamente en servidor. El administrador gestiona usuarios y auditoría sin obtener acceso automático a notas privadas de otros usuarios.
- **RF-06 Recuperación segura de contraseña:** Tokens aleatorios (`crypto.randomBytes(32)`), almacenados únicamente como hash **SHA-256** en MySQL, de un solo uso, con expiración de 30 minutos, respuestas genéricas anti-enumeración, envío vía **Nodemailer** e invalidación automática de sesiones activas.
- **RF-07 Panel administrativo y bitácora:** Métricas globales, gestión controlada de roles, bitácora persistente en MySQL (`security_events`) + logs JSON estructurados con **Pino** (redacción de secretos) y alertas ante fuerza bruta o intentos IDOR.
- **RF-08 Endpoint de salud:** `GET /health` responde `{ "status": "ok" }` sin exponer versiones, credenciales ni rutas internas.
- **Bonificaciones incluidas:** MFA TOTP con QR y códigos de recuperación, rotación de versiones de llaves AES-256-GCM, Docker multi-stage no-root + `docker-compose.yml`, escaneo Gitleaks en CI y alertas webhook externas con protección anti-SSRF.

---

## 2. Stack Tecnológico

| Capa | Tecnología |
|---|---|
| **Backend** | Node.js 22 LTS (ES Modules), Express.js 5 |
| **Base de datos** | MySQL 8.0+ / 8.4 (InnoDB, UTF8MB4) + `mysql2/promise` |
| **Sesiones** | `express-session` + `express-mysql-session` |
| **Hash de contraseñas** | `bcrypt` (costo mínimo 12) |
| **Cifrado simétrico** | `AES-256-GCM` mediante `node:crypto` + AAD + key versioning |
| **Validación y seguridad** | Zod, Helmet (CSP/HSTS/Frameguard), `express-rate-limit`, CSRF custom `timingSafeEqual` |
| **Logs y correo** | Pino (JSON estructurado) + Nodemailer |
| **Frontend** | React 19, Vite 6, React Router 7, CSS modular, Context API |
| **Pruebas y CI/CD** | `node:test`, Supertest, Vitest, React Testing Library, GitHub Actions, Gitleaks, Dependabot, Docker |

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
│   └── tests/                # Pruebas unitarias, HTTP OWASP e integración MySQL
├── frontend/                 # SPA React + Vite (11+ pantallas reales conectadas a la API)
├── database/                 # schema.sql, migrations/*.sql y create-app-user.sql (mínimo privilegio)
├── docs/                     # Investigación de despliegue, arquitectura, STRIDE, informe OWASP, guion y evidencias
├── .github/                  # GitHub Actions CI/CD y Dependabot
├── Dockerfile                # Contenedor multi-stage no-root
├── docker-compose.yml        # Stack local aislado (App + MySQL 8.4)
└── PLAN_EJECUCION.md         # Seguimiento detallado de las 20 etapas
```

---

## 4. Requisitos Previos e Instalación Local

- **Node.js** `>= 22.0.0` LTS y **npm** `>= 10.0.0`.
- **MySQL** `8.0+` o `8.4 LTS` (local o vía Docker Compose).

### 4.1 Clonar e instalar dependencias

```bash
npm run install:all
```

### 4.2 Configurar variables de entorno

Copia `.env.example` como `.env` en la raíz del proyecto (nunca subas `.env` a Git) y genera llaves criptográficas seguras:

```bash
cp .env.example .env
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('DATA_ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'))"
```

Completa `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `SESSION_SECRET` y `DATA_ENCRYPTION_KEY`.

### 4.3 Crear base de datos, usuario mínimo y ejecutar migraciones

1. Crea la base de datos y un usuario con privilegios mínimos (consulta [database/create-app-user.sql](database/create-app-user.sql), evitando usar `root` en runtime):
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

### 4.5 Ejecución Rápida con Docker Compose (Opcional — Bonificación 3)

```bash
# Asegúrate de definir DB_PASSWORD, MYSQL_ROOT_PASSWORD, SESSION_SECRET y DATA_ENCRYPTION_KEY en .env
docker compose up -d --build
```

MySQL queda ligado únicamente a `127.0.0.1:3306` en una red interna aislada y la aplicación corre bajo el usuario no-root `node` en `http://127.0.0.1:4000`.

---

## 5. Pruebas Automatizadas y Auditoría

```bash
# Pruebas unitarias y suite HTTP de seguridad OWASP Top 10:2025 (backend)
npm run test:backend

# Pruebas de interfaz React y protección anti-XSS (frontend)
npm run test:frontend

# Auditoría de dependencias (0 vulnerabilidades verificadas)
npm run audit

# Pruebas reales de integración contra MySQL (requiere MySQL en ejecución y TEST_DB_*)
MYSQL_TEST_ENABLED=true npm run test:integration
```

---

## 6. Seguridad, Documentación y Despliegue

- **Investigación de despliegue (Fase 0):** [docs/investigacion-deploy.md](docs/investigacion-deploy.md)
- **Arquitectura y diagramas:** [docs/arquitectura.md](docs/arquitectura.md)
- **Modelo de amenazas STRIDE:** [docs/modelo-amenazas.md](docs/modelo-amenazas.md)
- **Informe OWASP Top 10:2025:** [docs/informe-seguridad.md](docs/informe-seguridad.md)
- **Guion de demostración (10 min):** [docs/demostracion.md](docs/demostracion.md)
- **Evidencias verificadas:** [docs/evidencias/README.md](docs/evidencias/README.md)
- **Plan de ejecución:** [PLAN_EJECUCION.md](PLAN_EJECUCION.md)

### Despliegue en Producción (Railway / Render)

El proyecto incluye `Dockerfile`, `railway.json` y `render.yaml` listos para desplegar Node.js sirviendo el build estático de Vite en `same-origin` junto con MySQL 8.4 gestionado bajo TLS (`DB_SSL=true`).  
**URL pública:** *Pendiente de publicación en PaaS por el autor (requiere cuenta y secretos personales).*
