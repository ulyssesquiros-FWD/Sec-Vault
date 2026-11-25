# Arquitectura del Sistema — SecureVault

**Autor:** Josué (Proyecto Individual)  
**Última actualización:** 2026-11-25  

---

## 1. Visión General de la Arquitectura

SecureVault implementa una arquitectura Full Stack de tres capas orientada a defensa en profundidad:

1. **Capa de Presentación (Frontend SPA):** React 18+ y Vite compilados a artefactos estáticos servidos desde el mismo origen (`same-origin`) en producción o mediante proxy seguro en desarrollo. No almacena secretos ni tokens en `localStorage` ni `sessionStorage`.
2. **Capa de Aplicación y Seguridad (Backend API):** Node.js v22 LTS + Express.js con arquitectura modular estricta (`config` -> `middlewares` -> `routes` -> `controllers` -> `services` -> `repositories` -> `validators`). Aplica Helmet (CSP estricta, HSTS, `X-Frame-Options: DENY`), CORS restringido, limitación de tasa (`express-rate-limit`), protección CSRF por sesión, validación Zod `.strict()`, hash `bcrypt` (>= 12 rondas) y cifrado autenticado `AES-256-GCM` con AAD.
3. **Capa de Persistencia (Base de Datos MySQL 8.0+/8.4):** Motor InnoDB con conjunto de caracteres `utf8mb4`, integridad referencial por llaves foráneas, transacciones ACID, consultas 100% parametrizadas con `mysql2/promise` y almacenamiento persistente de sesiones HTTP mediante `express-mysql-session`.

### Diagrama 1: Arquitectura General del Sistema

```mermaid
flowchart LR
    U["Navegador del Usuario (HTTPS)"] -->|"TLS 1.2 / 1.3"| RP["Proxy Inverso / Balanceador TLS (PaaS / Nginx)"]
    RP -->|"X-Forwarded-For / X-Forwarded-Proto (trust proxy)"| APP["Express.js 5 API + SPA Estática"]

    subgraph SEC["Pipeline de Seguridad Backend"]
        direction TB
        H["Helmet + CSP + CORS"] --> RL["Rate Limiter (HTTP 429)"]
        RL --> SES["express-session (Cookie HttpOnly/Secure/SameSite)"]
        SES --> CSRF["Verificación X-CSRF-Token"]
        CSRF --> ZOD["Validación Zod (.strict)"]
        ZOD --> AUTH["authenticateUser + authorizeRole + verifyOwnership"]
    end

    APP --> SEC
    SEC --> SVC["Servicios (bcrypt, AES-256-GCM, TOTP, Pino, Nodemailer)"]
    SVC -->|"mysql2/promise Pool + TLS (rejectUnauthorized: true)"| DB[("MySQL 8.4 (InnoDB / UTF8MB4)")]
    SVC -->|"SMTP TLS"| MAIL["Servidor SMTP (Recuperación / Alertas)"]
```

---

## 2. Comunicación Frontend / Backend

En producción, Express sirve los archivos compilados de `frontend/dist` bajo el mismo dominio (`APP_URL`), eliminando problemas de cookies de terceros (`third-party cookies`). Todas las peticiones autenticadas viajan con `credentials: 'include'`:

- Las operaciones de lectura (`GET`) validan la cookie de sesión `secvault.sid` (`HttpOnly`, `Secure` en producción, `SameSite=Lax` o `Strict`).
- Las operaciones de escritura (`POST`, `PUT`, `PATCH`, `DELETE`) exigen adicionalmente la cabecera `X-CSRF-Token`, generada aleatoriamente por el servidor al iniciar/regenerar la sesión y verificada con `crypto.timingSafeEqual`.

### Diagrama 2: Comunicación Frontend / Backend y Protección de Sesión/CSRF

```mermaid
sequenceDiagram
    participant C as "React SPA (Memoria RAM)"
    participant E as "Express + Helmet + Session"
    participant M as "MySQL (Tabla sessions)"

    C->>E: "GET /api/auth/me (Cookie secvault.sid)"
    E->>M: "SELECT data FROM sessions WHERE session_id = ?"
    M-->>E: "Sesión válida + csrfToken"
    E-->>C: "200 OK { user, csrfToken }"
    Note over C: "csrfToken se guarda solo en memoria JS (nunca en localStorage)"

    C->>E: "POST /api/notes (Cookie secvault.sid + Header X-CSRF-Token)"
    E->>E: "Validar timingSafeEqual(headerToken, session.csrfToken)"
    E->>E: "Validar payload con Zod .strict()"
    E-->>C: "201 Created { note }"
```

---

## 3. Modelo de Datos MySQL (Diagrama Entidad-Relación)

Todas las tablas utilizan `ENGINE=InnoDB` y `DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci` para soportar texto internacional seguro y garantizar transacciones ACID.

### Diagrama 3: Entidad-Relación (ERD)

```mermaid
erDiagram
    USERS ||--o{ NOTES : "posee (owner_id)"
    USERS ||--o{ PASSWORD_RESETS : "solicita (user_id)"
    USERS ||--o{ SECURITY_EVENTS : "genera (actor_id)"

    USERS {
        bigint id PK
        varchar name
        varchar email UK
        varchar password_hash
        enum role "user | admin"
        text encrypted_phone "AES-256-GCM"
        varchar phone_key_version
        int session_version
        tinyint mfa_enabled
        text mfa_secret_encrypted "AES-256-GCM"
        json mfa_recovery_hashes
        datetime created_at
        datetime updated_at
    }

    NOTES {
        bigint id PK
        bigint owner_id FK
        varchar title
        longtext encrypted_content "AES-256-GCM"
        varchar key_version
        datetime created_at
        datetime updated_at
    }

    PASSWORD_RESETS {
        bigint id PK
        bigint user_id FK
        char token_hash UK "SHA-256 (64 hex)"
        datetime expires_at
        datetime used_at
        datetime created_at
    }

    SECURITY_EVENTS {
        bigint id PK
        bigint actor_id FK "NULLABLE"
        varchar event_type
        enum severity "INFO | WARNING | HIGH | CRITICAL"
        varchar description
        json metadata
        varchar ip_address
        datetime created_at
    }

    LOGIN_ATTEMPTS {
        bigint id PK
        varchar email_normalized UK
        int attempts
        datetime locked_until
        varchar last_ip
        datetime updated_at
    }

    SESSIONS {
        varchar session_id PK
        int expires
        mediumtext data
    }
```

### Justificación Técnica de la Elección de MySQL
Aunque el documento guía del laboratorio sugiere PostgreSQL o MongoDB, este proyecto adopta **MySQL 8.0+/8.4** por decisión técnica del estudiante debido a:
- **Integridad relacional estricta (ACID + InnoDB):** Garantiza consistencia transaccional en el registro de usuarios (creación + cifrado del teléfono vinculado al `id`), creación/rotación de notas y restablecimiento de contraseñas.
- **Almacenamiento maduro de sesiones:** `express-mysql-session` mantiene las sesiones directamente en MySQL sobre `mysql2/promise`, permitiendo invalidación inmediata y auditoría centralizada sin desplegar un segundo motor como Redis.
- **Portabilidad y desempeño:** `mysql2` soporta sentencias preparadas (`pool.execute`) nativas con placeholders `?` para erradicar inyección SQL y soporte TLS estricto en producción (`rejectUnauthorized: true`).

---

## 4. Flujos Críticos de Seguridad

### Diagrama 4: Flujo de Registro (RF-01)

```mermaid
flowchart TD
    A["POST /api/auth/register"] --> B["Validar Zod (.strict): nombre, email, password (12-72B UTF8), teléfono"]
    B --> C["Normalizar email: trim().toLowerCase()"]
    C --> D{"¿Email ya existe?"}
    D -->|"Sí"| E["Responder 409 Conflict + Auditar intento"]
    D -->|"No"| F["bcrypt.hash(password, >= 12 rondas)"]
    F --> G["Iniciar Transacción MySQL"]
    G --> H["INSERT INTO users (role='user' forzado en servidor)"]
    H --> I["AES-256-GCM encryptData(phone, AAD='user:ID:phone')"]
    I --> J["UPDATE users SET encrypted_phone"]
    J --> K["COMMIT + Registrar evento USER_REGISTERED"]
    K --> L["201 Created (sin password_hash ni secreto)"]
```

### Diagrama 5: Flujo de Inicio de Sesión, Bloqueo Progresivo y MFA TOTP

```mermaid
flowchart TD
    A["POST /api/auth/login"] --> B["Verificar rate limiter HTTP + login_attempts en MySQL"]
    B --> C{"¿Cuenta en bloqueo temporal?"}
    C -->|"Sí"| D["429 Too Many Requests + Retry-After"]
    C -->|"No"| E["Buscar usuario por email normalizado"]
    E -->|"No existe"| F["Ejecutar dummyVerify bcrypt (tiempo constante)"]
    F --> G["Incrementar login_attempts + Auditar LOGIN_FAILED -> 401 genérico"]
    E -->|"Existe"| H["bcrypt.compare(password, password_hash)"]
    H -->|"Inválida"| G
    H -->|"Válida"| I["Resetear login_attempts"]
    I --> J{"¿MFA TOTP habilitado?"}
    J -->|"Sí"| K["Regenerar sesión en estado pendingMfaUserId -> 200 mfaRequired:true"]
    K --> L["POST /api/auth/mfa/verify (TOTP o código recuperación)"]
    L --> M["Regenerar sesión autenticada + csrfToken -> 200 OK"]
    J -->|"No"| M
```

### Diagrama 6: Flujo CRUD de Notas Privadas (RF-04 + Anti-IDOR)

```mermaid
flowchart LR
    R["Petición /api/notes/:id"] --> A["authenticateUser (sesión + timeouts + session_version)"]
    A --> V["verifyOwnership: consultar owner_id de la nota"]
    V -->|"No existe"| NF["404 Not Found"]
    V -->|"owner_id != req.user.id"| IDOR["Auditar IDOR_ATTEMPT (HIGH) -> 403 Forbidden"]
    V -->|"owner_id == req.user.id"| OP{"Operación"}
    OP -->|"GET"| DEC["SELECT WHERE id=? AND owner_id=? -> decryptData con AAD"]
    OP -->|"PUT"| ENC["Validar <=20k chars -> encryptData(AAD) -> UPDATE WHERE id=? AND owner_id=?"]
    OP -->|"DELETE"| DEL["DELETE FROM notes WHERE id=? AND owner_id=?"]
```

### Diagrama 7: Flujo de Recuperación de Contraseña (RF-06)

```mermaid
sequenceDiagram
    participant U as "Usuario"
    participant API as "passwordController"
    participant DB as "MySQL (password_resets + users)"
    participant SMTP as "Nodemailer SMTP"

    U->>API: "POST /api/auth/forgot-password { email }"
    API->>DB: "Buscar usuario (si existe)"
    Note over API: "Si existe: crypto.randomBytes(32) -> SHA-256 -> Guardar token_hash (expira 30m)"
    API->>SMTP: "Enviar enlace ?token=... (nunca en logs ni respuesta HTTP)"
    API-->>U: "200 OK (Mensaje genérico idéntico exista o no el correo)"

    U->>API: "POST /api/auth/reset-password { token, newPassword }"
    API->>DB: "Buscar por SHA-256(token) con used_at IS NULL y expires_at > NOW()"
    API->>DB: "Transacción: bcrypt.hash(newPassword, 12) + marcar used_at + session_version++"
    API-->>U: "200 OK (Todas las sesiones anteriores quedan invalidadas)"
```

### Diagrama 8: Flujo de Cifrado, Descifrado AES-256-GCM y Rotación de Llaves

```mermaid
flowchart TD
    P["Texto plano (nota o teléfono)"] --> K["Obtener llave activa 32 bytes (ENCRYPTION_KEY_VERSION)"]
    K --> IV["Generar IV criptográfico único: crypto.randomBytes(12)"]
    IV --> AAD["Vincular AAD contextual (ej. note:42:owner:7)"]
    AAD --> CIP["AES-256-GCM encrypt + obtener Auth Tag (16 bytes)"]
    CIP --> FMT["Serializar: version.base64(iv).base64(tag).base64(ciphertext)"]

    FMT --> DEC_IN["Entrada a decryptData(payload, expectedAAD)"]
    DEC_IN --> PARSE["Validar exactamente 4 segmentos y longitudes (IV=12B, Tag=16B)"]
    PARSE --> KEY_RING["Buscar llave de la versión en KeyRing (activa o anteriores)"]
    KEY_RING --> VERIFY["setAuthTag(tag) + setAAD(expectedAAD) + decipher.final()"]
    VERIFY -->|"Tag o AAD adulterado"| FAIL["Lanzar error controlado (Fail Closed)"]
    VERIFY -->|"Auténtico"| OUT["Texto plano descifrado (+ re-cifrar si versión antigua)"]
```

---

## 5. Gestión de Sesiones, Llaves y Rotación

### Gestión de Sesiones (`express-session` + `express-mysql-session`)
- Al autenticarse o verificar MFA, se invoca `req.session.regenerate()` para prevenir fijación de sesión (*Session Fixation*).
- Se aplican dos ventanas de expiración validadas en cada solicitud por `authenticateUser`:
  - **Inactividad:** `SESSION_IDLE_TIMEOUT_MS` (30 minutos por defecto).
  - **Duración absoluta:** `SESSION_ABSOLUTE_TIMEOUT_MS` (12 horas por defecto).
- Además se valida `user.session_version === req.session.sessionVersion`: cuando un usuario cambia su contraseña, restablece su contraseña o un administrador modifica su rol, `session_version` se incrementa atómicamente en MySQL, revocando de inmediato cualquier otra sesión activa.

### Gestión y Rotación de Llaves Criptográficas
- Las llaves nunca se codifican en código fuente ni en Git; se validan estrictamente en el arranque (`fail-closed`): 64 dígitos hexadecimales (256 bits).
- Cada registro cifrado guarda el prefijo de versión (`v1.`, `v2.`, etc.).
- Para rotar sin pérdida de datos:
  1. Se mueve la llave saliente a `DATA_ENCRYPTION_PREVIOUS_KEYS=v1:<hex_anterior>`.
  2. Se define la nueva llave en `DATA_ENCRYPTION_KEY=<hex_nuevo>` y `ENCRYPTION_KEY_VERSION=v2`.
  3. Las lecturas descifran con `v1` y re-cifran progresivamente a `v2`, o bien el administrador ejecuta `POST /api/admin/crypto/rotate` / `npm run crypto:rotate` para migrar todo el lote de forma controlada.
  4. **Advertencia crítica:** Perder la llave correspondiente a una versión sin respaldo provoca la **pérdida permanente e irrecuperable** de los datos cifrados bajo dicha versión.
