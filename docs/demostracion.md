# Guion de Demostración y Presentación de Resultados — SecureVault

**Estudiante / Expositor único:** Josué  
**Modalidad:** Proyecto individual  

---

# PARTE I — Guion de Demostración Técnica en Vivo (10 Minutos)

## Cronograma (10 Minutos)

| Tiempo | Bloque | Duración |
|---|---|---|
| 0:00 – 1:00 | 1. Presentación de SecureVault y arquitectura | 1:00 |
| 1:00 – 2:15 | 2 y 3. Registro seguro (`RF-01`) + Inicio de sesión (`RF-02`) | 1:15 |
| 2:15 – 4:00 | 4 y 5. Creación de notas (`RF-04`) + Verificación de hash/cifrado en MySQL (`RF-05`) | 1:45 |
| 4:00 – 5:15 | 6. Intento de acceso a notas ajenas (Prueba IDOR + XSS) | 1:15 |
| 5:15 – 6:30 | 7. Demostración de roles (`RF-03`) | 1:15 |
| 6:30 – 7:45 | 8. Prueba de fuerza bruta (`HTTP 429`) y SQL Injection | 1:15 |
| 7:45 – 8:45 | 9 y 10. Panel administrativo y bitácora de seguridad (`RF-07`) | 1:00 |
| 8:45 – 9:30 | 11. Despliegue público HTTPS, `/health` (`RF-08`) y cabeceras | 0:45 |
| 9:30 – 10:00 | 12. Conclusiones y defensa técnica | 0:30 |

## Paso a Paso de la Demo en Vivo

1. **Presentación (0:00 – 1:00):** Mostrar la pantalla principal sobre HTTPS (o entorno Docker/local) explicando el stack: Node.js 22, Express 5, React + Vite, MySQL 8.4 (`mysql2`), `express-mysql-session`, `bcrypt >= 12` y `AES-256-GCM`.
2. **Registro `RF-01` (1:00 – 1:40):** En `/register`, mostrar rechazo de contraseña débil o >72 bytes UTF-8; registrar **Usuario A** (`usuario.a@ejemplo.com`, teléfono `+506 8812-3456`). Verificar en DevTools cookie `secvault.sid` con `HttpOnly` y `SameSite`, sin secretos en `localStorage`.
3. **Inicio de sesión `RF-02` y Perfil `RF-05` (1:40 – 2:15):** Cerrar sesión y volver a iniciar. Mostrar en `/profile` el teléfono enmascarado `***-***-3456` y revelarlo ingresando la contraseña actual.
4. **Creación de notas `RF-04` (2:15 – 3:00):** En `/notes/new`, guardar nota con `<script>alert('XSS')</script>` comprobando que se almacena y renderiza como texto inerte sin ejecutarse.
5. **Verificación directa en MySQL (3:00 – 4:00):**
   ```sql
   SELECT id, email, LEFT(password_hash, 25) AS hash_prefix, LEFT(encrypted_phone, 38) AS phone_cipher
   FROM users ORDER BY id DESC LIMIT 2;

   SELECT id, owner_id, title, LEFT(encrypted_content, 48) AS content_cipher, key_version
   FROM notes ORDER BY id DESC LIMIT 2;
   ```
   Confirmar prefijo `$2b$12$` en `password_hash` y formato `v1.<iv>.<tag>.<ciphertext>` en `encrypted_phone` y `encrypted_content`.
6. **Prueba IDOR (4:00 – 5:15):** Desde otra ventana autenticada como **Usuario B**, intentar consultar la nota de Usuario A (`GET /api/notes/1`) -> respuesta **HTTP `403 Forbidden`** y evento `IDOR_ATTEMPT` (`HIGH`) en bitácora.
7. **Demostración de roles `RF-03` (5:15 – 6:30):** Con **Usuario B** (`role: 'user'`), intentar abrir `/admin` o `GET /api/admin/stats` -> **HTTP `403 Forbidden`** (`ADMIN_ACCESS_DENIED`). Mostrar también que enviar `"role": "admin"` en `/api/auth/register` falla con `400`.
8. **Fuerza bruta `HTTP 429` y SQL Injection (6:30 – 7:45):** Enviar `' OR 1=1 --` en login (`400`); luego enviar 5 contraseñas incorrectas -> intentos 1–4 responden `401` genérico y el 5.º responde **`429 Too Many Requests`** con `Retry-After` persistido en `login_attempts`.
9. **Panel administrativo `RF-07` (7:45 – 8:15):** Iniciar sesión como `admin`, mostrar tarjetas de estadísticas reales y cambio controlado de rol sin acceso a notas privadas ajenas.
10. **Bitácora de seguridad `RF-07` (8:15 – 8:45):** En `/admin/events`, filtrar por severidad `HIGH` y mostrar `IDOR_ATTEMPT`, `ADMIN_ACCESS_DENIED`, `BRUTE_FORCE_ALERT` y `ROLE_CHANGED` sin fuga de contraseñas ni tokens.
11. **Despliegue público, `GET /health` `RF-08` y auditoría (8:45 – 9:30):** Mostrar certificado HTTPS, `GET /health` (`{"status":"ok"}`), cabeceras (`CSP`, `HSTS`, `Cache-Control: no-store`, sin `X-Powered-By`) y reportes de `npm audit`, OWASP ZAP, SecurityHeaders y SSL Labs.
12. **Conclusiones (9:30 – 10:00):** Cierre resumiendo las capas de defensa y lecciones aprendidas.

---

# PARTE II — Guion de Presentación de Resultados (10 Ejes para Defensa Individual)

Utiliza estos 10 puntos hablados para defender personalmente cada decisión técnica ante el docente:

### 1. Arquitectura
"SecureVault sigue una arquitectura modular de tres capas en un único repositorio desarrollado individualmente: un frontend React + Vite servido en producción bajo el mismo origen (`same-origin`) desde Express.js, una API REST organizada estrictamente en `routes -> middlewares -> validators -> controllers -> services -> repositories`, y una base de datos relacional MySQL 8.4 con motor InnoDB. Esta separación evita lógica acoplada en controladores y garantiza defensa en profundidad."

### 2. Node.js
"El backend corre sobre Node.js 22 LTS utilizando módulos ES nativos y Express 5. Aplica validación de entorno *fail-closed* al arrancar con Zod en `env.js`: si falta `DATA_ENCRYPTION_KEY`, `SESSION_SECRET`, o si en producción `DB_SSL` es falso o `APP_URL` no usa HTTPS, la aplicación se niega a iniciar. Además maneja `unhandledRejection`, `uncaughtException` y apagado ordenado (`SIGTERM`/`SIGINT`) con timeouts HTTP anti-Slowloris."

### 3. MySQL
"Elegí MySQL 8.0+/8.4 como alternativa relacional documentada al stack sugerido. Todas las 7 tablas usan InnoDB y `utf8mb4`, llaves primarias `BIGINT`, llaves foráneas (`ON DELETE CASCADE` para notas/tokens y `ON DELETE SET NULL` para preservar la bitácora), índices y restricciones `UNIQUE` en correo normalizado. Todas las consultas usan `mysql2/promise` con placeholders `?` (cero concatenación SQL) y transacciones ACID (`withTransaction`) en registro, cambio de rol, creación de notas y reseteo de contraseña."

### 4. bcrypt
"Las contraseñas nunca se cifran de forma reversible ni usan SHA/MD5. Se derivan de manera asíncrona con `bcrypt` y factor de costo mínimo 12 (`$2b$12$...`), con salt único generado automáticamente por usuario. Como `bcrypt` trunca internamente a 72 bytes, `passwordService.js` y Zod validan el tamaño real en bytes UTF-8 y rechazan cualquier contraseña mayor a 72 bytes sin truncarla silenciosamente."

### 5. AES-256-GCM
"Para información confidencial recuperable —contenido de notas y número telefónico— uso `node:crypto` con `aes-256-gcm`, llave de 32 bytes, IV criptográfico aleatorio de 12 bytes por operación y Authentication Tag de 16 bytes, serializado como `version.iv.tag.ciphertext`. Además vinculo cada dato mediante AAD (`note:<id>:owner:<owner_id>` o `user:<id>:phone`) para impedir que un atacante mueva datos cifrados entre registros, y soporto rotación progresiva de llaves (`v1` -> `v2`)."

### 6. Sesiones
"En lugar de JWT en `localStorage`, uso sesiones server-side con `express-session` persistidas en la tabla `sessions` de MySQL mediante `express-mysql-session`. La cookie `secvault.sid` lleva `HttpOnly`, `SameSite=Lax` y `Secure` en producción; al iniciar sesión se regenera el ID (`session.regenerate()`) contra fijación de sesión; se validan timeouts de inactividad y duración absoluta; y existe un contador `session_version` que revoca instantáneamente sesiones previas al cambiar contraseña o rol."

### 7. Roles
"El control de acceso RBAC soporta `user` y `admin` verificados exclusivamente en el servidor. El registro fuerza siempre `role = 'user'` y Zod `.strict()` rechaza cualquier intento de enviar `role` desde el cliente. El middleware `requireAdmin` protege `/api/admin/*`, se bloquea que un administrador modifique su propio rol, y la separación de privilegios impide al administrador leer notas privadas ajenas."

### 8. OWASP Top 10:2025
"Cada categoría de OWASP Top 10:2025 cuenta con mitigación en código y prueba automatizada: A01 con `verifyOwnership` anti-IDOR y validación DNS/IP anti-SSRF en webhooks; A02 con Helmet (CSP `script-src 'self'`, HSTS, `DENY`), `Cache-Control: no-store` en `/api/*` y `/health` mínimo; A03 con `npm ci`, Dependabot, Gitleaks y 0 vulnerabilidades en `npm audit`; A04 con bcrypt + AES-256-GCM + TLS MySQL; A05 con placeholders MySQL y escape React anti-XSS; A06 con STRIDE y límite de 50 notas; A07 con bloqueo progresivo persistente (`429`) y MFA TOTP opcional; A08 con CSRF `timingSafeEqual` y SHA-256 en recuperación; A09 con Pino JSON redactado y `security_events`; y A10 con manejador global de errores genérico."

### 9. Pruebas
"El repositorio incluye pruebas unitarias (`passwordService`, `encryptionService`, `tokenService`, `totpService`, Zod fail-closed), una suite HTTP de seguridad OWASP con Supertest, pruebas de interfaz Vitest + React Testing Library contra XSS y rutas protegidas, y una suite de integración real contra MySQL 8.4 (`mysql.integration.test.js`) que valida los 14 puntos exigidos y falla si MySQL no responde cuando `REQUIRE_MYSQL=true` está activo."

### 10. Despliegue
"El proyecto está preparado para producción con `Dockerfile` multi-stage no-root, `docker-compose.yml` aislado con servicio previo de migración, manifiestos para Railway y Render (sirviendo frontend y backend en un mismo origen HTTPS junto a MySQL gestionado con TLS `rejectUnauthorized: true`) y un pipeline GitHub Actions de 6 trabajos (Gitleaks, pruebas backend, integración real MySQL 8.4, `npm audit`, pruebas frontend y build Vite) previo al despliegue."
