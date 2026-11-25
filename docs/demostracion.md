# Guion de Demostración en Vivo (10 Minutos) — SecureVault

**Presentador:** Josué (Desarrollador individual)  
**Objetivo:** Demostrar funcional y técnicamente la seguridad real, criptografía (`bcrypt >= 12` + `AES-256-GCM`), controles OWASP Top 10:2025, base de datos MySQL 8.4 y despliegue de SecureVault.

---

## Cronograma (10 Minutos)

| Tiempo | Bloque | Duración |
|---|---|---|
| 0:00 – 1:00 | 1. Presentación de SecureVault y arquitectura | 1:00 |
| 1:00 – 2:15 | 2 y 3. Registro seguro + Inicio de sesión | 1:15 |
| 2:15 – 4:00 | 4 y 5. Creación de notas + Verificación de cifrado en MySQL | 1:45 |
| 4:00 – 5:15 | 6. Intento de acceso a notas ajenas (Prueba IDOR + XSS) | 1:15 |
| 5:15 – 6:30 | 7. Demostración de roles y separación de privilegios | 1:15 |
| 6:30 – 7:45 | 8. Prueba de fuerza bruta (HTTP 429) | 1:15 |
| 7:45 – 8:45 | 9 y 10. Panel administrativo y bitácora de seguridad | 1:00 |
| 8:45 – 9:30 | 11. Despliegue público HTTPS, `/health` y cabeceras | 0:45 |
| 9:30 – 10:00 | 12. Conclusiones y defensa técnica | 0:30 |

---

## Paso a Paso Exacto de la Demostración

### 1. Presentación de SecureVault (0:00 – 1:00)
- Mostrar la pantalla inicial de SecureVault en navegador sobre HTTPS (o entorno local integrado).
- Explicar brevemente: aplicación individual construida con **Node.js 22, Express 5, React + Vite, MySQL 8.4 (`mysql2`), sesiones persistentes (`express-mysql-session`), `bcrypt` costo 12 y `AES-256-GCM` (`node:crypto`)**.

### 2. Registro Seguro (1:00 – 1:40)
- Ir a `/register`.
- Mostrar primero cómo la UI y el backend rechazan una contraseña débil o mayor a 72 bytes UTF-8.
- Registrar **Usuario A** (`usuario.a@ejemplo.com`) con nombre, teléfono `+506 8812-3456` y contraseña válida (ej. `BovedaSegura!2026#`).
- **Resultado esperado:** HTTP `201`, redirección al dashboard, cookie `secvault.sid` con banderas `HttpOnly` y `SameSite` visible en DevTools (Application -> Cookies), sin nada en `localStorage`.

### 3. Inicio de Sesión (1:40 – 2:15)
- Cerrar sesión desde la barra superior (`POST /api/auth/logout`).
- Volver a `/login` e iniciar sesión con **Usuario A**.
- Mostrar en `/profile` que el teléfono aparece enmascarado (`***-***-3456`) y solo se revela tras re-autenticar la contraseña actual.

### 4. Creación de Notas Privadas (2:15 – 3:00)
- Ir a `/notes/new`.
- Crear una nota con título `Credenciales Respaldo` y contenido confidencial + payload XSS de prueba:
  `Clave maestra: X9$kL2#pQ | <script>alert('XSS')</script>`
- **Resultado esperado:** La nota se guarda (`201 Created`) y el payload `<script>` se renderiza como texto inerte en pantalla sin ejecutarse (CSP estricta + escape React).

### 5. Verificación del Hash y Cifrado en MySQL (3:00 – 4:00)
- Abrir consola MySQL (o cliente conectado a la base de datos) y ejecutar:
  ```sql
  SELECT id, email, LEFT(password_hash, 25) AS hash_prefix, LEFT(encrypted_phone, 38) AS phone_cipher
  FROM users
  ORDER BY id DESC LIMIT 2;

  SELECT id, owner_id, title, LEFT(encrypted_content, 48) AS content_cipher, key_version
  FROM notes
  ORDER BY id DESC LIMIT 2;
  ```
- **Resultado esperado:**
  - `password_hash` inicia con `$2b$12$...` (nunca texto plano).
  - `encrypted_phone` y `encrypted_content` muestran `v1.<ivBase64>.<tagBase64>.<ciphertextBase64>` — imposible leer el teléfono ni la nota directamente desde la base de datos.

### 6. Intento de Acceso a Notas Ajenas — Prueba IDOR (4:00 – 5:15)
- En una ventana privada (incógnito), registrar/iniciar sesión como **Usuario B** (`usuario.b@ejemplo.com`).
- Anotar el `id` de la nota del Usuario A (ej. `id = 1`) e intentar acceder desde la sesión de Usuario B en consola del navegador o DevTools:
  ```javascript
  fetch('/api/notes/1', { credentials: 'include' }).then(r => r.json().then(d => console.log(r.status, d)))
  ```
- **Resultado esperado:** El backend responde **HTTP `403 Forbidden`** (`"No tienes autorización para acceder a esta nota."`) y registra un evento `IDOR_ATTEMPT` de severidad `HIGH` en MySQL.

### 7. Demostración de Roles (5:15 – 6:30)
- Desde la sesión de **Usuario B** (`role: 'user'`), intentar acceder manualmente a `/admin` o consultar `GET /api/admin/stats`:
  - El frontend redirige al dashboard y el backend responde **HTTP `403 Forbidden`** (`ADMIN_ACCESS_DENIED`).
- Mostrar también con `curl` o consola que intentar registrarse enviando `"role": "admin"` falla con **HTTP `400 Bad Request`** gracias a `.strict()` en Zod.

### 8. Prueba de Fuerza Bruta y SQL Injection (6:30 – 7:45)
- Cerrar sesión o abrir `/login`.
- Probar payload SQL Injection `' OR 1=1 --` -> rechazado inmediatamente (`400` por validación Zod + consultas parametrizadas).
- Enviar **5 intentos fallidos consecutivos** contra `usuario.a@ejemplo.com`:
  - Intentos 1–4: `401 Credenciales inválidas.` (mensaje genérico).
  - Intento 5+: **HTTP `429 Too Many Requests`** con cabecera `Retry-After`, bloqueo persistente en tabla `login_attempts` de MySQL y evento `BRUTE_FORCE_ALERT`.

### 9. Panel Administrativo (7:45 – 8:15)
- Iniciar sesión con la cuenta **administradora** (`role: 'admin'`).
- Mostrar `/admin`: tarjetas con totales reales (usuarios, admins, usuarios normales, eventos, intentos fallidos, versión activa de llave AES-256-GCM).
- Ir a `/admin/users`: demostrar cambio de rol controlado sobre un usuario de prueba y enfatizar que el administrador **no tiene ruta ni permiso para descifrar notas privadas de terceros**.

### 10. Bitácora de Seguridad (8:15 – 8:45)
- Ir a `/admin/events`.
- Filtrar por severidad `HIGH` y mostrar los eventos reales recién generados durante la demo (`IDOR_ATTEMPT`, `ADMIN_ACCESS_DENIED`, `BRUTE_FORCE_ALERT`, `ROLE_CHANGED`), sin contraseñas ni tokens en los registros.

### 11. Despliegue Público HTTPS y Verificaciones (8:45 – 9:30)
- Mostrar la URL pública HTTPS, verificar el candado TLS del navegador, consultar `GET /health` (`{"status":"ok"}`) y mostrar las cabeceras de respuesta (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options: DENY`, ausencia de `X-Powered-By`).
- Mostrar los resultados de `npm audit` (0 vulnerabilidades) y los reportes de OWASP ZAP / SecurityHeaders / SSL Labs (cuando estén generados).

### 12. Conclusiones (9:30 – 10:00)
- Resumir cómo SecureVault integra defensa en profundidad real: hash lento `bcrypt >= 12`, confidencialidad e integridad con `AES-256-GCM + AAD`, sesiones persistentes revocables en MySQL, protección completa OWASP Top 10:2025 y flujo reproducible mediante migraciones, pruebas automatizadas y CI/CD.
