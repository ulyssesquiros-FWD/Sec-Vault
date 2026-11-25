# Modelo de Amenazas STRIDE — SecureVault

**Autor:** Ulysses Quiros (Proyecto Individual)  
**Alcance:** Aplicación web Full Stack SecureVault (React SPA, Express.js API, MySQL 8.4, Criptografía AES-256-GCM y bcrypt)  
**Última actualización:** 2026-11-25  

---

## 1. Activos Críticos del Sistema

1. **A1 — Credenciales de usuario (`password_hash` y flujo de login).**
2. **A2 — Contenido privado de notas (`notes.encrypted_content`) y teléfonos (`users.encrypted_phone`).**
3. **A3 — Llaves criptográficas (`DATA_ENCRYPTION_KEY`, `SESSION_SECRET`) y secretos TOTP (`mfa_secret_encrypted`).**
4. **A4 — Identificadores de sesión y tokens CSRF (`sessions`, cookie `secvault.sid`, `X-CSRF-Token`).**
5. **A5 — Tokens de recuperación de contraseña (`password_resets.token_hash`).**
6. **A6 — Integridad de roles administrativos (`users.role`) y bitácora de auditoría (`security_events`).**
7. **A7 — Disponibilidad del servicio API y base de datos MySQL.**

---

## 2. Matriz de Análisis de Amenazas STRIDE

| ID | Categoría STRIDE | Activo Afectado | Escenario de Amenaza | Prob. | Impacto | Mitigación Implementada | Evidencia / Verificación | Riesgo Residual |
|---|---|---|---|---|---|---|---|---|
| **T-01** | **S — Spoofing** (Suplantación) | A4 (Sesión) | Un atacante roba o fija una cookie de sesión mediante XSS, sniffing en HTTP o session fixation. | Media | Alto | Cookie `HttpOnly`, `Secure` en producción, `SameSite=Lax`, regeneración de sesión tras login/MFA (`session.regenerate()`), CSP estricta sin `unsafe-inline` en scripts y HTTPS obligatorio. | Pruebas HTTP de cookie flags y regeneración de ID de sesión; revisión CSP. | **Bajo** (requiere compromiso del equipo cliente). |
| **T-02** | **S — Spoofing** (Suplantación) | A1 (Credenciales) | Ataque de fuerza bruta o relleno de credenciales (*credential stuffing*) contra `/api/auth/login`. | Alta | Alto | `express-rate-limit` por IP + tabla persistente `login_attempts` en MySQL con bloqueo progresivo (60s/300s/900s), respuesta `HTTP 429`, mensajes genéricos y MFA TOTP opcional. | Prueba automatizada enviando >5 intentos fallidos -> `HTTP 429` y alerta `BRUTE_FORCE_ALERT`. | **Bajo** |
| **T-03** | **S — Spoofing** (Suplantación) | A4 (CSRF) | Un sitio malicioso induce al navegador autenticado a enviar `POST`/`DELETE` no deseados. | Media | Alto | Token CSRF ligado a la sesión en servidor validado con `crypto.timingSafeEqual` en cabecera `X-CSRF-Token` + `SameSite` cookie + verificación de origen CORS. | Prueba HTTP enviando escritura sin `X-CSRF-Token` -> `403 Forbidden`. | **Muy Bajo** |
| **T-04** | **T — Tampering** (Manipulación) | A2 (Notas / BD) | Modificación del ciphertext o intercambio de registros cifrados entre filas (`owner_id` distinto). | Media | Alto | Cifrado autenticado **AES-256-GCM** con Authentication Tag de 16 bytes + **AAD contextual** (`note:<id>:owner:<owner_id>` / `user:<id>:phone`). Cualquier alteración falla el descifrado (*fail closed*). | Prueba unitaria alterando 1 bit de ciphertext/tag o usando AAD de otro usuario -> rechazo inmediato. | **Muy Bajo** |
| **T-05** | **T — Tampering** (Manipulación) | A1 / A2 (SQL) | Inyección SQL (`' OR 1=1 --`) en formularios de login, registro, búsqueda o parámetros `:id`. | Alta | Crítico | Consultas 100% parametrizadas con `mysql2/promise` (`?` placeholders), sin concatenación de strings + validación previa Zod `.strict()` + usuario MySQL sin privilegios DDL/SUPER. | Prueba HTTP y de integración MySQL con `' OR 1=1 --` -> rechazado sin fuga ni bypass. | **Muy Bajo** |
| **T-06** | **T — Tampering** (Manipulación) | A2 (UI / XSS) | Inyección de `<script>alert('XSS')</script>` en título/contenido de notas o nombre de perfil. | Media | Alto | React escapa todo texto por defecto (cero `dangerouslySetInnerHTML`), respuestas JSON puras con `X-Content-Type-Options: nosniff` y CSP `script-src 'self'`. | Prueba HTTP enviando payload XSS + prueba Vitest confirmando ausencia de `<script>` ejecutables. | **Muy Bajo** |
| **T-07** | **R — Repudiation** (Repudio) | A6 (Bitácora) | Un atacante o administrador malintencionado intenta negar accesos fallidos, cambios de rol o intentos IDOR. | Media | Medio | Registro persistente en tabla `security_events` + logs JSON estructurados con Pino (actor, tipo, severidad, IP, timestamp). El usuario `securevault_app` de API solo consulta eventos; sin rutas de borrado. | Pruebas de auditoría verificando creación de registros `LOGIN_FAILED`, `ROLE_CHANGED`, `IDOR_ATTEMPT`. | **Bajo** |
| **T-08** | **I — Information Disclosure** (Divulgación) | A1 / A2 (BD / Caché) | Compromiso de respaldo, lectura directa de tablas MySQL o caché HTTP en navegador/proxy expone contraseñas o notas privadas. | Media | Crítico | Contraseñas exclusivamente con `bcrypt` (costo >= 12); notas y teléfonos cifrados con AES-256-GCM e IV aleatorio de 12 bytes por operación; teléfono enmascarado (`***-***-1234`); cabecera `Cache-Control: no-store, private` en toda respuesta `/api/*`. | Pruebas confirmando prefijos `$2b$12$`, `v1.<iv>.<tag>.<ct>` y cabecera `Cache-Control: no-store`. | **Bajo** (sujeto a custodia de la llave). |
| **T-09** | **I — Information Disclosure** (Divulgación) | A3 (Llaves / Secretos) | Fuga de `DATA_ENCRYPTION_KEY`, `SESSION_SECRET` o credenciales MySQL en código, GitHub o logs. | Media | Crítico | Secretos fuera del repo (`.gitignore`), validación fail-closed de placeholders al arrancar, `redact` estricto en Pino y escaneo **Gitleaks** en CI con historial completo. | Prueba de arranque rechazando llaves inválidas y configuración `.gitleaks.toml` en CI. | **Bajo** |
| **T-10** | **I — Information Disclosure** (Divulgación) | A5 (Tokens) | Interceptación o reutilización de token de recuperación en BD, URL/Referrer o logs. | Media | Alto | Generación `crypto.randomBytes(32)`, guardado solo como hash **SHA-256**, un solo uso (`used_at`), expiración 30 min, cabecera `Referrer-Policy: no-referrer`, limpieza inmediata de query param en SPA y revocación de sesiones previas. | Pruebas HTTP de expiración, rechazo de reutilización y verificación de respuesta genérica. | **Muy Bajo** |
| **T-11** | **I — Information Disclosure** (Divulgación) | A2 / A6 (Errores / Red) | Stack traces de Node/MySQL revelan rutas, SQL o entorno; o SSRF en alertas webhook externas. | Media | Medio | Manejador global de errores (A10) que responde `500` genérico; endpoint `/health` mínimo `{status:"ok"}`; validación anti-SSRF en `SECURITY_ALERT_WEBHOOK_URL` (solo HTTPS público, bloqueo IP privadas y `redirect:'error'`). | Prueba HTTP forzando excepción en repositorio -> respuesta genérica sin stack trace ni SQL. | **Muy Bajo** |
| **T-12** | **D — Denial of Service** (Denegación) | A7 (API / BD) | Saturación de CPU por contraseñas gigantes en bcrypt, notas infinitas, payloads grandes o ráfagas HTTP. | Media | Medio | Límite estricto `<= 72` bytes UTF-8 para bcrypt, cuerpo JSON limitado a `64kb`, máximo 50 notas/usuario y 20,000 chars/nota, `express-rate-limit` global y por ruta, timeouts y `connectionLimit` en pool MySQL. | Pruebas unitarias rechazando >72 bytes y pruebas de límites de negocio/rate limiting. | **Bajo** |
| **T-13** | **E — Elevation of Privilege** (Elevación) | A6 (Roles / IDOR) | Un usuario intenta registrarse como `admin`, autoasignarse rol, acceder al panel admin o leer/borrar notas ajenas (IDOR). | Alta | Crítico | Esquemas Zod `.strict()` rechazan campo `role`; rol `user` forzado en registro; `requireAdmin` en `/api/admin/*`; prohibición de auto-cambio de rol; `verifyOwnership` + `WHERE id = ? AND owner_id = ?`; admin sin acceso a notas privadas ajenas. | Pruebas HTTP de IDOR (`403`), escalación (`403`) y mass assignment (`400`). | **Muy Bajo** |

---

## 3. Abuso de Lógica de Negocio (A06 — Insecure Design)

- **Abuso 1 — Inundación de bóveda:** Mitigado limitando a **50 notas por usuario** y **20,000 caracteres por nota** dentro de transacción controlada.
- **Abuso 2 — Bloqueo dirigido de cuentas (Account Lockout DoS):** El bloqueo progresivo se combina con límite por IP (`authLimiter`) y ventana acotada (máximo 15 minutos), equilibrando protección contra fuerza bruta y disponibilidad.
- **Abuso 3 — Acceso administrativo a secretos de usuarios:** El panel administrativo muestra exclusivamente métricas agregadas, metadatos públicos autorizados de usuarios y bitácora de eventos; nunca descifra notas privadas de terceros ni expone teléfonos sin enmascarar.
