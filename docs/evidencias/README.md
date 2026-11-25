# Evidencias de Seguridad y Pruebas — SecureVault

**Autor:** Ulysses Quiros (Proyecto Individual)  
**Última actualización:** 2026-11-25  

---

## 1. Evidencias Reales Generadas Localmente (Verificadas)

| Archivo | Contenido | Resultado Real |
|---|---|---|
| [backend-tests.txt](backend-tests.txt) | Salida íntegra de `npm --prefix backend test` (`node --test`: suites unitarias de bcrypt, AES-256-GCM, SHA-256, TOTP, Zod fail-closed y suite HTTP OWASP Top 10:2025). | **24/24 pruebas aprobadas (0 fallos).** |
| [mysql-integration-check.txt](mysql-integration-check.txt) | Salida real de `npm --prefix backend run test:integration` contra MySQL local (`REQUIRE_MYSQL=true`, 14 verificaciones InnoDB/utf8mb4) y comprobación fail-closed con puerto inaccesible. | **3/3 pruebas reales de integración MySQL aprobadas (0 fallos);** modo fail-closed con `REQUIRE_MYSQL=true` confirmado (`ExitCode=1`). |
| [frontend-tests-and-build.txt](frontend-tests-and-build.txt) | Salida de `npm --prefix frontend test` (Vitest + React Testing Library) y `npm --prefix frontend run build` (Vite). | **4/4 pruebas aprobadas**; build limpio en `frontend/dist`. |
| [npm-audit.txt](npm-audit.txt) | Salida real de `npm --prefix backend audit --audit-level=high` y `npm --prefix frontend audit --audit-level=high`. | **0 vulnerabilidades** en backend y frontend. |

---

## 2. Verificaciones Pendientes (Requieren GitHub Actions y Despliegue Público)

### A. Pipeline GitHub Actions (Gitleaks + MySQL 8.4 real + 6 jobs)
Tras hacer `git push -u origin main`, revisa los 6 jobs en verde en `https://github.com/ulyssesquiros-FWD/Sec-Vault/actions` y guarda captura como `docs/evidencias/github-actions-ci.png`.

### B. Verificación Funcional sobre URL Pública (`https://TU-DOMINIO`)
Ejecuta y captura respuestas reales de:
1. `curl -i https://TU-DOMINIO/health` -> `200 OK {"status":"ok"}` + cabeceras Helmet.
2. Registro, Login, Creación/Edición/Borrado de nota, Perfil (teléfono enmascarado + revelado), Recuperación de contraseña, Acceso admin bloqueado a usuario normal (`403`), Prueba IDOR (`403`), Fuerza bruta (`429`) y Logout.
3. Inspección en MySQL de producción confirmando `$2b$12$` en `users.password_hash` y `v1.<iv>.<tag>.<ct>` en `notes.encrypted_content` y `users.encrypted_phone` -> `docs/evidencias/mysql-encryption-proof.png`.

### C. Auditorías Externas Post-Despliegue
1. **OWASP ZAP Baseline Scan:**
   ```bash
   docker run --rm -v "${PWD}/docs/evidencias:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://TU-DOMINIO -r owasp-zap-report.html
   ```
2. **SecurityHeaders.com:** Evalúa `https://securityheaders.com/?q=https://TU-DOMINIO&followRedirects=on` y guarda captura como `docs/evidencias/securityheaders.png`.
3. **Qualys SSL Labs:** Evalúa `https://www.ssllabs.com/ssltest/analyze.html?d=TU-DOMINIO` y guarda captura como `docs/evidencias/ssllabs.png`.
