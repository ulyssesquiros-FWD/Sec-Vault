# Evidencias de Seguridad y Pruebas — SecureVault

**Autor:** Josué (Proyecto Individual)  
**Última actualización:** 2026-11-25  

---

## 1. Evidencias Reales Generadas Localmente (Verificadas)

| Archivo | Contenido | Resultado Real |
|---|---|---|
| [backend-tests.txt](backend-tests.txt) | Salida íntegra de `npm --prefix backend test` (`node --test`: suites unitarias de bcrypt, AES-256-GCM, SHA-256, TOTP, Zod fail-closed y suite HTTP OWASP Top 10:2025). | **24/24 pruebas aprobadas (0 fallos).** |
| [frontend-tests-and-build.txt](frontend-tests-and-build.txt) | Salida de `npm --prefix frontend test` (Vitest + React Testing Library) y `npm --prefix frontend run build` (Vite). | **4/4 pruebas aprobadas**; build limpio en `frontend/dist`. |
| [npm-audit.txt](npm-audit.txt) | Salida real de `npm --prefix backend audit` y `npm --prefix frontend audit`. | **0 vulnerabilidades** en backend (162 paquetes) y **0 vulnerabilidades** en frontend (146 paquetes). |

---

## 2. Evidencias Externas Pendientes (Requieren Acción del Autor tras Desplegar)

Una vez que publiques el repositorio en GitHub y despliegues la aplicación en Railway/Render con MySQL gestionado y HTTPS público, agrega en esta carpeta las capturas y reportes reales siguientes:

1. `github-actions-ci.png`: Captura del workflow `.github/workflows/ci.yml` en verde (incluyendo **Gitleaks**, integración real contra **MySQL 8.4**, pruebas backend/frontend, build y `npm audit`).
2. `mysql-encryption-proof.png`: Captura de consola MySQL mostrando `password_hash` con prefijo `$2b$12$` y `encrypted_content` / `encrypted_phone` con formato `v1.<iv>.<tag>.<ciphertext>`.
3. `ui-dashboard-and-notes.png`: Captura del dashboard de usuario, listado de notas y perfil con teléfono enmascarado (`***-***-1234`).
4. `admin-audit-log.png`: Captura del panel administrativo mostrando métricas reales y la bitácora con eventos (`LOGIN_FAILED`, `BRUTE_FORCE_ALERT`, `IDOR_ATTEMPT`, `ROLE_CHANGED`).
5. `owasp-zap-report.html`: Reporte generado mediante `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://TU-URL-PUBLICA -r owasp-zap-report.html`.
6. `securityheaders.png`: Captura de https://securityheaders.com/?q=https://TU-URL-PUBLICA&followRedirects=on mostrando la calificación obtenida (objetivo: A / A+).
7. `ssllabs.png`: Captura de https://www.ssllabs.com/ssltest/analyze.html?d=TU-DOMINIO mostrando la calificación TLS (objetivo: A / A+).
