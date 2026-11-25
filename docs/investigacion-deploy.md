# Fase 0 — Deep Research: Despliegue de Node.js y MySQL en Producción

**Proyecto:** SecureVault (Sistema Full Stack seguro con Node.js, Express.js, React, MySQL, bcrypt y AES-256-GCM)  
**Autor:** Ulysses Quiros (Proyecto Individual)  
**Fecha de investigación y verificación:** 25 de noviembre de 2026  

---

## 1. Resumen Ejecutivo

Esta investigación evalúa las opciones vigentes para desplegar en producción una aplicación web de seguridad construida con **Node.js (Express.js)**, **React + Vite** y **MySQL 8.0+/8.4** por un desarrollador individual. Se responden las diez preguntas técnicas del laboratorio, se comparan plataformas PaaS (Render, Railway, Fly.io, DigitalOcean App Platform / Droplets) y proveedores de MySQL gestionado (Railway MySQL, Aiven for MySQL, DigitalOcean Managed MySQL, Amazon RDS for MySQL y TiDB Cloud Serverless), y se define la arquitectura de despliegue más adecuada equilibrando seguridad (HTTPS, TLS hacia MySQL, secretos gestionados), persistencia real de sesiones y bajo costo operativo.

> **Nota académica sobre la elección de MySQL:** El enunciado general del laboratorio sugiere PostgreSQL o MongoDB como opciones de referencia. Por decisión técnica del estudiante, **SecureVault implementa MySQL 8.0+/8.4 mediante `mysql2/promise` e `express-mysql-session`**, conservando integralmente todos los requisitos funcionales (RF-01 a RF-08), controles de seguridad OWASP Top 10:2025, integridad referencial (InnoDB, UTF8MB4, llaves foráneas, transacciones) y cifrado/hash solicitados.

---

## 2. Respuestas a las Diez Preguntas del Laboratorio

### 2.1 Tipos de despliegue: PaaS vs. Contenedores Docker vs. VPS/IaaS

| Dimensión | PaaS (Platform as a Service) | Contenedores Docker (PaaS/Orquestado) | VPS / IaaS (Virtual Private Server) |
|---|---|---|---|
| **Ejemplos** | Render, Railway, Heroku | Fly.io, Cloud Run, Docker sobre VPS | DigitalOcean Droplet, AWS EC2, Hetzner |
| **Ventajas** | Despliegue desde Git, HTTPS automático con Let's Encrypt, gestión de secretos integrada, sin administración de SO. | Entorno idéntico entre desarrollo y producción, portabilidad multi-nube, control exacto de versión de Node.js y librerías nativas (`bcrypt`). | Control total del sistema operativo, red, firewall (`ufw`), proxy inverso (Nginx/Caddy) y tuning del kernel. |
| **Desventajas** | Menor control sobre red/sistema operativo; posibles límites en planes gratuitos (suspensión por inactividad, disco efímero). | Requiere mantener `Dockerfile`, usuario no-root, parches de imagen base (`node:22-alpine`) y healthchecks. | Alta carga operativa: parches de seguridad Linux, renovación TLS, backups, systemd/PM2, hardening SSH. |
| **Costos típicos** | \$0–\$7 USD/mes para proyectos pequeños (pudiendo sumar base de datos gestionada). | \$0–\$5+ USD/mes según consumo por segundo (vCPU/RAM). | \$4–\$12 USD/mes por VPS básico (más almacenamiento/snapshots). |
| **Nivel de control** | Medio-bajo (enfocado en aplicación y variables). | Medio-alto (runtime, dependencias del sistema, usuario). | Total (root en máquina virtual). |
| **Complejidad** | Baja. | Media. | Alta para mantener seguridad de producción. |
| **Mantenimiento** | Proveedor mantiene hardware, SO, proxy TLS y runtime base. | Desarrollador mantiene `Dockerfile` y dependencias; proveedor mantiene host/TLS. | Desarrollador es responsable del 100% del hardening, SO, proxy, TLS y procesos. |

### 2.2 Comparación de plataformas para Node.js y proveedores MySQL

#### A. Plataformas de cómputo para Node.js + Frontend

| Característica | Render | Railway | Fly.io | DigitalOcean (App Platform / Droplet) |
|---|---|---|---|---|
| **Plan gratuito / crédito** | Free Tier \$0/mes (750 h/mes compartidas por workspace). | Trial inicial \$5/30 días; plan Free \$0/mes con \$1 de crédito mensual. | Crédito gratuito \$5/mes tras validar tarjeta (hasta 3 Machines pequeñas). | Sin tier gratuito permanente (App Platform desde \$5/mes; Droplet básico desde \$4–\$6/mes). |
| **Límites de recursos (nivel entrada)** | Free: 512 MB RAM, ~0.1 CPU compartida, disco efímero, ~5 GB egress Hobby. | Free: 0.5 GB RAM, 1 vCPU, 0.5 GB volumen. Hobby (\$5/mes incluye \$5 crédito): hasta 48 GB RAM / 48 vCPU medido por segundo. | `shared-cpu-1x` 256 MB RAM cuesta ~\$2.19/mes 24/7 (CPU \$20/vCPU-mes medido por segundo; almacenamiento \$0.15/GB-mes). | Droplet básico \$4/mes (512 MB RAM) o \$6/mes (1 GB RAM); App Platform \$5/mes (512 MB RAM). |
| **Suspensión por inactividad** | **Sí en Free:** spin-down tras 15 min sin tráfico; cold start ~1 min. Starter (\$7/mes) always-on. | **Sí en Free:** sleep tras pocos min sin tráfico. Hobby (\$5/mes) soporta ejecución continua sin sleep. | **Configurable:** auto-stop/auto-start rápido cuando no hay peticiones o siempre encendido si cabe en el crédito. | **No:** ejecución continua 24/7. |
| **Soporte Node.js** | Nativo (`package.json`) y Docker. | Nativo (Nixpacks/Railpack) y Docker. | Basado en Docker (`Dockerfile` o buildpacks). | Nativo en App Platform o manual en VPS Linux. |
| **HTTPS automático** | Sí, certificados TLS gestionados por defecto. | Sí, subdominios `*.up.railway.app` y dominios propios con TLS automático. | Sí, terminación TLS en edge con Let's Encrypt automático (primeros 10 certificados de dominio propio sin costo). | Sí en App Platform; en Droplet requiere Nginx/Caddy + Certbot. |
| **Regiones** | Oregon, Ohio, Virginia, Frankfurt, Singapur. | US West, US East, EU West, Asia (Singapur). | Amplia red global edge (`iad`, `ewr`, `fra`, `gru`, etc.). | NYC, SFO, FRA, LON, SGP, TOR, AMS, BLR, SYD. |
| **Variables / Secretos** | Panel Web Environment Variables & Secret Files. | Variables encriptadas por servicio/proyecto y referencia interna entre servicios. | `fly secrets set` (inyectados de forma cifrada al runtime). | Variables encriptadas en App Platform o archivo/gestor en VPS. |
| **Facilidad de despliegue** | Muy alta (Git push automático). | Muy alta (Git push + aprovisionamiento de MySQL en el mismo proyecto). | Media-alta (CLI `fly launch` / `fly deploy` + `fly.toml`). | Alta en App Platform; media-baja en Droplet (configuración manual). |

#### B. Investigación específica de proveedores MySQL gestionado en producción

*(Nota: No se consideran Neon ni Supabase porque operan sobre PostgreSQL y no corresponden al motor MySQL 8.0+/8.4 obligatorio en este proyecto).*

| Proveedor MySQL | Disponibilidad y Versiones | Costos y Planes (2026) | Límites clave | TLS y Cifrado | Backups y Recuperación | Restricción de Red / IP y Conexión Node.js |
|---|---|---|---|---|---|---|
| **Railway Managed MySQL** | MySQL 8.0 / 8.4 gestionado dentro del proyecto. | Basado en uso (\$0.000463/GB-min RAM, \$20/vCPU-mes, \$0.15/GB-mes volumen); incluido en trial \$5 o Hobby \$5/mes (~5–10 USD/mes reales 24/7 junto con backend). | Free limitado a 0.5 GB volumen y con riesgo de sleep; Hobby hasta 5 GB volumen/servicio. | Conexión privada interna (Private Networking) sin exposición pública y TLS disponible en proxy TCP público. | Volúmenes persistentes + snapshots/backups programables en Railway. | Red privada interna por defecto; conexión directa con `mysql2/promise` vía variables `MYSQLHOST`/`MYSQLPASSWORD`. |
| **Aiven for MySQL** | MySQL 8.0 gestionado. | **Free tier de MySQL retirado.** Plan mínimo **Developer \$5/mes** (single-node 24/7). | 1 vCPU, 1 GB RAM, 8 GB almacenamiento en Developer; sin SLA de HA en Developer. | **TLS obligatorio por defecto** + certificado CA descargable del proyecto; cifrado en reposo. | Backups diarios automáticos en Developer; PITR continuo desde Startup (\$75/mes). | Reglas de IP permitidas (IP allowlist) configurables; `mysql2/promise` usando `ssl: { ca, rejectUnauthorized: true }`. |
| **DigitalOcean Managed MySQL** | MySQL 8.x gestionado. | Standard desde **\$15/mes** (1 GiB RAM, 1 vCPU). HA desde \$30/mes. | Sin tier gratuito; almacenamiento extra \$0.215/GiB-mes. | **TLS obligatorio en tránsito**; cifrado en reposo con LUKS. | Backups diarios automáticos gratuitos con **Point-in-Time Recovery (PITR) de 7 días**. | Aislamiento VPC + Firewall **Trusted Sources** (IP allowlist); conexión simple con `mysql2/promise` y CA bundle. |
| **Amazon RDS for MySQL** | MySQL 8.0 y **8.4 LTS** (soporte estándar AWS de MySQL 8.0 finalizó el 31/07/2026; usar **8.4** evita cargos de Extended Support). | **Free Tier 12 meses:** 750 h/mes `db.t3.micro`/`db.t4g.micro` + 20 GB SSD + 20 GB backups. Luego ~\$12–\$16/mes + almacenamiento. | Requiere cuenta AWS y tarjeta; fuera de Free Tier o con MySQL 8.0 en Extended Support genera cargos adicionales. | **TLS gratuito** con `require_secure_transport=ON` y bundle CA regional de AWS RDS. | Snapshots diarios automáticos (retención configurable 1–35 días) y PITR. | Security Groups (restricción estricta de puerto 3306 por IP/VPC); `mysql2/promise` con CA bundle oficial AWS. |
| **TiDB Cloud Serverless** *(compatible MySQL)* | Protocolo MySQL 8.0 compatible (motor SQL distribuido TiDB, no MySQL Community nativo). | **Serverless Tier \$0/mes** sin tarjeta (cuota gratuita mensual de Request Units y almacenamiento). | Hasta 25 GiB row storage gratuito; algunas diferencias menores de DDL/bloqueos respecto a InnoDB nativo. | **TLS obligatorio por defecto** (`rejectUnauthorized: true`). | Backups automáticos según nivel de plan. | IP access list + enlace TLS directo con `mysql2/promise`. |

### 2.3 Gestión de secretos

- **Variables de entorno:** Pares clave-valor inyectados por el sistema operativo o plataforma al proceso Node.js (`process.env.*`), separando configuración y credenciales del código fuente.
- **Archivo `.env`:** Archivo local de conveniencia para desarrollo (cargado vía `dotenv`) que **siempre debe excluirse del control de versiones mediante `.gitignore`**. Solo `.env.example` (sin valores reales) debe residir en el repositorio.
- **Gestor de secretos:** Servicio cifrado en reposo y auditado (GitHub Secrets, variables encriptadas de Railway/Render, AWS Secrets Manager) que inyecta credenciales únicamente en memoria durante el arranque o ejecución.
- **Por qué no basta un `.env` en producción:** En un PaaS con despliegues efímeros el archivo `.env` no debe subirse al repo ni empaquetarse dentro de la imagen Docker (quedaría legible en las capas de la imagen). Además, carece de rotación centralizada, control de acceso por rol y auditoría.
- **Protección de credenciales MySQL y llaves criptográficas:** Generar `SESSION_SECRET` y `DATA_ENCRYPTION_KEY` (32 bytes = 64 hex) con `crypto.randomBytes(32)`, almacenarlos exclusivamente en el panel cifrado del PaaS, usar un usuario MySQL de privilegios mínimos (`SELECT, INSERT, UPDATE, DELETE`, nunca `root`), exigir TLS hacia MySQL y jamás imprimir secretos en logs.
- **Prevención de filtraciones en GitHub:** `.gitignore` estricto + hook/escaneo automático con **Gitleaks** en GitHub Actions + `.gitleaks.toml` personalizado + bloqueo de merge si aparece un secreto.

### 2.4 TLS y HTTPS

- **Certificado TLS:** Documento digital emitido por una Autoridad Certificadora (CA) que vincula la clave pública de un dominio con su identidad, permitiendo cifrar el canal de transporte y autenticar el servidor.
- **Let's Encrypt:** Autoridad certificadora gratuita y automatizada basada en el protocolo ACME (retos HTTP-01 o DNS-01) que emite certificados válidos por 90 días con renovación automática sin intervención manual.
- **HTTPS:** HTTP encapsulado sobre TLS 1.2/1.3. Garantiza confidencialidad (evita sniffing de credenciales, sesiones y notas), integridad (impide modificación en tránsito) y autenticidad del servidor.
- **HSTS (`Strict-Transport-Security`):** Cabecera HTTP que instruye al navegador a conectarse exclusivamente por HTTPS durante un periodo (`max-age=31536000; includeSubDomains; preload`), bloqueando ataques de downgrade SSL Stripping.
- **HTTP vs. HTTPS:** HTTP viaja en texto plano sobre TCP/80; cualquiera en la red (Wi-Fi pública, ISP, proxy) puede leer cookies de sesión (`secvault.sid`), contraseñas en `/api/auth/login` o respuestas JSON descifradas. HTTPS cifra todo el flujo HTTP (rutas, cabeceras, cookies, cuerpo) sobre TCP/443.
- **Por qué SecureVault lo necesita:** Sin HTTPS las cookies con atributo `Secure` no se envían, las contraseñas enviadas al endpoint de login o registro quedarían expuestas en red y las notas descifradas devueltas al cliente autenticado serían interceptables.

### 2.5 Proxy inverso y `trust proxy` en Express

- **Nginx y Caddy:** Servidores web y proxies inversos de alto rendimiento. Nginx es estándar industrial configurable; Caddy destaca por automatizar HTTPS con Let's Encrypt de forma nativa sin configuración compleja.
- **Qué es un proxy inverso y por qué va delante de Node.js:** Es un intermediario entre Internet y Express.js que termina la conexión TLS pública, filtra peticiones malformadas, sirve archivos estáticos o comprime respuestas y reenvía tráfico HTTP limpio al puerto interno de Node.js, agregando cabeceras como `X-Forwarded-For` y `X-Forwarded-Proto`.
- **Significado de `trust proxy` en Express:** Indica a Express cuántos saltos de proxy confiables existen delante de la aplicación (por ejemplo `app.set('trust proxy', 1)` detrás del balanceador TLS de Railway/Render/Nginx). Sin él, Express vería la IP interna del proxy y `req.protocol` sería `'http'` en lugar de `'https'`.
- **Impacto en cookies `Secure` y rate limiting:**
  - `express-session` solo emite cookies con `cookie.secure = true` si `req.secure === true` (lo cual depende de `X-Forwarded-Proto: https` + `trust proxy`).
  - `express-rate-limit` utiliza `req.ip` para contabilizar solicitudes; sin `trust proxy` configurado con exactitud (nunca `true` abierto si se expone directamente sin proxy, sino el número exacto de saltos `1`), todos los usuarios compartirían la IP del proxy o un atacante podría falsificar `X-Forwarded-For`.

### 2.6 Gestión de procesos

- **PM2 y systemd:** PM2 es un gestor de procesos Node.js (reinicio ante caídas, modo clúster, logs); `systemd` es el sistema de inicio y supervisión nativo de Linux (`Restart=always`).
- **Cuándo se necesitan:** Son imprescindibles en un **VPS/IaaS** para mantener Node.js vivo tras caídas o reinicios del servidor.
- **Cuándo no son necesarios en un PaaS o Docker:** En PaaS (Render, Railway, Fly.io) o Docker, el orquestador de la plataforma ejecuta un único proceso principal (`node src/server.js`), monitorea el `/health` check y reinicia automáticamente el contenedor si falla. Meter PM2 dentro de un contenedor puede ocultar códigos de salida y complicar el apagado limpio (`SIGTERM`).

### 2.7 CI/CD con GitHub Actions

Un pipeline mínimo seguro para SecureVault debe ejecutarse automáticamente en cada `push` y `pull_request` sobre `main`:
1. **Checkout completo** (`actions/checkout@v4` con `fetch-depth: 0` para Gitleaks).
2. **Escaneo de secretos** con `gitleaks/gitleaks-action@v2` (detiene el flujo ante cualquier fuga).
3. **Configuración de Node.js LTS** (`actions/setup-node@v4`, versión 22) y servicio temporal `mysql:8.4` aislado para pruebas de integración.
4. **Instalación determinista** con `npm ci` usando `package-lock.json`.
5. **Pruebas automatizadas** (unitarias, seguridad OWASP HTTP, integración MySQL real y pruebas frontend).
6. **Auditoría de dependencias** con `npm audit --audit-level=high`.
7. **Build de producción** (`npm run build` en frontend Vite).
8. **Despliegue condicionado** (`needs: [...]`) disparando el deploy hook únicamente si todas las etapas previas aprobaron sin errores.

### 2.8 Bases de datos MySQL locales vs. gestionadas

| Aspecto | MySQL Local (Desarrollo) | MySQL Gestionado (Producción) |
|---|---|---|
| **Administración** | Manual por el desarrollador en `127.0.0.1:3306`. | Proveedor gestiona parches, disponibilidad, disco y monitoreo. |
| **TLS en tránsito** | Opcional en loopback local. | Obligatorio mediante certificado CA validado (`rejectUnauthorized: true`). |
| **Privilegios** | Usuario local `securevault_app` con permisos mínimos. | Usuario dedicado con permisos mínimos (`SELECT, INSERT, UPDATE, DELETE`) y `REQUIRE SSL`, nunca `root`. |
| **Aislamiento de red** | Solo loopback (`127.0.0.1`). | Red privada VPC / Private Networking o firewall con IP allowlist estricta. |
| **Backups y recuperación** | Exportaciones manuales (`mysqldump`). | Snapshots automáticos diarios + PITR (recuperación a un punto en el tiempo). |
| **Costos** | \$0. | \$5–\$15 USD/mes o capa gratuita temporal (AWS RDS 12 meses / trial Railway). |

### 2.9 Desarrollo frente a producción

| Parámetro | Desarrollo Local | Producción |
|---|---|---|
| `NODE_ENV` | `development` | `production` |
| **Logs (Pino)** | JSON legible o nivel `debug` (siempre con redacción de secretos). | JSON estructurado nivel `info`, sin datos sensibles ni stack traces al cliente. |
| **Manejo de errores** | Mensajes detallados solo en logs internos; respuestas controladas. | Respuestas genéricas al cliente (`500 Error interno`), fail-closed al arrancar. |
| **CORS** | `http://localhost:5173` (origen dev Vite). | Mismo origen (`APP_URL`) o únicamente el dominio HTTPS exacto autorizado. |
| **Cookies de sesión** | `httpOnly: true`, `secure: false` (HTTP local), `sameSite: 'lax'`. | `httpOnly: true`, `secure: true` (HTTPS estricto), `sameSite: 'lax'` o `'strict'`. |
| **HTTPS / HSTS** | HTTP local (Vite proxy hacia backend). | HTTPS obligatorio con redirección desde HTTP + HSTS `max-age=31536000`. |
| **Secretos** | Archivo local `.env` ignorado por Git. | Variables encriptadas del gestor de secretos del PaaS (placeholders rechazados al iniciar). |
| **Pool MySQL** | `connectionLimit: 10`, timeouts finitos. | `connectionLimit: 10`, `connectTimeout: 10000`, validación estricta de entorno. |
| **TLS hacia MySQL** | `DB_SSL=false` en loopback local. | `DB_SSL=true` obligatorio con `rejectUnauthorized: true`. |
| **Sesiones** | `express-mysql-session` en MySQL local. | `express-mysql-session` en MySQL gestionado con limpieza automática (`clearExpired: true`). |

### 2.10 Verificaciones posteriores al despliegue

| Herramienta | Qué evalúa | Cuándo utilizarla | Qué resultados revisar |
|---|---|---|---|
| **`npm audit`** | Vulnerabilidades conocidas (CVE/GHSA) en árbol de dependencias de `package-lock.json`. | En cada cambio en CI/CD y antes de cada despliegue. | Cero vulnerabilidades `high` o `critical` sin mitigación compatible. |
| **Gitleaks** | Secretos, tokens, contraseñas y llaves privadas en código e historial Git. | En cada commit/PR en CI y antes de publicar repositorios. | 0 fugas detectadas en todo el historial (`fetch-depth: 0`). |
| **OWASP ZAP (Baseline Scan)** | Escaneo dinámico (DAST) pasivo sobre la URL pública: cabeceras, cookies, fugas, CORS, formularios. | Inmediatamente después de desplegar la aplicación en HTTPS. | 0 alertas `High`/`Medium`; verificar cookies `HttpOnly`/`Secure` y ausencia de fugas. |
| **SecurityHeaders.com** | Presencia y fortaleza de cabeceras HTTP (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`). | Tras activar HTTPS y dominio público de producción. | Calificación objetivo **A** o **A+** sin advertencias críticas en CSP. |
| **Qualys SSL Labs** | Calidad criptográfica TLS del servidor público: versiones (TLS 1.2/1.3), suites cifradas, cadena de certificados, Forward Secrecy. | Tras configurar dominio HTTPS de producción. | Calificación objetivo **A** o **A+**, TLS 1.0/1.1 deshabilitados y sin suites débiles. |

---

## 3. Plan de Despliegue Propuesto y Selección Justificada

### Arquitectura y Plataforma Elegida
- **Plataforma seleccionada (Principal):** **Railway** (Hobby \$5/mes con \$5 crédito incluido, o Trial \$5 para demostración académica).
  - **Por qué es óptima para un desarrollador individual:** Permite alojar en un **único proyecto** el servicio Node.js/Express (sirviendo el build estático de React+Vite en **same-origin**) junto con un **servicio MySQL 8.4 gestionado** conectado a través de una **red privada interna**, evitando exponer el puerto `3306` a Internet y simplificando enormemente las cookies `HttpOnly`/`SameSite` y la protección CSRF. Además ofrece HTTPS automático, reinicio automático ante caídas y panel cifrado de variables de entorno.
- **Alternativa documentada (Costo \$0 si se dispone de AWS Free Tier):** **Render Web Service** (o Fly.io) + **Amazon RDS for MySQL 8.4** (Free Tier 12 meses) con TLS `rejectUnauthorized: true` usando el CA bundle de AWS RDS, o **Aiven for MySQL Developer** (\$5/mes). *(Desventaja en Render Free: spin-down tras 15 minutos de inactividad).*
- **Base de datos seleccionada:** **MySQL 8.4 LTS** (InnoDB, UTF8MB4) conectada mediante `mysql2/promise` con usuario de aplicación de privilegios mínimos (`securevault_app`, nunca `root`) y almacenamiento de sesiones `express-mysql-session`.
  - **Nota operativa de TLS (`DB_SSL_CA`):** En proveedores con certificado CA propio (como Aiven, Amazon RDS, TiDB o el `ca.pem` autogenerado en `/var/lib/mysql/ca.pem` por la imagen oficial de MySQL en Railway), `backend/src/config/database.js`, `env.js` y `migrate.js` validan estrictamente el certificado (`rejectUnauthorized: true`, mínimo `TLSv1.2`) aceptando `DB_SSL_CA` como ruta de archivo, bloque PEM directo o cadena PEM codificada en Base64, rechazando cualquier llave privada y soportando opcionalmente `DB_SSL_VERIFY_IDENTITY=true` para validar el hostname SAN. **Bloqueo sin `DB_SSL_CA` en Railway MySQL:** Railway no ofrece botón UI de descarga de `ca.pem`; como `mysql:8.4` genera una CA autofirmada (`auto_generate_certs = ON`), conectar sin fijar `DB_SSL_CA` produce `self-signed certificate in certificate chain` (comportamiento *fail-closed* esperado). Alternativas seguras: extraer `/var/lib/mysql/ca.pem` del volumen MySQL vía `railway ssh` y cargarlo en `DB_SSL_CA`, o emplear un proveedor MySQL gestionado con CA descargable en panel.
- **Contenedorización adicional (Bonificación 3):** Se incluye `Dockerfile` multi-stage con usuario no-root `node` y `docker-compose.yml` con MySQL 8.4 en red aislada + servicio `migrate` previo al arranque de la aplicación.

---

## 4. Referencias Oficiales Consultadas (25 de noviembre de 2026)

1. **OWASP Top 10:2025** — *OWASP Foundation*. URL: https://top10.owasp.org/2025/ (Consultado: 2026-11-25).
2. **Express behind proxies (`trust proxy`)** — *Express.js Official Guide*. URL: https://expressjs.com/en/guide/behind-proxies.html (Consultado: 2026-11-25).
3. **Node.js `crypto` Documentation** — *Node.js v22 LTS Docs*. URL: https://nodejs.org/api/crypto.html (Consultado: 2026-11-25).
4. **MySQL 8.4 Reference Manual — Encrypted Connections (TLS)** — *Oracle / MySQL*. URL: https://dev.mysql.com/doc/refman/8.4/en/encrypted-connections.html (Consultado: 2026-11-25).
5. **Render Pricing & Free Tier Limits** — *Render Docs*. URL: https://render.com/docs/free (Consultado: 2026-11-25).
6. **Railway Pricing & Plans** — *Railway Docs*. URL: https://docs.railway.com/reference/pricing/plans (Consultado: 2026-11-25).
7. **Fly.io Resource Pricing** — *Fly.io Docs*. URL: https://fly.io/docs/about/pricing/ (Consultado: 2026-11-25).
8. **Aiven for MySQL Pricing & Plans** — *Aiven*. URL: https://aiven.io/mysql (Consultado: 2026-11-25).
9. **DigitalOcean Managed MySQL** — *DigitalOcean Docs*. URL: https://docs.digitalocean.com/products/databases/mysql/ (Consultado: 2026-11-25).
10. **Amazon RDS for MySQL Free Tier & Version Lifecycle** — *AWS*. URL: https://aws.amazon.com/rds/mysql/pricing/ (Consultado: 2026-11-25).
11. **GitHub Actions & Gitleaks Documentation** — *GitHub Docs*. URL: https://docs.github.com/en/actions (Consultado: 2026-11-25).
