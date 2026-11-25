-- ==============================================================================
-- SecureVault - Usuario de Aplicación con Privilegios Mínimos (Principio de Mínimo Privilegio)
-- IMPORTANTE:
-- 1. Reemplaza 'REEMPLAZAR_PASSWORD_FUERTE' por una contraseña generada con CSPRNG.
-- 2. Nunca utilices el usuario root de MySQL desde el backend de SecureVault.
-- 3. Ejecuta DDL/migraciones con un usuario administrativo aparte y opera la app
--    con `securevault_app` limitado a DML (SELECT, INSERT, UPDATE, DELETE).
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS securevault
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

-- Para producción con TLS obligatorio (ajustar host según IP/VPC de la plataforma):
CREATE USER IF NOT EXISTS 'securevault_app'@'%'
  IDENTIFIED BY 'REEMPLAZAR_PASSWORD_FUERTE'
  REQUIRE SSL;

-- En desarrollo local estricto por loopback:
-- CREATE USER IF NOT EXISTS 'securevault_app'@'127.0.0.1'
--   IDENTIFIED BY 'REEMPLAZAR_PASSWORD_LOCAL';

GRANT SELECT, INSERT, UPDATE, DELETE
  ON securevault.*
  TO 'securevault_app'@'%';

-- Si `securevault_app` ejecutará `npm run db:migrate` en el despliegue inicial,
-- otorgar CREATE, ALTER, INDEX únicamente durante la ventana de migración o
-- ejecutar `migrate.js` con un usuario dedicado de migraciones.

FLUSH PRIVILEGES;
