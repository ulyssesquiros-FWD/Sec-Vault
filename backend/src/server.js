import { loadConfig } from './config/env.js';
import { createLogger } from './config/logger.js';
import { createPool, checkDatabaseHealth } from './config/database.js';
import { createMySQLSessionStore, createSessionMiddleware } from './config/session.js';
import { createApp } from './app.js';

let server = null;
let pool = null;
let sessionStore = null;

async function startServer() {
  const config = loadConfig();
  const logger = createLogger(config);

  pool = createPool(config, logger);
  await checkDatabaseHealth(pool);
  logger.info('Conexión verificada con MySQL');

  sessionStore = createMySQLSessionStore(pool, config);
  await sessionStore.onReady();
  logger.info('Almacenamiento persistente de sesiones MySQL inicializado');

  const sessionMiddleware = createSessionMiddleware(config, sessionStore);
  const { app } = createApp({
    config,
    logger,
    pool,
    sessionMiddleware
  });

  server = app.listen(config.port, () => {
    logger.info({ port: config.port, env: config.nodeEnv }, 'SecureVault API escuchando');
  });

  // Timeouts de protección contra Slowloris (OWASP A10)
  server.headersTimeout = 60000;
  server.requestTimeout = 30000;

  async function shutdown(signal) {
    logger.info({ signal }, 'Iniciando apagado ordenado de SecureVault');
    try {
      if (server) {
        await new Promise((resolve) => server.close(resolve));
      }
      if (sessionStore?.close) {
        await sessionStore.close();
      }
      if (pool) {
        await pool.end();
      }
      process.exit(0);
    } catch (err) {
      logger.error({ errMessage: err?.message }, 'Error durante apagado ordenado');
      process.exit(1);
    }
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    logger.fatal(
      { errMessage: reason instanceof Error ? reason.message : String(reason) },
      'Promesa rechazada no controlada (unhandledRejection) - cerrando de forma segura'
    );
    shutdown('unhandledRejection');
  });

  process.on('uncaughtException', (err) => {
    logger.fatal(
      { errName: err?.name, errMessage: err?.message },
      'Excepción no controlada (uncaughtException) - cerrando de forma segura'
    );
    shutdown('uncaughtException');
  });
}

startServer().catch((err) => {
  // Error al inicializar configuración o base de datos -> fail closed
  console.error('Fallo crítico al iniciar SecureVault:', err.message);
  process.exit(1);
});
