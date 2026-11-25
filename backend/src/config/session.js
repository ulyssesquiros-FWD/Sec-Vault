import session from 'express-session';
import connectMySQLSession from 'express-mysql-session';

const MySQLStore = connectMySQLSession(session);

/**
 * Crea el almacenamiento persistente de sesiones en MySQL usando el pool mysql2/promise.
 * @param {import('mysql2/promise').Pool} pool
 * @param {ReturnType<import('./env.js').loadConfig>} config
 */
export function createMySQLSessionStore(pool, config) {
  const storeOptions = {
    clearExpired: true,
    checkExpirationInterval: 900000, // Limpieza automática cada 15 min
    expiration: config.session.absoluteTimeoutMs,
    createDatabaseTable: true,
    schema: {
      tableName: 'sessions',
      columnNames: {
        session_id: 'session_id',
        expires: 'expires',
        data: 'data'
      }
    }
  };

  return new MySQLStore(storeOptions, pool);
}

/**
 * Construye el middleware `express-session` con cookies endurecidas.
 * @param {ReturnType<import('./env.js').loadConfig>} config
 * @param {import('express-session').Store} store
 */
export function createSessionMiddleware(config, store) {
  return session({
    name: 'secvault.sid',
    secret: config.session.secret,
    store,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: Boolean(config.trustProxy),
    cookie: {
      httpOnly: true,
      secure: config.isProduction,
      sameSite: config.session.sameSite,
      maxAge: config.session.idleTimeoutMs,
      path: '/'
    }
  });
}
