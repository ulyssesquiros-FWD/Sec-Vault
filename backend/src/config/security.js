import helmet from 'helmet';
import cors from 'cors';
import { forbidden } from '../utils/errors.js';

/**
 * Configura cabeceras de seguridad HTTP con Helmet + CSP estricta + Permissions-Policy.
 * @param {ReturnType<import('./env.js').loadConfig>} config
 */
export function createSecurityMiddlewares(config) {
  const helmetMiddleware = helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'", ...(config.isProduction ? [] : [config.allowedOrigin])],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        ...(config.isProduction ? { upgradeInsecureRequests: [] } : {})
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: config.isProduction
      ? {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true
        }
      : false
  });

  const permissionsPolicyMiddleware = (req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
  };

  const allowedOrigins = new Set([config.appUrl, config.allowedOrigin]);
  const corsMiddleware = cors({
    origin(origin, callback) {
      // Permitir peticiones sin cabecera Origin (ej. navegaciones same-origin, curl o healthchecks)
      if (!origin) {
        return callback(null, true);
      }
      if (allowedOrigins.has(origin)) {
        return callback(null, true);
      }
      return callback(forbidden('Origen CORS no autorizado.', 'CORS_FORBIDDEN'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token']
  });

  return {
    helmetMiddleware,
    permissionsPolicyMiddleware,
    corsMiddleware
  };
}
