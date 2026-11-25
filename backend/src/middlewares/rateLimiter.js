import rateLimit from 'express-rate-limit';

/**
 * Crea limitadores de solicitudes configurables para entorno productivo y pruebas.
 */
export function createRateLimiters(overrides = {}) {
  const globalLimiter = rateLimit({
    windowMs: overrides.globalWindowMs ?? 15 * 60 * 1000,
    max: overrides.globalMax ?? 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Demasiadas solicitudes desde esta dirección. Intenta más tarde.' }
  });

  const authLimiter = rateLimit({
    windowMs: overrides.authWindowMs ?? 15 * 60 * 1000,
    max: overrides.authMax ?? 20,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Demasiados intentos de autenticación. Espera unos minutos antes de reintentar.' }
  });

  const passwordResetLimiter = rateLimit({
    windowMs: overrides.resetWindowMs ?? 15 * 60 * 1000,
    max: overrides.resetMax ?? 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Demasiadas solicitudes de recuperación. Intenta más tarde.' }
  });

  const noteWriteLimiter = rateLimit({
    windowMs: overrides.writeWindowMs ?? 1 * 60 * 1000,
    max: overrides.writeMax ?? 60,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Has excedido el límite temporal de escritura de notas.' }
  });

  return {
    globalLimiter,
    authLimiter,
    passwordResetLimiter,
    noteWriteLimiter
  };
}
