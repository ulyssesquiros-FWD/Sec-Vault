import { AppError } from '../utils/errors.js';

/**
 * Manejador global de errores (OWASP A10:2025).
 * Registra detalles completos internamente con Pino y devuelve respuestas genéricas seguras al cliente.
 */
export function createErrorHandler(logger) {
  // eslint-disable-next-line no-unused-vars
  return function errorHandler(err, req, res, next) {
    if (res.headersSent) {
      return;
    }

    // Error de JSON malformado en el cuerpo de la petición
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
      return res.status(400).json({
        error: 'El cuerpo JSON de la petición está malformado.',
        code: 'INVALID_JSON'
      });
    }

    // Payload demasiado grande
    if (err?.type === 'entity.too.large' || err?.status === 413) {
      return res.status(413).json({
        error: 'El tamaño de la petición excede el límite permitido.',
        code: 'PAYLOAD_TOO_LARGE'
      });
    }

    if (err instanceof AppError) {
      if (err.statusCode >= 500) {
        logger?.error(
          {
            code: err.code,
            statusCode: err.statusCode,
            method: req.method,
            path: req.originalUrl,
            message: err.message
          },
          'Error operacional del servidor'
        );
      }

      return res.status(err.statusCode).json({
        error: err.statusCode >= 500 ? 'Error interno del servidor.' : err.message,
        code: err.code,
        ...(err.details ? { details: err.details } : {})
      });
    }

    // Cualquier error no controlado (SQL, crypto, red, runtime) nunca filtra detalles al cliente
    logger?.error(
      {
        errName: err?.name,
        errCode: err?.code,
        errMessage: err?.message,
        stack: err?.stack,
        method: req.method,
        path: req.originalUrl
      },
      'Error inesperado capturado por manejador global'
    );

    return res.status(500).json({
      error: 'Error interno del servidor.',
      code: 'INTERNAL_SERVER_ERROR'
    });
  };
}
