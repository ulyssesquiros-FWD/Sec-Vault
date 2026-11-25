/**
 * Clase de error operacional controlada para respuestas HTTP seguras (OWASP A10:2025).
 * Nunca expone detalles internos de infraestructura o SQL al cliente.
 */
export class AppError extends Error {
  /**
   * @param {string} message Mensaje seguro para el cliente
   * @param {number} statusCode Código HTTP
   * @param {string} [code] Código simbólico interno
   * @param {unknown} [details] Detalles públicos seguros (ej. errores de validación)
   */
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', details = undefined) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

export function badRequest(message = 'Solicitud inválida.', code = 'BAD_REQUEST', details = undefined) {
  return new AppError(message, 400, code, details);
}

export function unauthorized(message = 'No autenticado.', code = 'UNAUTHORIZED') {
  return new AppError(message, 401, code);
}

export function forbidden(message = 'Acceso denegado.', code = 'FORBIDDEN') {
  return new AppError(message, 403, code);
}

export function notFound(message = 'Recurso no encontrado.', code = 'NOT_FOUND') {
  return new AppError(message, 404, code);
}

export function conflict(message = 'El recurso ya existe.', code = 'CONFLICT') {
  return new AppError(message, 409, code);
}

export function tooManyRequests(
  message = 'Demasiadas solicitudes. Intenta nuevamente más tarde.',
  code = 'TOO_MANY_REQUESTS',
  details = undefined
) {
  return new AppError(message, 429, code, details);
}
