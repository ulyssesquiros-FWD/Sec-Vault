import { badRequest } from '../utils/errors.js';

/**
 * Middleware de validación con Zod (OWASP A05 / A08).
 * Almacena datos saneados en `req.validated` para compatibilidad estricta con Express 5.
 * @param {{ body?: import('zod').ZodTypeAny, params?: import('zod').ZodTypeAny, query?: import('zod').ZodTypeAny }} schemas
 */
export function validateRequest(schemas = {}) {
  return (req, res, next) => {
    req.validated = req.validated || {};
    const errors = [];

    for (const part of ['params', 'query', 'body']) {
      const schema = schemas[part];
      if (!schema) continue;

      const parsed = schema.safeParse(req[part]);
      if (!parsed.success) {
        for (const issue of parsed.error.issues) {
          errors.push({
            location: part,
            field: issue.path.join('.') || part,
            message: issue.message
          });
        }
      } else {
        req.validated[part] = parsed.data;
      }
    }

    if (errors.length > 0) {
      return next(badRequest('Datos de entrada inválidos.', 'VALIDATION_ERROR', errors));
    }

    return next();
  };
}
