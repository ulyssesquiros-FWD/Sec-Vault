import { z } from 'zod';
import { stripControlChars } from '../utils/sanitize.js';

export const userIdParamSchema = z
  .object({
    id: z.coerce.number().int().positive('Identificador de usuario inválido.')
  })
  .strict();

export const updateRoleSchema = z
  .object({
    role: z.enum(['user', 'admin'], {
      error: 'El rol debe ser "user" o "admin".'
    })
  })
  .strict();

export const listUsersQuerySchema = z
  .object({
    search: z
      .string()
      .trim()
      .max(100)
      .transform(stripControlChars)
      .optional()
      .default(''),
    role: z.enum(['', 'user', 'admin']).optional().default(''),
    page: z.coerce.number().int().min(1).max(1000).optional().default(1),
    limit: z.coerce.number().int().min(1).max(100).optional().default(20)
  })
  .strict();

export const listEventsQuerySchema = z
  .object({
    severity: z.enum(['', 'INFO', 'WARNING', 'HIGH', 'CRITICAL']).optional().default(''),
    eventType: z
      .string()
      .trim()
      .max(64)
      .transform(stripControlChars)
      .optional()
      .default(''),
    search: z
      .string()
      .trim()
      .max(100)
      .transform(stripControlChars)
      .optional()
      .default(''),
    page: z.coerce.number().int().min(1).max(1000).optional().default(1),
    limit: z.coerce.number().int().min(1).max(100).optional().default(30)
  })
  .strict();
