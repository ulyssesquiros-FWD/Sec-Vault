import { z } from 'zod';
import { passwordPolicySchema } from './authValidators.js';
import { stripControlChars } from '../utils/sanitize.js';

export const updateProfileSchema = z
  .object({
    name: z
      .string({ error: 'El nombre es requerido.' })
      .trim()
      .min(2, 'El nombre debe tener al menos 2 caracteres.')
      .max(120, 'El nombre no debe exceder 120 caracteres.')
      .transform(stripControlChars),
    phone: z
      .string({ error: 'El teléfono es requerido.' })
      .trim()
      .regex(/^[+\d][\d\s()-]{6,19}$/, 'Teléfono inválido.')
  })
  .strict();

export const changePasswordSchema = z
  .object({
    currentPassword: z
      .string({ error: 'La contraseña actual es requerida.' })
      .min(1, 'La contraseña actual es requerida.')
      .max(128),
    newPassword: passwordPolicySchema
  })
  .strict();

export const revealPhoneSchema = z
  .object({
    currentPassword: z
      .string({ error: 'Debes confirmar tu contraseña actual.' })
      .min(1, 'Debes confirmar tu contraseña actual.')
      .max(128)
  })
  .strict();

export const mfaEnableSchema = z
  .object({
    code: z
      .string({ error: 'El código TOTP de 6 dígitos es requerido.' })
      .trim()
      .regex(/^\d{6}$/, 'El código TOTP debe tener exactamente 6 dígitos numéricos.')
  })
  .strict();

export const mfaDisableSchema = z
  .object({
    currentPassword: z
      .string({ error: 'Debes confirmar tu contraseña actual para desactivar MFA.' })
      .min(1)
      .max(128)
  })
  .strict();
