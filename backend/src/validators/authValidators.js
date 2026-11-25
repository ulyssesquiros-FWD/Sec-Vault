import { z } from 'zod';
import { MAX_BCRYPT_BYTES } from '../services/passwordService.js';
import { normalizeEmail, stripControlChars } from '../utils/sanitize.js';

export const passwordPolicySchema = z
  .string({ error: 'La contraseña es requerida.' })
  .min(12, 'La contraseña debe tener al menos 12 caracteres.')
  .max(72, 'La contraseña no debe exceder 72 caracteres.')
  .refine((val) => Buffer.byteLength(val, 'utf8') <= MAX_BCRYPT_BYTES, {
    message: 'La contraseña excede el límite máximo de 72 bytes UTF-8.'
  })
  .refine((val) => /[A-Z]/.test(val), {
    message: 'La contraseña debe incluir al menos una letra mayúscula.'
  })
  .refine((val) => /[a-z]/.test(val), {
    message: 'La contraseña debe incluir al menos una letra minúscula.'
  })
  .refine((val) => /[0-9]/.test(val), {
    message: 'La contraseña debe incluir al menos un número.'
  })
  .refine((val) => /[^A-Za-z0-9]/.test(val), {
    message: 'La contraseña debe incluir al menos un símbolo especial.'
  });

const emailSchema = z
  .string({ error: 'El correo electrónico es requerido.' })
  .trim()
  .min(5, 'Correo electrónico inválido.')
  .max(254, 'Correo electrónico demasiado largo.')
  .pipe(z.email({ error: 'Formato de correo electrónico inválido.' }))
  .transform(normalizeEmail);

const phoneSchema = z
  .string({ error: 'El teléfono es requerido.' })
  .trim()
  .regex(/^[+\d][\d\s()-]{6,19}$/, 'El teléfono debe tener entre 7 y 20 caracteres numéricos válidos.');

export const registerSchema = z
  .object({
    name: z
      .string({ error: 'El nombre es requerido.' })
      .trim()
      .min(2, 'El nombre debe tener al menos 2 caracteres.')
      .max(120, 'El nombre no debe exceder 120 caracteres.')
      .transform(stripControlChars),
    email: emailSchema,
    password: passwordPolicySchema,
    phone: phoneSchema
  })
  .strict();

export const loginSchema = z
  .object({
    email: emailSchema,
    password: z
      .string({ error: 'La contraseña es requerida.' })
      .min(1, 'La contraseña es requerida.')
      .max(128, 'Credenciales inválidas.')
  })
  .strict();

export const forgotPasswordSchema = z
  .object({
    email: emailSchema
  })
  .strict();

export const resetPasswordSchema = z
  .object({
    token: z
      .string({ error: 'El token es requerido.' })
      .trim()
      .regex(/^[0-9a-fA-F]{64}$/, 'El formato del token de recuperación es inválido.'),
    newPassword: passwordPolicySchema
  })
  .strict();

export const mfaVerifySchema = z
  .object({
    code: z
      .string({ error: 'El código de verificación es requerido.' })
      .trim()
      .regex(/^(\d{6}|[A-Za-z0-9]{5}-[A-Za-z0-9]{5})$/, 'Ingresa un código TOTP de 6 dígitos o código de recuperación.')
  })
  .strict();
