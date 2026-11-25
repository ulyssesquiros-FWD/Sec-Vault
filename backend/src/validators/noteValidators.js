import { z } from 'zod';
import { stripControlChars } from '../utils/sanitize.js';

export const MAX_NOTE_CONTENT_LENGTH = 20000;

export const noteIdParamSchema = z
  .object({
    id: z.coerce.number().int().positive('Identificador de nota inválido.')
  })
  .strict();

export const noteBodySchema = z
  .object({
    title: z
      .string({ error: 'El título es obligatorio.' })
      .trim()
      .min(1, 'El título no puede estar vacío.')
      .max(150, 'El título no debe exceder 150 caracteres.')
      .transform(stripControlChars),
    content: z
      .string({ error: 'El contenido es obligatorio.' })
      .trim()
      .min(1, 'El contenido de la nota no puede estar vacío.')
      .max(MAX_NOTE_CONTENT_LENGTH, `El contenido no debe exceder ${MAX_NOTE_CONTENT_LENGTH} caracteres.`)
  })
  .strict();
