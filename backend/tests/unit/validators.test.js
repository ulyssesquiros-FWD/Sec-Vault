import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { registerSchema, resetPasswordSchema } from '../../src/validators/authValidators.js';
import { noteBodySchema } from '../../src/validators/noteValidators.js';
import { loadConfig } from '../../src/config/env.js';

describe('Validadores Zod (.strict) y carga de entorno fail-closed', () => {
  it('normaliza correos y rechaza intento de inyectar role=admin en registro (mass assignment)', () => {
    const ok = registerSchema.safeParse({
      name: '  Josué Varela ',
      email: '  JOSUE@Ejemplo.COM ',
      password: 'PasswordSegura!2026',
      phone: '+506 8812-3456'
    });
    assert.equal(ok.success, true);
    assert.equal(ok.data.email, 'josue@ejemplo.com');

    const escalation = registerSchema.safeParse({
      name: 'Atacante',
      email: 'bad@ejemplo.com',
      password: 'PasswordSegura!2026',
      phone: '+506 8812-3456',
      role: 'admin'
    });
    assert.equal(escalation.success, false);
  });

  it('rechaza notas vacías o mayores a 20,000 caracteres y tokens inválidos', () => {
    assert.equal(noteBodySchema.safeParse({ title: '', content: 'Hola' }).success, false);
    assert.equal(
      noteBodySchema.safeParse({ title: 'T', content: 'x'.repeat(20001) }).success,
      false
    );
    assert.equal(
      resetPasswordSchema.safeParse({ token: 'no-hex', newPassword: 'PasswordSegura!2026' }).success,
      false
    );
  });

  it('falla en arranque si falta DATA_ENCRYPTION_KEY o se usan valores placeholder en producción', () => {
    assert.throws(() =>
      loadConfig(
        {
          NODE_ENV: 'production',
          SESSION_SECRET: 'x'.repeat(40),
          DATA_ENCRYPTION_KEY: 'short'
        },
        { loadDotenv: false }
      )
    );

    assert.throws(() =>
      loadConfig(
        {
          NODE_ENV: 'production',
          APP_URL: 'https://securevault.example.com',
          DB_PASSWORD: 'strong_db_password',
          DB_SSL: 'true',
          SESSION_SECRET: 'changeme-super-secret-placeholder-123456',
          DATA_ENCRYPTION_KEY: '0'.repeat(64)
        },
        { loadDotenv: false }
      )
    );
  });
});
