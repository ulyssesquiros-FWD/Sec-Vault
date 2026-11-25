import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MIN_SALT_ROUNDS,
  MAX_BCRYPT_BYTES,
  hashPassword,
  verifyPassword,
  getHashRounds
} from '../../src/services/passwordService.js';

describe('passwordService (bcrypt obligatorio >= 12)', () => {
  it('genera hash bcrypt con factor de costo >= 12 y salt distinto cada vez', async () => {
    const plain = 'ClaveSegura!2026#';
    const hash1 = await hashPassword(plain);
    const hash2 = await hashPassword(plain);

    assert.match(hash1, /^\$2[abxy]\$12\$/);
    assert.notEqual(hash1, hash2);
    assert.notEqual(hash1, plain);
    assert.ok(getHashRounds(hash1) >= MIN_SALT_ROUNDS);
  });

  it('verifica positivamente la contraseña correcta y negativamente una incorrecta', async () => {
    const plain = 'VaultAccess#9876';
    const hash = await hashPassword(plain, 12);

    assert.equal(await verifyPassword(plain, hash), true);
    assert.equal(await verifyPassword('VaultAccess#9877', hash), false);
    assert.equal(await verifyPassword('', hash), false);
  });

  it('rechaza explícitamente contraseñas que exceden 72 bytes UTF-8 (sin truncar silenciosamente)', async () => {
    const ascii73 = 'A'.repeat(MAX_BCRYPT_BYTES + 1);
    await assert.rejects(() => hashPassword(ascii73), {
      code: 'PASSWORD_TOO_LONG'
    });

    // Caracteres multibyte UTF-8: 25 emojis son 100 bytes aunque length sea 25
    const multiByte = '🔐'.repeat(20);
    assert.ok(Buffer.byteLength(multiByte, 'utf8') > 72);
    await assert.rejects(() => hashPassword(multiByte), {
      code: 'PASSWORD_TOO_LONG'
    });
  });

  it('rechaza factor de costo menor a 12', async () => {
    await assert.rejects(() => hashPassword('ClaveSegura!2026#', 10));
  });
});
