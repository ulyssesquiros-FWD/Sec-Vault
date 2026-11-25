import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateSecureToken,
  hashToken,
  timingSafeCompare
} from '../../src/services/tokenService.js';

describe('tokenService (randomBytes 32 + SHA-256)', () => {
  it('genera tokens aleatorios de 32 bytes (64 hex) y calcula hash SHA-256 distinto al token', () => {
    const raw1 = generateSecureToken(32);
    const raw2 = generateSecureToken(32);
    assert.match(raw1, /^[0-9a-f]{64}$/);
    assert.notEqual(raw1, raw2);

    const hash = hashToken(raw1);
    assert.match(hash, /^[0-9a-f]{64}$/);
    assert.notEqual(hash, raw1);
    assert.equal(hashToken(raw1), hash);
  });

  it('compara cadenas en tiempo constante rechazando longitudes o valores distintos', () => {
    const a = generateSecureToken(16);
    assert.equal(timingSafeCompare(a, a), true);
    assert.equal(timingSafeCompare(a, `${a.slice(0, -1)}0`), false);
    assert.equal(timingSafeCompare(a, `${a}00`), false);
    assert.equal(timingSafeCompare('', ''), false);
  });
});
