import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateTotpSecret,
  buildOtpAuthUri,
  generateTotpCode,
  verifyTotpCode,
  generateRecoveryCodes,
  consumeRecoveryCode
} from '../../src/services/totpService.js';

describe('totpService (Bonificación 1 — MFA TOTP RFC 6238)', () => {
  it('genera secreto Base32, URI otpauth y verifica código TOTP dentro de la ventana válida', () => {
    const secret = generateTotpSecret();
    assert.match(secret, /^[A-Z2-7]{32}$/);

    const uri = buildOtpAuthUri({ secret, email: 'ulysses@securevault.test' });
    assert.ok(uri.startsWith('otpauth://totp/'));
    assert.ok(uri.includes(secret));

    const now = 1_760_000_000_000;
    const code = generateTotpCode(secret, now);
    assert.match(code, /^\d{6}$/);

    assert.equal(verifyTotpCode(secret, code, 1, now), true);
    assert.equal(verifyTotpCode(secret, '000000', 0, now), code === '000000');
    assert.equal(verifyTotpCode(secret, 'abcdef', 1, now), false);
  });

  it('genera códigos de recuperación y permite un único consumo por código', () => {
    const { plainCodes, hashedCodes } = generateRecoveryCodes(8);
    assert.equal(plainCodes.length, 8);
    assert.equal(hashedCodes.length, 8);

    const firstUse = consumeRecoveryCode(plainCodes[0], hashedCodes);
    assert.equal(firstUse.matched, true);
    assert.equal(firstUse.remainingHashes.length, 7);

    const reuse = consumeRecoveryCode(plainCodes[0], firstUse.remainingHashes);
    assert.equal(reuse.matched, false);
  });
});
