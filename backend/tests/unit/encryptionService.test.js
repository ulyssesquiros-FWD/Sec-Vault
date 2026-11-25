import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createEncryptionService } from '../../src/services/encryptionService.js';
import { maskPhone } from '../../src/utils/sanitize.js';

const KEY_V1 = crypto.randomBytes(32);
const KEY_V2 = crypto.randomBytes(32);

describe('encryptionService (AES-256-GCM + AAD + Rotación)', () => {
  it('cifra y descifra correctamente con IV aleatorio único por operación', () => {
    const service = createEncryptionService({
      activeKeyVersion: 'v1',
      keyRing: new Map([['v1', KEY_V1]])
    });

    const plaintext = 'Secreto crítico: API_KEY=99887766';
    const aad = 'note:10:owner:3';

    const cipher1 = service.encryptData(plaintext, aad);
    const cipher2 = service.encryptData(plaintext, aad);

    assert.ok(cipher1.startsWith('v1.'));
    assert.equal(cipher1.split('.').length, 4);
    assert.notEqual(cipher1, cipher2, 'Cada operación debe generar un IV único');
    assert.equal(cipher1.includes(plaintext), false);

    assert.equal(service.decryptData(cipher1, aad), plaintext);
    assert.equal(service.decryptData(cipher2, aad), plaintext);
  });

  it('rechaza contenido manipulado, tag alterado, AAD distinto o llave incorrecta', () => {
    const service = createEncryptionService({
      activeKeyVersion: 'v1',
      keyRing: new Map([['v1', KEY_V1]])
    });
    const wrongKeyService = createEncryptionService({
      activeKeyVersion: 'v1',
      keyRing: new Map([['v1', KEY_V2]])
    });

    const payload = service.encryptData('Dato confidencial', 'note:5:owner:1');
    const [ver, iv, tag, ct] = payload.split('.');

    // Alterar ciphertext
    const ctBuf = Buffer.from(ct, 'base64');
    ctBuf[0] ^= 0xff;
    const tamperedCt = [ver, iv, tag, ctBuf.toString('base64')].join('.');
    assert.throws(() => service.decryptData(tamperedCt, 'note:5:owner:1'), {
      code: 'DECRYPTION_AUTH_FAILED'
    });

    // Alterar Authentication Tag
    const tagBuf = Buffer.from(tag, 'base64');
    tagBuf[0] ^= 0xff;
    const tamperedTag = [ver, iv, tagBuf.toString('base64'), ct].join('.');
    assert.throws(() => service.decryptData(tamperedTag, 'note:5:owner:1'), {
      code: 'DECRYPTION_AUTH_FAILED'
    });

    // AAD incorrecto (previene mover ciphertext entre notas/usuarios)
    assert.throws(() => service.decryptData(payload, 'note:5:owner:2'), {
      code: 'DECRYPTION_AUTH_FAILED'
    });

    // Llave incorrecta
    assert.throws(() => wrongKeyService.decryptData(payload, 'note:5:owner:1'), {
      code: 'DECRYPTION_AUTH_FAILED'
    });
  });

  it('soporta descifrado con versión anterior y detecta necesidad de re-cifrado hacia v2', () => {
    const serviceV1 = createEncryptionService({
      activeKeyVersion: 'v1',
      keyRing: new Map([['v1', KEY_V1]])
    });
    const oldPayload = serviceV1.encryptData('Teléfono +50688112233', 'user:1:phone');

    const serviceV2 = createEncryptionService({
      activeKeyVersion: 'v2',
      keyRing: new Map([
        ['v1', KEY_V1],
        ['v2', KEY_V2]
      ])
    });

    assert.equal(serviceV2.needsReencryption(oldPayload), true);
    assert.equal(serviceV2.decryptData(oldPayload, 'user:1:phone'), 'Teléfono +50688112233');

    const rotatedPayload = serviceV2.encryptData('Teléfono +50688112233', 'user:1:phone');
    assert.ok(rotatedPayload.startsWith('v2.'));
    assert.equal(serviceV2.needsReencryption(rotatedPayload), false);
  });

  it('enmascara teléfonos dejando únicamente los últimos 4 dígitos', () => {
    assert.equal(maskPhone('+506 8812-3456'), '***-***-3456');
    assert.equal(maskPhone('12'), '***');
    assert.equal(maskPhone(''), '***');
  });
});
