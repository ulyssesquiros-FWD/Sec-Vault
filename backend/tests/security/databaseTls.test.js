import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSslOptions,
  classifyDatabaseError,
  sanitizeDatabaseErrorMessage,
  createPool,
  checkDatabaseHealth
} from '../../src/config/database.js';
import { loadConfig } from '../../src/config/env.js';

const require = createRequire(import.meta.url);
const HandshakePacket = require('../../node_modules/mysql2/lib/packets/handshake.js');
const ClientConstants = require('../../node_modules/mysql2/lib/constants/client.js');

function resolveOpenSslBinary() {
  const candidates =
    process.platform === 'win32'
      ? ['openssl', 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe']
      : ['openssl'];
  for (const bin of candidates) {
    try {
      execFileSync(bin, ['version'], { stdio: 'ignore' });
      return bin;
    } catch {
      // Probar siguiente ruta
    }
  }
  return null;
}

function createEphemeralMysqlTlsServer({ key, cert, onTlsHandshake }) {
  return new Promise((resolve) => {
    const sockets = new Set();
    const server = net.createServer((rawSocket) => {
      rawSocket.pause();
      sockets.add(rawSocket);
      rawSocket.on('close', () => sockets.delete(rawSocket));

      const hello = new HandshakePacket({
        protocolVersion: 10,
        serverVersion: '8.4.3-tls-test',
        connectionId: 42,
        authPluginData1: crypto.randomBytes(8),
        authPluginData2: crypto.randomBytes(12),
        capabilityFlags:
          ClientConstants.LONG_PASSWORD |
          ClientConstants.PROTOCOL_41 |
          ClientConstants.SSL |
          ClientConstants.SECURE_CONNECTION |
          ClientConstants.PLUGIN_AUTH,
        characterSet: 45,
        statusFlags: 2,
        authPluginName: 'mysql_native_password'
      });

      const pkt = hello.toPacket(0);
      pkt.writeHeader(0);
      rawSocket.write(pkt.buffer);

      const onReadable = () => {
        const sslRequest = rawSocket.read(36);
        if (!sslRequest) {
          return;
        }
        rawSocket.removeListener('readable', onReadable);

        const tlsSocket = new tls.TLSSocket(rawSocket, {
          isServer: true,
          key,
          cert,
          requestCert: false,
          minVersion: 'TLSv1.2'
        });
        sockets.add(tlsSocket);
        tlsSocket.on('close', () => sockets.delete(tlsSocket));
        tlsSocket.on('error', (err) => {
          onTlsHandshake?.(err);
        });

        let authenticated = false;
        tlsSocket.on('data', (chunk) => {
          if (!authenticated) {
            authenticated = true;
            // Respuesta OK (seq=3 tras SSLRequest seq=1 y HandshakeResponse seq=2)
            tlsSocket.write(Buffer.from([7, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0]));
            return;
          }
          // Responder OK a COM_PING (0x0e) o COM_QUIT (0x01)
          if (chunk.length >= 5 && chunk[4] === 0x0e) {
            tlsSocket.write(Buffer.from([7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]));
          } else if (chunk.length >= 5 && chunk[4] === 0x01) {
            tlsSocket.end();
          }
        });
      };

      rawSocket.on('readable', onReadable);
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        close: () =>
          new Promise((res) => {
            for (const s of sockets) s.destroy();
            server.close(() => res());
          })
      });
    });
  });
}

describe('Seguridad TLS MySQL (buildSslOptions, classifyDatabaseError y handshake TLS real)', () => {
  let tmpDir;
  let caPem;
  let otherCaPem;
  let serverNoSanCert;
  let serverNoSanKey;
  let serverSanCert;
  let serverSanKey;
  let untrustedCert;
  let untrustedKey;
  let caFilePath;
  let hasOpenSsl = false;

  before(() => {
    const opensslBin = resolveOpenSslBinary();
    if (!opensslBin) {
      return;
    }
    hasOpenSsl = true;
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secvault-tls-'));

    const caKeyPath = path.join(tmpDir, 'ca-key.pem');
    caFilePath = path.join(tmpDir, 'ca.pem');
    execFileSync(opensslBin, ['genrsa', '-out', caKeyPath, '2048'], { stdio: 'ignore' });
    execFileSync(
      opensslBin,
      ['req', '-new', '-x509', '-days', '1', '-key', caKeyPath, '-out', caFilePath, '-subj', '/CN=SecureVault-Test-CA'],
      { stdio: 'ignore' }
    );
    caPem = fs.readFileSync(caFilePath, 'utf8');

    // Segunda CA independiente (para verificar rechazo de CA incorrecta)
    const otherCaKeyPath = path.join(tmpDir, 'other-ca-key.pem');
    const otherCaCertPath = path.join(tmpDir, 'other-ca.pem');
    execFileSync(opensslBin, ['genrsa', '-out', otherCaKeyPath, '2048'], { stdio: 'ignore' });
    execFileSync(
      opensslBin,
      ['req', '-new', '-x509', '-days', '1', '-key', otherCaKeyPath, '-out', otherCaCertPath, '-subj', '/CN=Untrusted-CA'],
      { stdio: 'ignore' }
    );
    otherCaPem = fs.readFileSync(otherCaCertPath, 'utf8');

    // Certificado estilo Railway MySQL (`auto_generate_certs` sin SAN) firmado por ca.pem
    const srvNoSanKeyPath = path.join(tmpDir, 'srv-nosan-key.pem');
    const srvNoSanCsrPath = path.join(tmpDir, 'srv-nosan.csr');
    const srvNoSanCertPath = path.join(tmpDir, 'srv-nosan.pem');
    execFileSync(opensslBin, ['genrsa', '-out', srvNoSanKeyPath, '2048'], { stdio: 'ignore' });
    execFileSync(
      opensslBin,
      ['req', '-new', '-key', srvNoSanKeyPath, '-out', srvNoSanCsrPath, '-subj', '/CN=MySQL_Server_8.4.3_Auto_Generated_Server_Certificate'],
      { stdio: 'ignore' }
    );
    execFileSync(
      opensslBin,
      ['x509', '-req', '-in', srvNoSanCsrPath, '-CA', caFilePath, '-CAkey', caKeyPath, '-CAcreateserial', '-out', srvNoSanCertPath, '-days', '1'],
      { stdio: 'ignore' }
    );
    serverNoSanCert = fs.readFileSync(srvNoSanCertPath, 'utf8');
    serverNoSanKey = fs.readFileSync(srvNoSanKeyPath, 'utf8');

    // Certificado con SAN (estilo MySQL gestionado con validación de hostname)
    const sanExtPath = path.join(tmpDir, 'san.cnf');
    fs.writeFileSync(sanExtPath, 'subjectAltName=IP:127.0.0.1,DNS:localhost\n', 'utf8');
    const srvSanKeyPath = path.join(tmpDir, 'srv-san-key.pem');
    const srvSanCsrPath = path.join(tmpDir, 'srv-san.csr');
    const srvSanCertPath = path.join(tmpDir, 'srv-san.pem');
    execFileSync(opensslBin, ['genrsa', '-out', srvSanKeyPath, '2048'], { stdio: 'ignore' });
    execFileSync(
      opensslBin,
      ['req', '-new', '-key', srvSanKeyPath, '-out', srvSanCsrPath, '-subj', '/CN=localhost'],
      { stdio: 'ignore' }
    );
    execFileSync(
      opensslBin,
      ['x509', '-req', '-in', srvSanCsrPath, '-CA', caFilePath, '-CAkey', caKeyPath, '-CAcreateserial', '-out', srvSanCertPath, '-days', '1', '-extfile', sanExtPath],
      { stdio: 'ignore' }
    );
    serverSanCert = fs.readFileSync(srvSanCertPath, 'utf8');
    serverSanKey = fs.readFileSync(srvSanKeyPath, 'utf8');

    // Certificado autofirmado independiente sin CA confiable
    const untrustedKeyPath = path.join(tmpDir, 'untrusted-key.pem');
    const untrustedCertPath = path.join(tmpDir, 'untrusted.pem');
    execFileSync(opensslBin, ['genrsa', '-out', untrustedKeyPath, '2048'], { stdio: 'ignore' });
    execFileSync(
      opensslBin,
      ['req', '-new', '-x509', '-days', '1', '-key', untrustedKeyPath, '-out', untrustedCertPath, '-subj', '/CN=Rogue-Self-Signed'],
      { stdio: 'ignore' }
    );
    untrustedCert = fs.readFileSync(untrustedCertPath, 'utf8');
    untrustedKey = fs.readFileSync(untrustedKeyPath, 'utf8');
  });

  after(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('buildSslOptions exige rejectUnauthorized=true, TLSv1.2+ y soporta PEM, Base64 y archivo sin aceptar llaves privadas', () => {
    assert.equal(buildSslOptions({ ssl: false }), undefined);

    const strictDefault = buildSslOptions({ ssl: true });
    assert.equal(strictDefault.rejectUnauthorized, true);
    assert.equal(strictDefault.minVersion, 'TLSv1.2');
    assert.equal(strictDefault.verifyIdentity, undefined);

    const withVerifyIdentity = buildSslOptions({ ssl: true, sslVerifyIdentity: true });
    assert.equal(withVerifyIdentity.rejectUnauthorized, true);
    assert.equal(withVerifyIdentity.verifyIdentity, true);

    if (hasOpenSsl) {
      const fromEscaped = buildSslOptions({
        ssl: true,
        sslCa: `"${caPem.replace(/\n/g, '\\n')}"`
      });
      assert.ok(fromEscaped.ca.includes('BEGIN CERTIFICATE'));

      const fromBase64 = buildSslOptions({
        ssl: true,
        sslCa: Buffer.from(caPem, 'utf8').toString('base64')
      });
      assert.equal(fromBase64.ca, caPem.replace(/\r\n/g, '\n'));

      const fromFile = buildSslOptions({ ssl: true, sslCa: caFilePath });
      assert.equal(fromFile.ca, caPem.replace(/\r\n/g, '\n'));

      assert.throws(
        () => buildSslOptions({ ssl: true, sslCa: serverSanKey }),
        /llaves privadas/
      );
    }

    assert.throws(
      () => buildSslOptions({ ssl: true, sslCa: 'no-es-un-certificado-ni-ruta' }),
      /certificado PEM válido/
    );
  });

  it('classifyDatabaseError identifica los 5 tipos de error y redacta credenciales/PEM', () => {
    const tlsErr = classifyDatabaseError({
      code: 'HANDSHAKE_SSL_ERROR',
      message: 'self-signed certificate in certificate chain'
    });
    assert.equal(tlsErr.category, 'TLS_CERTIFICATE_ERROR');
    assert.match(tlsErr.guidance, /DB_SSL_CA/);

    const authErr = classifyDatabaseError({
      code: 'ER_ACCESS_DENIED_ERROR',
      message: "Access denied for user 'securevault_app'@'10.0.0.2' password=SuperSecret123"
    });
    assert.equal(authErr.category, 'MYSQL_AUTH_ERROR');
    assert.equal(authErr.message.includes('SuperSecret123'), false);

    const connErr = classifyDatabaseError({
      code: 'ECONNREFUSED',
      message: 'connect ECONNREFUSED mysql://user:topsecret@10.0.0.3:3306/railway'
    });
    assert.equal(connErr.category, 'MYSQL_CONNECTION_ERROR');
    assert.equal(connErr.message.includes('topsecret'), false);
    assert.match(connErr.message, /\[REDACTED\]/);

    const cfgErr = classifyDatabaseError(
      new Error('DB_SSL=true es obligatorio en producción para validar TLS hacia MySQL.')
    );
    assert.equal(cfgErr.category, 'CONFIGURATION_ERROR');

    const availErr = classifyDatabaseError({
      code: 'ER_BAD_DB_ERROR',
      message: "Unknown database 'missing_db'"
    });
    assert.equal(availErr.category, 'MYSQL_AVAILABILITY_ERROR');

    const missingTableErr = classifyDatabaseError({
      code: 'ER_NO_SUCH_TABLE',
      message: "Table 'railway.users' doesn't exist"
    });
    assert.equal(missingTableErr.category, 'MYSQL_AVAILABILITY_ERROR');
    assert.match(missingTableErr.guidance, /db:migrate/);

    const scrubbedPem = sanitizeDatabaseErrorMessage(
      'Fallo con -----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----'
    );
    assert.equal(scrubbedPem.includes('ABC'), false);
    assert.match(scrubbedPem, /\[PEM REDACTED\]/);
  });

  it('mysql2 rechaza certificados autofirmados no confiables y conecta con éxito cuando se fija DB_SSL_CA', async (t) => {
    if (!hasOpenSsl) {
      t.skip('OpenSSL no disponible para generar certificados efímeros');
      return;
    }

    const baseEnv = {
      NODE_ENV: 'production',
      APP_URL: 'https://sec-vault-production-4ffdb3db.up.railway.app',
      DB_HOST: '127.0.0.1',
      DB_NAME: 'railway',
      DB_USER: 'securevault_app',
      DB_PASSWORD: 'StrongTestDbPassword_2026!',
      DB_SSL: 'true',
      SESSION_SECRET: crypto.randomBytes(32).toString('hex'),
      DATA_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex')
    };

    // 1) Servidor con certificado autofirmado SIN DB_SSL_CA -> DEBE RECHAZAR
    const srvUntrusted = await createEphemeralMysqlTlsServer({ key: untrustedKey, cert: untrustedCert });
    try {
      const cfgNoCa = loadConfig({ ...baseEnv, DB_PORT: String(srvUntrusted.port) }, { loadDotenv: false });
      const poolNoCa = createPool(cfgNoCa);
      try {
        await assert.rejects(
          () => checkDatabaseHealth(poolNoCa, { requireTls: true }),
          (err) => {
            const c = classifyDatabaseError(err);
            assert.equal(c.category, 'TLS_CERTIFICATE_ERROR');
            return true;
          }
        );
      } finally {
        await poolNoCa.end();
      }
    } finally {
      await srvUntrusted.close();
    }

    // 2) Servidor estilo Railway MySQL (certificado sin SAN firmado por CA propia):
    //    - Falla con CA equivocada
    //    - Conecta cifrado con DB_SSL_CA en Base64 fijando la CA correcta (rejectUnauthorized: true)
    //    - Rechaza si se activa DB_SSL_VERIFY_IDENTITY=true sin SAN coincidente
    const srvNoSan = await createEphemeralMysqlTlsServer({ key: serverNoSanKey, cert: serverNoSanCert });
    try {
      const cfgWrongCa = loadConfig(
        { ...baseEnv, DB_PORT: String(srvNoSan.port), DB_SSL_CA: otherCaPem },
        { loadDotenv: false }
      );
      const poolWrongCa = createPool(cfgWrongCa);
      try {
        await assert.rejects(
          () => checkDatabaseHealth(poolWrongCa),
          (err) => classifyDatabaseError(err).category === 'TLS_CERTIFICATE_ERROR'
        );
      } finally {
        await poolWrongCa.end();
      }

      const caBase64 = Buffer.from(caPem, 'utf8').toString('base64');
      const cfgPinnedCa = loadConfig(
        { ...baseEnv, DB_PORT: String(srvNoSan.port), DB_SSL_CA: caBase64 },
        { loadDotenv: false }
      );
      const poolPinnedCa = createPool(cfgPinnedCa);
      try {
        assert.equal(await checkDatabaseHealth(poolPinnedCa), true);
      } finally {
        await poolPinnedCa.end();
      }

      const cfgStrictHostname = loadConfig(
        {
          ...baseEnv,
          DB_HOST: 'localhost',
          DB_PORT: String(srvNoSan.port),
          DB_SSL_CA: caBase64,
          DB_SSL_VERIFY_IDENTITY: 'true'
        },
        { loadDotenv: false }
      );
      const poolStrictHostname = createPool(cfgStrictHostname);
      try {
        await assert.rejects(
          () => checkDatabaseHealth(poolStrictHostname),
          (err) => classifyDatabaseError(err).category === 'TLS_CERTIFICATE_ERROR'
        );
      } finally {
        await poolStrictHostname.end();
      }
    } finally {
      await srvNoSan.close();
    }

    // 3) Servidor con SAN válido + DB_SSL_VERIFY_IDENTITY=true + DB_SSL_CA -> CONECTA CON VERIFICACIÓN DE IDENTIDAD
    const srvSan = await createEphemeralMysqlTlsServer({ key: serverSanKey, cert: serverSanCert });
    try {
      const cfgSan = loadConfig(
        {
          ...baseEnv,
          DB_HOST: 'localhost',
          DB_PORT: String(srvSan.port),
          DB_SSL_CA: caPem,
          DB_SSL_VERIFY_IDENTITY: 'true'
        },
        { loadDotenv: false }
      );
      const poolSan = createPool(cfgSan);
      try {
        assert.equal(await checkDatabaseHealth(poolSan), true);
      } finally {
        await poolSan.end();
      }
    } finally {
      await srvSan.close();
    }
  });
});
