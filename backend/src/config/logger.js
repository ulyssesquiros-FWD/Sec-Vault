import pino from 'pino';

/**
 * Crea un logger JSON estructurado Pino con redacción estricta de secretos y PII sensible.
 * @param {{ nodeEnv?: string, isTest?: boolean }} [config]
 */
export function createLogger(config = {}) {
  const level = config.isTest ? 'silent' : config.nodeEnv === 'production' ? 'info' : 'debug';

  return pino({
    level,
    base: { service: 'securevault-api' },
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: [
        'req.headers.cookie',
        'req.headers.authorization',
        'req.headers["x-csrf-token"]',
        'res.headers["set-cookie"]',
        '*.password',
        '*.newPassword',
        '*.currentPassword',
        '*.passwordHash',
        '*.password_hash',
        '*.token',
        '*.rawToken',
        '*.resetToken',
        '*.csrfToken',
        '*.secret',
        '*.sessionSecret',
        '*.totpSecret',
        '*.mfaSecret',
        '*.encryptionKey',
        '*.content',
        '*.decryptedContent',
        '*.phone',
        '*.smtpPassword'
      ],
      censor: '[REDACTED]'
    }
  });
}
