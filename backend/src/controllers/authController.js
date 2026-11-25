import { hashPassword, verifyPassword, dummyVerify } from '../services/passwordService.js';
import {
  establishAuthenticatedSession,
  establishPendingMfaSession,
  destroySession
} from '../services/sessionService.js';
import { verifyTotpCode, consumeRecoveryCode } from '../services/totpService.js';
import { extractClientIp } from '../utils/sanitize.js';
import { unauthorized, tooManyRequests } from '../utils/errors.js';

function sanitizePublicUser(user) {
  return {
    id: Number(user.id),
    name: user.name,
    email: user.email,
    role: user.role,
    mfaEnabled: Boolean(user.mfa_enabled ?? user.mfaEnabled),
    createdAt: user.created_at ?? user.createdAt,
    updatedAt: user.updated_at ?? user.updatedAt
  };
}

export function createAuthController({
  config,
  userRepository,
  loginAttemptRepository,
  encryptionService,
  auditService,
  alertService
}) {
  async function register(req, res, next) {
    try {
      const { name, email, password, phone } = req.validated.body;
      const ip = extractClientIp(req);

      const passwordHash = await hashPassword(password, config.crypto.bcryptRounds);
      const createdUser = await userRepository.createUserWithEncryptedPhone({
        name,
        emailNormalized: email,
        passwordHash,
        phone,
        encryptionService
      });

      const csrfToken = await establishAuthenticatedSession(req, {
        id: createdUser.id,
        role: createdUser.role,
        sessionVersion: createdUser.session_version
      });

      await auditService.recordEvent({
        actorId: createdUser.id,
        eventType: 'SESSION_CREATED',
        severity: 'INFO',
        description: 'Sesión inicial creada tras registro exitoso',
        metadata: { role: createdUser.role },
        ipAddress: ip
      });

      return res.status(201).json({
        user: sanitizePublicUser(createdUser),
        csrfToken
      });
    } catch (err) {
      return next(err);
    }
  }

  async function login(req, res, next) {
    try {
      const { email, password } = req.validated.body;
      const ip = extractClientIp(req);

      const attemptRecord = await loginAttemptRepository.getByEmail(email);
      if (attemptRecord?.locked_until) {
        const lockedUntilMs = new Date(attemptRecord.locked_until).getTime();
        if (lockedUntilMs > Date.now()) {
          const retryAfterSeconds = Math.max(1, Math.ceil((lockedUntilMs - Date.now()) / 1000));
          res.setHeader('Retry-After', String(retryAfterSeconds));

          await auditService.recordEvent({
            actorId: null,
            eventType: 'LOGIN_LOCKED_ATTEMPT',
            severity: 'HIGH',
            description: 'Intento de login sobre cuenta temporalmente bloqueada',
            metadata: { retryAfterSeconds },
            ipAddress: ip
          });

          return next(
            tooManyRequests(
              'Demasiados intentos fallidos. Tu cuenta está bloqueada temporalmente.',
              'ACCOUNT_LOCKED',
              { retryAfterSeconds }
            )
          );
        }
      }

      const user = await userRepository.findByEmailForAuth(email);
      let passwordValid = false;

      if (!user) {
        await dummyVerify(password);
      } else {
        passwordValid = await verifyPassword(password, user.password_hash);
      }

      if (!passwordValid || !user) {
        const failure = await loginAttemptRepository.recordFailure(email, ip);

        if (failure.attempts >= 5) {
          await alertService.triggerSecurityAlert({
            actorId: user ? Number(user.id) : null,
            eventType: 'BRUTE_FORCE_ALERT',
            severity: 'HIGH',
            description: `Alerta de fuerza bruta: ${failure.attempts} intentos fallidos consecutivos`,
            metadata: { attempts: failure.attempts, lockSeconds: failure.lockSeconds },
            ipAddress: ip
          });
        } else {
          await auditService.recordEvent({
            actorId: user ? Number(user.id) : null,
            eventType: 'LOGIN_FAILED',
            severity: 'WARNING',
            description: 'Intento de inicio de sesión con credenciales inválidas',
            metadata: { attempts: failure.attempts },
            ipAddress: ip
          });
        }

        if (failure.lockSeconds > 0) {
          res.setHeader('Retry-After', String(failure.lockSeconds));
          return next(
            tooManyRequests(
              'Demasiados intentos fallidos. Cuenta bloqueada temporalmente.',
              'ACCOUNT_LOCKED',
              { retryAfterSeconds: failure.lockSeconds }
            )
          );
        }

        return next(unauthorized('Credenciales inválidas.', 'INVALID_CREDENTIALS'));
      }

      await loginAttemptRepository.reset(email);

      if (user.mfa_enabled) {
        const csrfToken = await establishPendingMfaSession(req, user.id);
        await auditService.recordEvent({
          actorId: Number(user.id),
          eventType: 'MFA_CHALLENGE_ISSUED',
          severity: 'INFO',
          description: 'Segundo factor TOTP requerido para completar el inicio de sesión',
          ipAddress: ip
        });

        return res.status(200).json({
          mfaRequired: true,
          csrfToken
        });
      }

      const csrfToken = await establishAuthenticatedSession(req, {
        id: user.id,
        role: user.role,
        sessionVersion: user.session_version
      });

      await auditService.recordEvent({
        actorId: Number(user.id),
        eventType: 'LOGIN_SUCCESS',
        severity: 'INFO',
        description: 'Inicio de sesión exitoso',
        metadata: { role: user.role },
        ipAddress: ip
      });

      return res.status(200).json({
        mfaRequired: false,
        user: sanitizePublicUser(user),
        csrfToken
      });
    } catch (err) {
      return next(err);
    }
  }

  async function verifyMfa(req, res, next) {
    try {
      const pendingUserId = req.session?.pendingMfaUserId;
      const pendingExpires = Number(req.session?.pendingMfaExpiresAt || 0);
      const ip = extractClientIp(req);

      if (!pendingUserId || Date.now() > pendingExpires) {
        await destroySession(req).catch(() => {});
        return next(unauthorized('La verificación MFA ha expirado. Inicia sesión nuevamente.', 'MFA_EXPIRED'));
      }

      const user = await userRepository.findById(pendingUserId);
      if (!user || !user.mfa_enabled || !user.mfa_secret_encrypted) {
        await destroySession(req).catch(() => {});
        return next(unauthorized('Estado MFA inválido.', 'MFA_INVALID_STATE'));
      }

      const { code } = req.validated.body;
      const secret = encryptionService.decryptData(user.mfa_secret_encrypted, `user:${user.id}:mfa`);
      let verified = verifyTotpCode(secret, code);
      let usedRecovery = false;

      if (!verified) {
        const storedHashes = Array.isArray(user.mfa_recovery_hashes)
          ? user.mfa_recovery_hashes
          : typeof user.mfa_recovery_hashes === 'string'
            ? JSON.parse(user.mfa_recovery_hashes)
            : [];
        const recovery = consumeRecoveryCode(code, storedHashes);
        if (recovery.matched) {
          verified = true;
          usedRecovery = true;
          await userRepository.updateMfaRecoveryHashes({
            userId: user.id,
            mfaRecoveryHashes: recovery.remainingHashes
          });
        }
      }

      if (!verified) {
        await auditService.recordEvent({
          actorId: Number(user.id),
          eventType: 'MFA_FAILED',
          severity: 'WARNING',
          description: 'Código TOTP o de recuperación inválido',
          ipAddress: ip
        });
        return next(unauthorized('Código MFA inválido.', 'INVALID_MFA_CODE'));
      }

      const csrfToken = await establishAuthenticatedSession(req, {
        id: user.id,
        role: user.role,
        sessionVersion: user.session_version
      });

      await auditService.recordEvent({
        actorId: Number(user.id),
        eventType: 'LOGIN_SUCCESS',
        severity: 'INFO',
        description: usedRecovery
          ? 'Inicio de sesión exitoso mediante código de recuperación MFA'
          : 'Inicio de sesión exitoso con verificación MFA TOTP',
        metadata: { mfa: true, usedRecovery },
        ipAddress: ip
      });

      return res.status(200).json({
        user: sanitizePublicUser(user),
        csrfToken
      });
    } catch (err) {
      return next(err);
    }
  }

  async function logout(req, res, next) {
    try {
      const actorId = req.session?.userId ? Number(req.session.userId) : null;
      const ip = extractClientIp(req);

      await destroySession(req);
      res.clearCookie('secvault.sid', { path: '/' });

      if (actorId) {
        await auditService.recordEvent({
          actorId,
          eventType: 'LOGOUT',
          severity: 'INFO',
          description: 'Cierre de sesión voluntario',
          ipAddress: ip
        });
      }

      return res.status(200).json({ message: 'Sesión cerrada correctamente.' });
    } catch (err) {
      return next(err);
    }
  }

  async function me(req, res) {
    return res.status(200).json({
      user: sanitizePublicUser(req.user),
      csrfToken: req.session.csrfToken
    });
  }

  return {
    register,
    login,
    verifyMfa,
    logout,
    me
  };
}
