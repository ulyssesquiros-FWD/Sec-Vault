import { hashPassword, verifyPassword } from '../services/passwordService.js';
import { establishAuthenticatedSession } from '../services/sessionService.js';
import {
  generateTotpSecret,
  buildOtpAuthUri,
  generateQrDataUrl,
  verifyTotpCode,
  generateRecoveryCodes
} from '../services/totpService.js';
import { extractClientIp, maskPhone } from '../utils/sanitize.js';
import { badRequest, unauthorized } from '../utils/errors.js';

export function createUserController({
  config,
  userRepository,
  encryptionService,
  auditService
}) {
  async function getProfile(req, res, next) {
    try {
      const user = await userRepository.findById(req.user.id);
      if (!user) {
        return next(unauthorized('Usuario no encontrado.', 'USER_NOT_FOUND'));
      }

      let maskedPhone = '***';
      if (user.encrypted_phone) {
        const plainPhone = encryptionService.decryptData(user.encrypted_phone, `user:${user.id}:phone`);
        maskedPhone = maskPhone(plainPhone);

        if (encryptionService.needsReencryption(user.encrypted_phone)) {
          const rotated = encryptionService.encryptData(plainPhone, `user:${user.id}:phone`);
          await userRepository.updateEncryptedPhone({
            userId: user.id,
            encryptedPhone: rotated,
            phoneKeyVersion: encryptionService.activeKeyVersion
          });
        }
      }

      return res.status(200).json({
        profile: {
          id: Number(user.id),
          name: user.name,
          email: user.email,
          role: user.role,
          maskedPhone,
          mfaEnabled: Boolean(user.mfa_enabled),
          createdAt: user.created_at,
          updatedAt: user.updated_at
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function revealPhone(req, res, next) {
    try {
      const { currentPassword } = req.validated.body;
      const ip = extractClientIp(req);
      const creds = await userRepository.findCredentialsById(req.user.id);

      const ok = await verifyPassword(currentPassword, creds?.password_hash);
      if (!ok) {
        return next(unauthorized('La contraseña actual es incorrecta.', 'INVALID_PASSWORD'));
      }

      const user = await userRepository.findById(req.user.id);
      const plainPhone = user?.encrypted_phone
        ? encryptionService.decryptData(user.encrypted_phone, `user:${user.id}:phone`)
        : '';

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'PHONE_REVEALED',
        severity: 'INFO',
        description: 'El usuario reveló su teléfono completo tras verificar contraseña',
        ipAddress: ip
      });

      return res.status(200).json({ phone: plainPhone });
    } catch (err) {
      return next(err);
    }
  }

  async function updateProfile(req, res, next) {
    try {
      const { name, phone } = req.validated.body;
      const ip = extractClientIp(req);
      const encryptedPhone = encryptionService.encryptData(phone, `user:${req.user.id}:phone`);

      const updated = await userRepository.updateProfile({
        userId: req.user.id,
        name,
        encryptedPhone,
        phoneKeyVersion: encryptionService.activeKeyVersion
      });

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'PROFILE_UPDATED',
        severity: 'INFO',
        description: 'Perfil de usuario actualizado',
        ipAddress: ip
      });

      return res.status(200).json({
        profile: {
          id: Number(updated.id),
          name: updated.name,
          email: updated.email,
          role: updated.role,
          maskedPhone: maskPhone(phone),
          mfaEnabled: Boolean(updated.mfa_enabled),
          createdAt: updated.created_at,
          updatedAt: updated.updated_at
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword } = req.validated.body;
      const ip = extractClientIp(req);

      const creds = await userRepository.findCredentialsById(req.user.id);
      const valid = await verifyPassword(currentPassword, creds?.password_hash);
      if (!valid) {
        return next(unauthorized('La contraseña actual es incorrecta.', 'INVALID_CURRENT_PASSWORD'));
      }

      if (currentPassword === newPassword) {
        return next(badRequest('La nueva contraseña debe ser diferente a la actual.', 'SAME_PASSWORD'));
      }

      const newPasswordHash = await hashPassword(newPassword, config.crypto.bcryptRounds);
      await userRepository.updatePasswordAndBumpSessionVersion({
        userId: req.user.id,
        newPasswordHash
      });

      const nextSessionVersion = Number(creds.session_version) + 1;
      const csrfToken = await establishAuthenticatedSession(req, {
        id: req.user.id,
        role: req.user.role,
        sessionVersion: nextSessionVersion
      });

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'PASSWORD_CHANGED',
        severity: 'INFO',
        description: 'Contraseña actualizada y sesiones anteriores revocadas',
        ipAddress: ip
      });

      return res.status(200).json({
        message: 'Contraseña actualizada correctamente.',
        csrfToken
      });
    } catch (err) {
      return next(err);
    }
  }

  async function setupMfa(req, res, next) {
    try {
      const secret = generateTotpSecret();
      const otpauthUri = buildOtpAuthUri({ secret, email: req.user.email });
      const qrDataUrl = await generateQrDataUrl(otpauthUri);

      req.session.pendingTotpSetupSecret = secret;

      return res.status(200).json({
        secret,
        otpauthUri,
        qrDataUrl
      });
    } catch (err) {
      return next(err);
    }
  }

  async function enableMfa(req, res, next) {
    try {
      const { code } = req.validated.body;
      const pendingSecret = req.session?.pendingTotpSetupSecret;
      const ip = extractClientIp(req);

      if (!pendingSecret) {
        return next(badRequest('Inicia primero la configuración MFA generando un código QR.', 'MFA_SETUP_REQUIRED'));
      }

      if (!verifyTotpCode(pendingSecret, code)) {
        return next(badRequest('El código de verificación TOTP es incorrecto.', 'INVALID_TOTP_CODE'));
      }

      const encryptedSecret = encryptionService.encryptData(pendingSecret, `user:${req.user.id}:mfa`);
      const { plainCodes, hashedCodes } = generateRecoveryCodes(8);

      await userRepository.setMfaConfig({
        userId: req.user.id,
        mfaEnabled: true,
        mfaSecretEncrypted: encryptedSecret,
        mfaRecoveryHashes: hashedCodes
      });

      delete req.session.pendingTotpSetupSecret;

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'MFA_ENABLED',
        severity: 'INFO',
        description: 'Autenticación multifactor (TOTP) activada en la cuenta',
        ipAddress: ip
      });

      return res.status(200).json({
        message: 'MFA TOTP activado correctamente. Guarda estos códigos de recuperación en un lugar seguro.',
        recoveryCodes: plainCodes
      });
    } catch (err) {
      return next(err);
    }
  }

  async function disableMfa(req, res, next) {
    try {
      const { currentPassword } = req.validated.body;
      const ip = extractClientIp(req);

      const creds = await userRepository.findCredentialsById(req.user.id);
      const valid = await verifyPassword(currentPassword, creds?.password_hash);
      if (!valid) {
        return next(unauthorized('Contraseña incorrecta.', 'INVALID_PASSWORD'));
      }

      await userRepository.setMfaConfig({
        userId: req.user.id,
        mfaEnabled: false,
        mfaSecretEncrypted: null,
        mfaRecoveryHashes: null
      });

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'MFA_DISABLED',
        severity: 'WARNING',
        description: 'Autenticación multifactor (TOTP) desactivada por el usuario',
        ipAddress: ip
      });

      return res.status(200).json({
        message: 'MFA desactivado correctamente.'
      });
    } catch (err) {
      return next(err);
    }
  }

  return {
    getProfile,
    revealPhone,
    updateProfile,
    changePassword,
    setupMfa,
    enableMfa,
    disableMfa
  };
}
