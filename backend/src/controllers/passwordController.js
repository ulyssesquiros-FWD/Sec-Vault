import { hashPassword } from '../services/passwordService.js';
import { generateSecureToken, hashToken } from '../services/tokenService.js';
import { destroySession } from '../services/sessionService.js';
import { getClearCookieOptions } from '../config/session.js';
import { extractClientIp } from '../utils/sanitize.js';

const RESET_EXPIRATION_MS = 30 * 60 * 1000;
const GENERIC_FORGOT_MESSAGE =
  'Si el correo electrónico se encuentra registrado, recibirás instrucciones para restablecer tu contraseña.';

export function createPasswordController({
  config,
  userRepository,
  passwordResetRepository,
  emailService,
  auditService
}) {
  async function forgotPassword(req, res, next) {
    try {
      const { email } = req.validated.body;
      const ip = extractClientIp(req);
      const user = await userRepository.findByEmailForAuth(email);

      if (user) {
        const rawToken = generateSecureToken(32);
        const tokenHash = hashToken(rawToken);
        const expiresAt = new Date(Date.now() + RESET_EXPIRATION_MS);

        await passwordResetRepository.createResetToken({
          userId: user.id,
          tokenHash,
          expiresAt
        });

        const delivery = await emailService.sendPasswordResetEmail({
          to: user.email,
          name: user.name,
          rawToken
        });

        await auditService.recordEvent({
          actorId: Number(user.id),
          eventType: 'PASSWORD_RESET_REQUESTED',
          severity: 'INFO',
          description: 'Solicitud de recuperación de contraseña generada',
          metadata: { emailSent: delivery.sent },
          ipAddress: ip
        });
      } else {
        await auditService.recordEvent({
          actorId: null,
          eventType: 'PASSWORD_RESET_UNKNOWN_EMAIL',
          severity: 'INFO',
          description: 'Solicitud de recuperación para correo no registrado (respuesta genérica)',
          ipAddress: ip
        });
      }

      // Respuesta idéntica exista o no la cuenta para evitar enumeración de usuarios
      return res.status(200).json({ message: GENERIC_FORGOT_MESSAGE });
    } catch (err) {
      return next(err);
    }
  }

  async function resetPassword(req, res, next) {
    try {
      const { token, newPassword } = req.validated.body;
      const ip = extractClientIp(req);
      const tokenHash = hashToken(token);
      const newPasswordHash = await hashPassword(newPassword, config.crypto.bcryptRounds);

      await passwordResetRepository.consumeTokenAndResetPassword({
        tokenHash,
        newPasswordHash,
        ipAddress: ip
      });

      if (req.session) {
        await destroySession(req).catch(() => {});
        res.clearCookie('secvault.sid', getClearCookieOptions(config));
      }

      return res.status(200).json({
        message: 'Contraseña restablecida correctamente. Ya puedes iniciar sesión con tu nueva clave.'
      });
    } catch (err) {
      return next(err);
    }
  }

  return {
    forgotPassword,
    resetPassword
  };
}
