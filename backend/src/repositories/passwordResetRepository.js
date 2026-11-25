import { withTransaction } from '../config/database.js';
import { AppError } from '../utils/errors.js';

/**
 * Repositorio MySQL para tokens SHA-256 de recuperación de contraseñas.
 */
export function createPasswordResetRepository(pool) {
  async function createResetToken({ userId, tokenHash, expiresAt }) {
    return withTransaction(pool, async (conn) => {
      // Invalidar cualquier token activo previo del mismo usuario
      await conn.execute(
        `UPDATE password_resets
         SET used_at = NOW()
         WHERE user_id = ? AND used_at IS NULL`,
        [Number(userId)]
      );

      await conn.execute(
        `INSERT INTO password_resets (user_id, token_hash, expires_at)
         VALUES (?, ?, ?)`,
        [Number(userId), tokenHash, expiresAt]
      );
    });
  }

  async function consumeTokenAndResetPassword({ tokenHash, newPasswordHash, ipAddress }) {
    return withTransaction(pool, async (conn) => {
      const [rows] = await conn.execute(
        `SELECT id, user_id, expires_at, used_at
         FROM password_resets
         WHERE token_hash = ?
         LIMIT 1
         FOR UPDATE`,
        [tokenHash]
      );

      if (!rows.length) {
        throw new AppError('El token de recuperación es inválido o ha expirado.', 400, 'INVALID_RESET_TOKEN');
      }

      const record = rows[0];
      if (record.used_at !== null) {
        throw new AppError('Este enlace de recuperación ya fue utilizado.', 400, 'RESET_TOKEN_ALREADY_USED');
      }

      if (new Date(record.expires_at).getTime() <= Date.now()) {
        throw new AppError('El token de recuperación ha expirado.', 400, 'RESET_TOKEN_EXPIRED');
      }

      await conn.execute(
        'UPDATE password_resets SET used_at = NOW() WHERE id = ?',
        [Number(record.id)]
      );

      await conn.execute(
        'UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL',
        [Number(record.user_id)]
      );

      await conn.execute(
        `UPDATE users
         SET password_hash = ?, session_version = session_version + 1
         WHERE id = ?`,
        [newPasswordHash, Number(record.user_id)]
      );

      await conn.execute(
        `INSERT INTO security_events (actor_id, event_type, severity, description, metadata, ip_address)
         VALUES (?, 'PASSWORD_RESET_COMPLETED', 'INFO', 'Contraseña restablecida mediante token seguro de un solo uso', ?, ?)`,
        [Number(record.user_id), JSON.stringify({ sessionsInvalidated: true }), ipAddress || null]
      );

      return { userId: Number(record.user_id) };
    });
  }

  return {
    createResetToken,
    consumeTokenAndResetPassword
  };
}
