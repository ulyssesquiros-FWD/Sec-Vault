import { withTransaction } from '../config/database.js';
import { AppError } from '../utils/errors.js';

/**
 * Repositorio MySQL para usuarios.
 * Todas las consultas utilizan placeholders `?` parametrizados.
 */
export function createUserRepository(pool) {
  async function findByEmailForAuth(emailNormalized) {
    const [rows] = await pool.execute(
      `SELECT id, name, email, password_hash, role, encrypted_phone, phone_key_version,
              session_version, mfa_enabled, mfa_secret_encrypted, mfa_recovery_hashes,
              created_at, updated_at
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [emailNormalized]
    );
    return rows[0] || null;
  }

  async function findById(userId) {
    const [rows] = await pool.execute(
      `SELECT id, name, email, role, encrypted_phone, phone_key_version,
              session_version, mfa_enabled, mfa_secret_encrypted, mfa_recovery_hashes,
              created_at, updated_at
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [Number(userId)]
    );
    return rows[0] || null;
  }

  async function findCredentialsById(userId) {
    const [rows] = await pool.execute(
      `SELECT id, name, email, password_hash, role, session_version, mfa_enabled
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [Number(userId)]
    );
    return rows[0] || null;
  }

  async function createUserWithEncryptedPhone({ name, emailNormalized, passwordHash, phone, encryptionService }) {
    return withTransaction(pool, async (conn) => {
      const [existing] = await conn.execute(
        'SELECT id FROM users WHERE email = ? LIMIT 1',
        [emailNormalized]
      );
      if (existing.length > 0) {
        throw new AppError('No fue posible completar el registro con ese correo.', 409, 'EMAIL_ALREADY_EXISTS');
      }

      const [insertResult] = await conn.execute(
        `INSERT INTO users (name, email, password_hash, role, encrypted_phone, phone_key_version, session_version)
         VALUES (?, ?, ?, 'user', NULL, ?, 1)`,
        [name, emailNormalized, passwordHash, encryptionService.activeKeyVersion]
      );

      const userId = Number(insertResult.insertId);
      const encryptedPhone = encryptionService.encryptData(phone, `user:${userId}:phone`);

      await conn.execute(
        `UPDATE users SET encrypted_phone = ?, phone_key_version = ? WHERE id = ?`,
        [encryptedPhone, encryptionService.activeKeyVersion, userId]
      );

      await conn.execute(
        `INSERT INTO security_events (actor_id, event_type, severity, description, metadata)
         VALUES (?, 'USER_REGISTERED', 'INFO', 'Nuevo usuario registrado en SecureVault', ?)`,
        [userId, JSON.stringify({ role: 'user' })]
      );

      return {
        id: userId,
        name,
        email: emailNormalized,
        role: 'user',
        session_version: 1,
        mfa_enabled: 0
      };
    });
  }

  async function createAdminSeedUser({ name, emailNormalized, passwordHash, phone, encryptionService }) {
    return withTransaction(pool, async (conn) => {
      const [existing] = await conn.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [emailNormalized]);
      if (existing.length > 0) {
        return { created: false, id: Number(existing[0].id) };
      }

      const [insertResult] = await conn.execute(
        `INSERT INTO users (name, email, password_hash, role, encrypted_phone, phone_key_version, session_version)
         VALUES (?, ?, ?, 'admin', NULL, ?, 1)`,
        [name, emailNormalized, passwordHash, encryptionService.activeKeyVersion]
      );

      const userId = Number(insertResult.insertId);
      const encryptedPhone = encryptionService.encryptData(phone, `user:${userId}:phone`);

      await conn.execute(
        'UPDATE users SET encrypted_phone = ?, phone_key_version = ? WHERE id = ?',
        [encryptedPhone, encryptionService.activeKeyVersion, userId]
      );

      await conn.execute(
        `INSERT INTO security_events (actor_id, event_type, severity, description, metadata)
         VALUES (?, 'ADMIN_SEEDED', 'INFO', 'Cuenta administrativa inicializada', ?)`,
        [userId, JSON.stringify({ role: 'admin' })]
      );

      return { created: true, id: userId };
    });
  }

  async function updateProfile({ userId, name, encryptedPhone, phoneKeyVersion }) {
    await pool.execute(
      `UPDATE users
       SET name = ?, encrypted_phone = ?, phone_key_version = ?
       WHERE id = ?`,
      [name, encryptedPhone, phoneKeyVersion, Number(userId)]
    );
    return findById(userId);
  }

  async function updateEncryptedPhone({ userId, encryptedPhone, phoneKeyVersion }) {
    await pool.execute(
      `UPDATE users SET encrypted_phone = ?, phone_key_version = ? WHERE id = ?`,
      [encryptedPhone, phoneKeyVersion, Number(userId)]
    );
  }

  async function updatePasswordAndBumpSessionVersion({ userId, newPasswordHash }) {
    await pool.execute(
      `UPDATE users
       SET password_hash = ?, session_version = session_version + 1
       WHERE id = ?`,
      [newPasswordHash, Number(userId)]
    );
  }

  async function updateRoleWithAudit({ targetUserId, newRole, adminId, ipAddress }) {
    return withTransaction(pool, async (conn) => {
      const [rows] = await conn.execute(
        'SELECT id, role, email FROM users WHERE id = ? FOR UPDATE',
        [Number(targetUserId)]
      );
      if (!rows.length) {
        throw new AppError('Usuario no encontrado.', 404, 'USER_NOT_FOUND');
      }

      const previousRole = rows[0].role;
      await conn.execute(
        `UPDATE users
         SET role = ?, session_version = session_version + 1
         WHERE id = ?`,
        [newRole, Number(targetUserId)]
      );

      await conn.execute(
        `INSERT INTO security_events (actor_id, event_type, severity, description, metadata, ip_address)
         VALUES (?, 'ROLE_CHANGED', 'HIGH', ?, ?, ?)`,
        [
          Number(adminId),
          `Cambio de rol para usuario #${Number(targetUserId)}: ${previousRole} -> ${newRole}`,
          JSON.stringify({ targetUserId: Number(targetUserId), previousRole, newRole }),
          ipAddress || null
        ]
      );

      return {
        id: Number(targetUserId),
        previousRole,
        role: newRole
      };
    });
  }

  async function setMfaConfig({ userId, mfaEnabled, mfaSecretEncrypted, mfaRecoveryHashes }) {
    await pool.execute(
      `UPDATE users
       SET mfa_enabled = ?, mfa_secret_encrypted = ?, mfa_recovery_hashes = ?
       WHERE id = ?`,
      [
        mfaEnabled ? 1 : 0,
        mfaSecretEncrypted,
        mfaRecoveryHashes ? JSON.stringify(mfaRecoveryHashes) : null,
        Number(userId)
      ]
    );
  }

  async function updateMfaRecoveryHashes({ userId, mfaRecoveryHashes }) {
    await pool.execute(
      'UPDATE users SET mfa_recovery_hashes = ? WHERE id = ?',
      [JSON.stringify(mfaRecoveryHashes), Number(userId)]
    );
  }

  async function listUsers({ search = '', role = '', limit = 20, offset = 0 }) {
    const conditions = [];
    const params = [];

    if (role === 'user' || role === 'admin') {
      conditions.push('role = ?');
      params.push(role);
    }
    if (search) {
      conditions.push('(name LIKE ? OR email LIKE ?)');
      const term = `%${search}%`;
      params.push(term, term);
    }

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const safeLimit = Math.min(Math.max(Number.parseInt(limit, 10) || 20, 1), 100);
    const safeOffset = Math.max(Number.parseInt(offset, 10) || 0, 0);

    const [countRows] = await pool.execute(
      `SELECT COUNT(*) AS total FROM users ${whereClause}`,
      params
    );

    const [rows] = await pool.query(
      `SELECT id, name, email, role, mfa_enabled, created_at, updated_at
       FROM users ${whereClause}
       ORDER BY created_at DESC, id DESC
       LIMIT ? OFFSET ?`,
      [...params, safeLimit, safeOffset]
    );

    return {
      users: rows,
      total: Number(countRows[0]?.total || 0)
    };
  }

  async function getStats() {
    const [rows] = await pool.execute(
      `SELECT
         COUNT(*) AS totalUsers,
         SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) AS adminCount,
         SUM(CASE WHEN role = 'user' THEN 1 ELSE 0 END) AS userCount
       FROM users`
    );
    return {
      totalUsers: Number(rows[0]?.totalUsers || 0),
      adminCount: Number(rows[0]?.adminCount || 0),
      userCount: Number(rows[0]?.userCount || 0)
    };
  }

  async function listUsersNeedingKeyRotation(activeKeyVersion) {
    const [rows] = await pool.execute(
      `SELECT id, encrypted_phone, phone_key_version, mfa_secret_encrypted
       FROM users
       WHERE (encrypted_phone IS NOT NULL AND phone_key_version <> ?)
          OR mfa_secret_encrypted IS NOT NULL`,
      [activeKeyVersion]
    );
    return rows;
  }

  return {
    findByEmailForAuth,
    findById,
    findCredentialsById,
    createUserWithEncryptedPhone,
    createAdminSeedUser,
    updateProfile,
    updateEncryptedPhone,
    updatePasswordAndBumpSessionVersion,
    updateRoleWithAudit,
    setMfaConfig,
    updateMfaRecoveryHashes,
    listUsers,
    getStats,
    listUsersNeedingKeyRotation
  };
}
