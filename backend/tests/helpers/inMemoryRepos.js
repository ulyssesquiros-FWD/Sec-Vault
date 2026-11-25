import { AppError } from '../../src/utils/errors.js';
import { MAX_NOTES_PER_USER } from '../../src/repositories/noteRepository.js';

/**
 * Adaptador de repositorios en memoria exclusivo para la suite HTTP aislada
 * cuando no hay un servidor MySQL levantado en el entorno local.
 * Refleja fielmente las restricciones UNIQUE, FK, transacciones, bloqueos y formatos reales.
 */
export function createInMemoryRepositories() {
  let nextUserId = 1;
  let nextNoteId = 1;
  let nextResetId = 1;
  let nextEventId = 1;
  let nextAttemptId = 1;

  const users = new Map();
  const notes = new Map();
  const passwordResets = [];
  const securityEvents = [];
  const loginAttempts = new Map();

  function cloneUser(u) {
    return u ? { ...u } : null;
  }

  const securityEventRepository = {
    async create({
      actorId = null,
      eventType,
      severity = 'INFO',
      description,
      metadata = null,
      ipAddress = null
    }) {
      const id = nextEventId++;
      securityEvents.push({
        id,
        actor_id: actorId ? Number(actorId) : null,
        event_type: eventType,
        severity,
        description,
        metadata: metadata ? structuredClone(metadata) : null,
        ip_address: ipAddress,
        created_at: new Date().toISOString()
      });
      return id;
    },

    async list({ severity = '', eventType = '', search = '', limit = 30, offset = 0 }) {
      const filtered = securityEvents
        .slice()
        .reverse()
        .filter((ev) => {
          if (severity && ev.severity !== severity) return false;
          if (eventType && ev.event_type !== eventType) return false;
          if (search) {
            const q = search.toLowerCase();
            const actor = ev.actor_id ? users.get(ev.actor_id) : null;
            const hay =
              ev.description.toLowerCase().includes(q) ||
              ev.event_type.toLowerCase().includes(q) ||
              (actor?.email || '').toLowerCase().includes(q);
            if (!hay) return false;
          }
          return true;
        });

      const slice = filtered.slice(offset, offset + limit).map((ev) => ({
        ...ev,
        actor_email: ev.actor_id ? users.get(ev.actor_id)?.email || null : null
      }));

      return { events: slice, total: filtered.length };
    },

    async getStats() {
      return {
        totalEvents: securityEvents.length,
        failedAuthEvents: securityEvents.filter(
          (e) => e.event_type === 'LOGIN_FAILED' || e.event_type === 'MFA_FAILED'
        ).length,
        highSeverityEvents: securityEvents.filter(
          (e) => e.severity === 'HIGH' || e.severity === 'CRITICAL'
        ).length
      };
    }
  };

  const userRepository = {
    async findByEmailForAuth(emailNormalized) {
      for (const user of users.values()) {
        if (user.email === emailNormalized) return cloneUser(user);
      }
      return null;
    },

    async findById(userId) {
      return cloneUser(users.get(Number(userId)));
    },

    async findCredentialsById(userId) {
      return cloneUser(users.get(Number(userId)));
    },

    async createUserWithEncryptedPhone({ name, emailNormalized, passwordHash, phone, encryptionService }) {
      for (const existing of users.values()) {
        if (existing.email === emailNormalized) {
          throw new AppError('No fue posible completar el registro con ese correo.', 409, 'EMAIL_ALREADY_EXISTS');
        }
      }

      const id = nextUserId++;
      const now = new Date().toISOString();
      const encryptedPhone = encryptionService.encryptData(phone, `user:${id}:phone`);

      const record = {
        id,
        name,
        email: emailNormalized,
        password_hash: passwordHash,
        role: 'user',
        encrypted_phone: encryptedPhone,
        phone_key_version: encryptionService.activeKeyVersion,
        session_version: 1,
        mfa_enabled: 0,
        mfa_secret_encrypted: null,
        mfa_recovery_hashes: null,
        created_at: now,
        updated_at: now
      };
      users.set(id, record);
      await securityEventRepository.create({
        actorId: id,
        eventType: 'USER_REGISTERED',
        severity: 'INFO',
        description: 'Nuevo usuario registrado en SecureVault',
        metadata: { role: 'user' }
      });
      return cloneUser(record);
    },

    async createAdminSeedUser({ name, emailNormalized, passwordHash, phone, encryptionService }) {
      for (const existing of users.values()) {
        if (existing.email === emailNormalized) {
          return { created: false, id: existing.id };
        }
      }
      const id = nextUserId++;
      const now = new Date().toISOString();
      const encryptedPhone = encryptionService.encryptData(phone, `user:${id}:phone`);
      users.set(id, {
        id,
        name,
        email: emailNormalized,
        password_hash: passwordHash,
        role: 'admin',
        encrypted_phone: encryptedPhone,
        phone_key_version: encryptionService.activeKeyVersion,
        session_version: 1,
        mfa_enabled: 0,
        mfa_secret_encrypted: null,
        mfa_recovery_hashes: null,
        created_at: now,
        updated_at: now
      });
      return { created: true, id };
    },

    async updateProfile({ userId, name, encryptedPhone, phoneKeyVersion }) {
      const user = users.get(Number(userId));
      if (!user) return null;
      user.name = name;
      user.encrypted_phone = encryptedPhone;
      user.phone_key_version = phoneKeyVersion;
      user.updated_at = new Date().toISOString();
      return cloneUser(user);
    },

    async updateEncryptedPhone({ userId, encryptedPhone, phoneKeyVersion }) {
      const user = users.get(Number(userId));
      if (user) {
        user.encrypted_phone = encryptedPhone;
        user.phone_key_version = phoneKeyVersion;
      }
    },

    async updatePasswordAndBumpSessionVersion({ userId, newPasswordHash }) {
      const user = users.get(Number(userId));
      if (user) {
        user.password_hash = newPasswordHash;
        user.session_version += 1;
        user.updated_at = new Date().toISOString();
      }
    },

    async updateRoleWithAudit({ targetUserId, newRole, adminId, ipAddress }) {
      const target = users.get(Number(targetUserId));
      if (!target) throw new AppError('Usuario no encontrado.', 404, 'USER_NOT_FOUND');
      const previousRole = target.role;
      target.role = newRole;
      target.session_version += 1;
      target.updated_at = new Date().toISOString();

      await securityEventRepository.create({
        actorId: adminId,
        eventType: 'ROLE_CHANGED',
        severity: 'HIGH',
        description: `Cambio de rol para usuario #${target.id}: ${previousRole} -> ${newRole}`,
        metadata: { targetUserId: target.id, previousRole, newRole },
        ipAddress
      });

      return { id: target.id, previousRole, role: newRole };
    },

    async setMfaConfig({ userId, mfaEnabled, mfaSecretEncrypted, mfaRecoveryHashes }) {
      const user = users.get(Number(userId));
      if (user) {
        user.mfa_enabled = mfaEnabled ? 1 : 0;
        user.mfa_secret_encrypted = mfaSecretEncrypted;
        user.mfa_recovery_hashes = mfaRecoveryHashes ? [...mfaRecoveryHashes] : null;
      }
    },

    async updateMfaRecoveryHashes({ userId, mfaRecoveryHashes }) {
      const user = users.get(Number(userId));
      if (user) {
        user.mfa_recovery_hashes = [...mfaRecoveryHashes];
      }
    },

    async listUsers({ search = '', role = '', limit = 20, offset = 0 }) {
      const filtered = Array.from(users.values())
        .filter((u) => {
          if (role && u.role !== role) return false;
          if (search) {
            const q = search.toLowerCase();
            if (!u.name.toLowerCase().includes(q) && !u.email.toLowerCase().includes(q)) return false;
          }
          return true;
        })
        .reverse();

      return {
        users: filtered.slice(offset, offset + limit).map((u) => ({
          id: u.id,
          name: u.name,
          email: u.email,
          role: u.role,
          mfa_enabled: u.mfa_enabled,
          created_at: u.created_at,
          updated_at: u.updated_at
        })),
        total: filtered.length
      };
    },

    async getStats() {
      const all = Array.from(users.values());
      return {
        totalUsers: all.length,
        adminCount: all.filter((u) => u.role === 'admin').length,
        userCount: all.filter((u) => u.role === 'user').length
      };
    },

    async listUsersNeedingKeyRotation(activeKeyVersion) {
      return Array.from(users.values())
        .filter(
          (u) =>
            (u.encrypted_phone && u.phone_key_version !== activeKeyVersion) ||
            Boolean(u.mfa_secret_encrypted)
        )
        .map(cloneUser);
    }
  };

  const noteRepository = {
    async findAllByOwner(ownerId) {
      return Array.from(notes.values())
        .filter((n) => n.owner_id === Number(ownerId))
        .reverse()
        .map((n) => ({ ...n }));
    },

    async findByIdAndOwner(noteId, ownerId) {
      const n = notes.get(Number(noteId));
      if (!n || n.owner_id !== Number(ownerId)) return null;
      return { ...n };
    },

    async findOwnerById(noteId) {
      const n = notes.get(Number(noteId));
      return n ? { id: n.id, owner_id: n.owner_id } : null;
    },

    async createNote({ ownerId, title, content, encryptionService }) {
      const count = Array.from(notes.values()).filter((n) => n.owner_id === Number(ownerId)).length;
      if (count >= MAX_NOTES_PER_USER) {
        throw new AppError(
          `Has alcanzado el límite máximo de ${MAX_NOTES_PER_USER} notas privadas.`,
          400,
          'NOTE_LIMIT_REACHED'
        );
      }

      const id = nextNoteId++;
      const now = new Date().toISOString();
      const encryptedContent = encryptionService.encryptData(content, `note:${id}:owner:${Number(ownerId)}`);
      const record = {
        id,
        owner_id: Number(ownerId),
        title,
        encrypted_content: encryptedContent,
        key_version: encryptionService.activeKeyVersion,
        created_at: now,
        updated_at: now
      };
      notes.set(id, record);
      return { ...record };
    },

    async updateNote({ noteId, ownerId, title, encryptedContent, keyVersion }) {
      const n = notes.get(Number(noteId));
      if (!n || n.owner_id !== Number(ownerId)) return null;
      n.title = title;
      n.encrypted_content = encryptedContent;
      n.key_version = keyVersion;
      n.updated_at = new Date().toISOString();
      return { ...n };
    },

    async deleteNote({ noteId, ownerId }) {
      const n = notes.get(Number(noteId));
      if (!n || n.owner_id !== Number(ownerId)) return false;
      notes.delete(Number(noteId));
      return true;
    },

    async listNotesNeedingKeyRotation(activeKeyVersion) {
      return Array.from(notes.values())
        .filter((n) => n.key_version !== activeKeyVersion)
        .map((n) => ({ ...n }));
    },

    async updateRotatedContent({ noteId, ownerId, encryptedContent, keyVersion }) {
      const n = notes.get(Number(noteId));
      if (n && n.owner_id === Number(ownerId)) {
        n.encrypted_content = encryptedContent;
        n.key_version = keyVersion;
      }
    }
  };

  const passwordResetRepository = {
    async createResetToken({ userId, tokenHash, expiresAt }) {
      for (const r of passwordResets) {
        if (r.user_id === Number(userId) && r.used_at === null) {
          r.used_at = new Date();
        }
      }
      passwordResets.push({
        id: nextResetId++,
        user_id: Number(userId),
        token_hash: tokenHash,
        expires_at: expiresAt,
        used_at: null,
        created_at: new Date()
      });
    },

    async consumeTokenAndResetPassword({ tokenHash, newPasswordHash, ipAddress }) {
      const record = passwordResets.find((r) => r.token_hash === tokenHash);
      if (!record) {
        throw new AppError('El token de recuperación es inválido o ha expirado.', 400, 'INVALID_RESET_TOKEN');
      }
      if (record.used_at !== null) {
        throw new AppError('Este enlace de recuperación ya fue utilizado.', 400, 'RESET_TOKEN_ALREADY_USED');
      }
      if (new Date(record.expires_at).getTime() <= Date.now()) {
        throw new AppError('El token de recuperación ha expirado.', 400, 'RESET_TOKEN_EXPIRED');
      }

      record.used_at = new Date();
      const user = users.get(record.user_id);
      if (user) {
        user.password_hash = newPasswordHash;
        user.session_version += 1;
      }

      await securityEventRepository.create({
        actorId: record.user_id,
        eventType: 'PASSWORD_RESET_COMPLETED',
        severity: 'INFO',
        description: 'Contraseña restablecida mediante token seguro de un solo uso',
        metadata: { sessionsInvalidated: true },
        ipAddress
      });

      return { userId: record.user_id };
    }
  };

  const loginAttemptRepository = {
    async getByEmail(emailNormalized) {
      return loginAttempts.get(emailNormalized) || null;
    },

    async recordFailure(emailNormalized, ipAddress) {
      const current = loginAttempts.get(emailNormalized);
      const attempts = (current ? current.attempts : 0) + 1;
      const lockSeconds = attempts >= 10 ? 900 : attempts >= 8 ? 300 : attempts >= 5 ? 60 : 0;
      const lockedUntil = lockSeconds > 0 ? new Date(Date.now() + lockSeconds * 1000) : null;

      loginAttempts.set(emailNormalized, {
        id: current?.id || nextAttemptId++,
        email_normalized: emailNormalized,
        attempts,
        locked_until: lockedUntil,
        last_ip: ipAddress,
        updated_at: new Date()
      });

      return { attempts, lockSeconds, lockedUntil };
    },

    async reset(emailNormalized) {
      loginAttempts.delete(emailNormalized);
    }
  };

  return {
    repositories: {
      userRepository,
      noteRepository,
      passwordResetRepository,
      securityEventRepository,
      loginAttemptRepository
    },
    inspect: {
      users,
      notes,
      passwordResets,
      securityEvents,
      loginAttempts
    }
  };
}
