import { extractClientIp } from '../utils/sanitize.js';
import { forbidden } from '../utils/errors.js';

export function createAdminController({
  userRepository,
  noteRepository,
  securityEventRepository,
  encryptionService,
  auditService,
  alertService
}) {
  async function getStats(req, res, next) {
    try {
      const [users, security] = await Promise.all([
        userRepository.getStats(),
        securityEventRepository.getStats()
      ]);

      return res.status(200).json({
        stats: {
          totalUsers: users.totalUsers,
          registeredUsers: users.totalUsers,
          adminCount: users.adminCount,
          normalUserCount: users.userCount,
          totalSecurityEvents: security.totalEvents,
          failedAuthAttempts: security.failedAuthEvents,
          highSeverityEvents: security.highSeverityEvents,
          activeEncryptionKeyVersion: encryptionService.activeKeyVersion
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function listUsers(req, res, next) {
    try {
      const { search, role, page, limit } = req.validated.query;
      const offset = (page - 1) * limit;
      const result = await userRepository.listUsers({ search, role, limit, offset });

      return res.status(200).json({
        users: result.users.map((u) => ({
          id: Number(u.id),
          name: u.name,
          email: u.email,
          role: u.role,
          mfaEnabled: Boolean(u.mfa_enabled),
          createdAt: u.created_at,
          updatedAt: u.updated_at
        })),
        pagination: {
          page,
          limit,
          total: result.total,
          totalPages: Math.max(1, Math.ceil(result.total / limit))
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function updateUserRole(req, res, next) {
    try {
      const targetUserId = req.validated.params.id;
      const { role } = req.validated.body;
      const ip = extractClientIp(req);

      if (Number(targetUserId) === Number(req.user.id)) {
        await alertService.triggerSecurityAlert({
          actorId: req.user.id,
          eventType: 'SELF_ROLE_CHANGE_BLOCKED',
          severity: 'HIGH',
          description: 'Bloqueo de intento de modificar el propio rol administrativo',
          metadata: { targetUserId, attemptedRole: role },
          ipAddress: ip
        });
        return next(forbidden('No puedes modificar tu propio rol.', 'SELF_ROLE_CHANGE_FORBIDDEN'));
      }

      const updated = await userRepository.updateRoleWithAudit({
        targetUserId,
        newRole: role,
        adminId: req.user.id,
        ipAddress: ip
      });

      return res.status(200).json({
        message: 'Rol actualizado correctamente.',
        user: updated
      });
    } catch (err) {
      return next(err);
    }
  }

  async function listSecurityEvents(req, res, next) {
    try {
      const { severity, eventType, search, page, limit } = req.validated.query;
      const offset = (page - 1) * limit;
      const result = await securityEventRepository.list({
        severity,
        eventType,
        search,
        limit,
        offset
      });

      return res.status(200).json({
        events: result.events.map((e) => ({
          id: Number(e.id),
          actorId: e.actor_id ? Number(e.actor_id) : null,
          actorEmail: e.actor_email || null,
          eventType: e.event_type,
          severity: e.severity,
          description: e.description,
          metadata: e.metadata,
          ipAddress: e.ip_address,
          createdAt: e.created_at
        })),
        pagination: {
          page,
          limit,
          total: result.total,
          totalPages: Math.max(1, Math.ceil(result.total / limit))
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function rotateEncryptionKeys(req, res, next) {
    try {
      const ip = extractClientIp(req);
      let rotatedUsers = 0;
      let rotatedNotes = 0;

      const users = await userRepository.listUsersNeedingKeyRotation(encryptionService.activeKeyVersion);
      for (const user of users) {
        if (user.encrypted_phone && encryptionService.needsReencryption(user.encrypted_phone)) {
          const aad = `user:${user.id}:phone`;
          const plain = encryptionService.decryptData(user.encrypted_phone, aad);
          const reencrypted = encryptionService.encryptData(plain, aad);
          await userRepository.updateEncryptedPhone({
            userId: user.id,
            encryptedPhone: reencrypted,
            phoneKeyVersion: encryptionService.activeKeyVersion
          });
          rotatedUsers += 1;
        }
        if (user.mfa_secret_encrypted && encryptionService.needsReencryption(user.mfa_secret_encrypted)) {
          const aad = `user:${user.id}:mfa`;
          const plainSecret = encryptionService.decryptData(user.mfa_secret_encrypted, aad);
          const reencryptedSecret = encryptionService.encryptData(plainSecret, aad);
          const recoveryHashes =
            typeof user.mfa_recovery_hashes === 'string'
              ? JSON.parse(user.mfa_recovery_hashes)
              : user.mfa_recovery_hashes;
          await userRepository.setMfaConfig({
            userId: user.id,
            mfaEnabled: true,
            mfaSecretEncrypted: reencryptedSecret,
            mfaRecoveryHashes: recoveryHashes
          });
        }
      }

      const notes = await noteRepository.listNotesNeedingKeyRotation(encryptionService.activeKeyVersion);
      for (const note of notes) {
        if (encryptionService.needsReencryption(note.encrypted_content)) {
          const aad = `note:${note.id}:owner:${note.owner_id}`;
          const plainContent = encryptionService.decryptData(note.encrypted_content, aad);
          const reencryptedContent = encryptionService.encryptData(plainContent, aad);
          await noteRepository.updateRotatedContent({
            noteId: note.id,
            ownerId: note.owner_id,
            encryptedContent: reencryptedContent,
            keyVersion: encryptionService.activeKeyVersion
          });
          rotatedNotes += 1;
        }
      }

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'KEY_ROTATION_EXECUTED',
        severity: 'INFO',
        description: `Rotación controlada hacia llave ${encryptionService.activeKeyVersion}`,
        metadata: {
          activeKeyVersion: encryptionService.activeKeyVersion,
          rotatedUsers,
          rotatedNotes
        },
        ipAddress: ip
      });

      return res.status(200).json({
        activeKeyVersion: encryptionService.activeKeyVersion,
        rotatedUsers,
        rotatedNotes
      });
    } catch (err) {
      return next(err);
    }
  }

  return {
    getStats,
    listUsers,
    updateUserRole,
    listEvents: listSecurityEvents,
    rotateEncryptionKeys
  };
}
