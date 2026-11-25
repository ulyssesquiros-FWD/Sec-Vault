import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../config/env.js';
import { createLogger } from '../config/logger.js';
import { createPool, classifyDatabaseError } from '../config/database.js';
import { createEncryptionService } from '../services/encryptionService.js';
import { createUserRepository } from '../repositories/userRepository.js';
import { createNoteRepository } from '../repositories/noteRepository.js';
import { createSecurityEventRepository } from '../repositories/securityEventRepository.js';
import { createAuditService } from '../services/auditService.js';

const __filename = fileURLToPath(import.meta.url);

/**
 * Job CLI para re-cifrar progresivamente registros cifrados con versiones anteriores
 * hacia `ENCRYPTION_KEY_VERSION` activa sin pérdida de datos.
 */
async function rotateAllKeys() {
  const config = loadConfig();
  const logger = createLogger(config);
  const pool = createPool(config, logger);

  try {
    const encryptionService = createEncryptionService(config.crypto);
    const userRepository = createUserRepository(pool);
    const noteRepository = createNoteRepository(pool);
    const securityEventRepository = createSecurityEventRepository(pool);
    const auditService = createAuditService(securityEventRepository, logger);

    let rotatedUsers = 0;
    let rotatedNotes = 0;

    const users = await userRepository.listUsersNeedingKeyRotation(encryptionService.activeKeyVersion);
    for (const user of users) {
      if (user.encrypted_phone && encryptionService.needsReencryption(user.encrypted_phone)) {
        const aad = `user:${user.id}:phone`;
        const plainPhone = encryptionService.decryptData(user.encrypted_phone, aad);
        const updatedPhone = encryptionService.encryptData(plainPhone, aad);
        await userRepository.updateEncryptedPhone({
          userId: user.id,
          encryptedPhone: updatedPhone,
          phoneKeyVersion: encryptionService.activeKeyVersion
        });
        rotatedUsers += 1;
      }

      if (user.mfa_secret_encrypted && encryptionService.needsReencryption(user.mfa_secret_encrypted)) {
        const aad = `user:${user.id}:mfa`;
        const plainSecret = encryptionService.decryptData(user.mfa_secret_encrypted, aad);
        const updatedSecret = encryptionService.encryptData(plainSecret, aad);
        const recoveryHashes =
          typeof user.mfa_recovery_hashes === 'string'
            ? JSON.parse(user.mfa_recovery_hashes)
            : user.mfa_recovery_hashes;
        await userRepository.setMfaConfig({
          userId: user.id,
          mfaEnabled: true,
          mfaSecretEncrypted: updatedSecret,
          mfaRecoveryHashes: recoveryHashes
        });
      }
    }

    const notes = await noteRepository.listNotesNeedingKeyRotation(encryptionService.activeKeyVersion);
    for (const note of notes) {
      if (encryptionService.needsReencryption(note.encrypted_content)) {
        const aad = `note:${note.id}:owner:${note.owner_id}`;
        const plainContent = encryptionService.decryptData(note.encrypted_content, aad);
        const updatedContent = encryptionService.encryptData(plainContent, aad);
        await noteRepository.updateRotatedContent({
          noteId: note.id,
          ownerId: note.owner_id,
          encryptedContent: updatedContent,
          keyVersion: encryptionService.activeKeyVersion
        });
        rotatedNotes += 1;
      }
    }

    await auditService.recordEvent({
      actorId: null,
      eventType: 'KEY_ROTATION_CLI_COMPLETED',
      severity: 'INFO',
      description: `Rotación CLI completada hacia versión ${encryptionService.activeKeyVersion}`,
      metadata: { rotatedUsers, rotatedNotes, activeKeyVersion: encryptionService.activeKeyVersion }
    });

    console.log(
      JSON.stringify({
        activeKeyVersion: encryptionService.activeKeyVersion,
        rotatedUsers,
        rotatedNotes
      })
    );
  } finally {
    await pool.end();
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMain) {
  rotateAllKeys()
    .then(() => process.exit(0))
    .catch((err) => {
      const classified = classifyDatabaseError(err);
      console.error(
        `Error durante rotación de llaves [${classified.label} | ${classified.code}]: ${classified.message}`
      );
      console.error(`Acción sugerida: ${classified.guidance}`);
      process.exit(1);
    });
}
