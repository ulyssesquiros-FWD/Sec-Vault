import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../config/env.js';
import { createLogger } from '../config/logger.js';
import { createPool } from '../config/database.js';
import { createEncryptionService } from '../services/encryptionService.js';
import { hashPassword } from '../services/passwordService.js';
import { createUserRepository } from '../repositories/userRepository.js';
import { normalizeEmail } from '../utils/sanitize.js';

const __filename = fileURLToPath(import.meta.url);

async function runSeed() {
  const config = loadConfig();
  const logger = createLogger(config);

  const adminEmail = normalizeEmail(process.env.SEED_ADMIN_EMAIL || '');
  const adminPassword = process.env.SEED_ADMIN_PASSWORD || '';
  const adminName = (process.env.SEED_ADMIN_NAME || 'Administrador SecureVault').trim();
  const adminPhone = (process.env.SEED_ADMIN_PHONE || '+50688000000').trim();

  if (!adminEmail || !adminPassword) {
    throw new Error(
      'Define SEED_ADMIN_EMAIL y SEED_ADMIN_PASSWORD en variables de entorno para inicializar el administrador.'
    );
  }
  if (adminPassword.length < 12) {
    throw new Error('SEED_ADMIN_PASSWORD debe tener al menos 12 caracteres.');
  }

  const pool = createPool(config, logger);
  try {
    const encryptionService = createEncryptionService(config.crypto);
    const userRepository = createUserRepository(pool);
    const passwordHash = await hashPassword(adminPassword, config.crypto.bcryptRounds);

    const result = await userRepository.createAdminSeedUser({
      name: adminName,
      emailNormalized: adminEmail,
      passwordHash,
      phone: adminPhone,
      encryptionService
    });

    if (result.created) {
      logger.info({ adminId: result.id }, 'Administrador inicial creado correctamente');
    } else {
      logger.info({ adminId: result.id }, 'El administrador inicial ya existía en MySQL');
    }
  } finally {
    await pool.end();
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMain) {
  runSeed()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Error en seed:', err.message);
      process.exit(1);
    });
}
