import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createSecurityMiddlewares } from './config/security.js';
import { createEncryptionService } from './services/encryptionService.js';
import { createEmailService } from './services/emailService.js';
import { createAuditService } from './services/auditService.js';
import { createAlertService } from './services/alertService.js';
import { createUserRepository } from './repositories/userRepository.js';
import { createNoteRepository } from './repositories/noteRepository.js';
import { createPasswordResetRepository } from './repositories/passwordResetRepository.js';
import { createSecurityEventRepository } from './repositories/securityEventRepository.js';
import { createLoginAttemptRepository } from './repositories/loginAttemptRepository.js';
import { createAuthenticateUser } from './middlewares/authenticateUser.js';
import { createAuthorizeRole } from './middlewares/authorizeRole.js';
import { createVerifyNoteOwnership } from './middlewares/verifyOwnership.js';
import { createCsrfProtection } from './middlewares/csrfProtection.js';
import { createRateLimiters } from './middlewares/rateLimiter.js';
import { createErrorHandler } from './middlewares/errorHandler.js';
import { createAuthController } from './controllers/authController.js';
import { createPasswordController } from './controllers/passwordController.js';
import { createUserController } from './controllers/userController.js';
import { createNoteController } from './controllers/noteController.js';
import { createAdminController } from './controllers/adminController.js';
import { createHealthRoutes } from './routes/healthRoutes.js';
import { createAuthRoutes } from './routes/authRoutes.js';
import { createUserRoutes } from './routes/userRoutes.js';
import { createNoteRoutes } from './routes/noteRoutes.js';
import { createAdminRoutes } from './routes/adminRoutes.js';
import { notFound } from './utils/errors.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_FRONTEND_DIST = path.resolve(__dirname, '../../frontend/dist');

/**
 * Ensambla la aplicación Express de SecureVault con inyección de dependencias opcional
 * para permitir pruebas automatizadas rigurosas sin alterar el flujo real de seguridad.
 */
export function createApp({
  config,
  logger,
  pool = null,
  sessionMiddleware,
  repositories = null,
  emailTransporter = null,
  fetchImpl = globalThis.fetch,
  rateLimitOverrides = {},
  frontendDistPath = DEFAULT_FRONTEND_DIST
}) {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  const { helmetMiddleware, permissionsPolicyMiddleware, corsMiddleware } = createSecurityMiddlewares(config);
  app.use(helmetMiddleware);
  app.use(permissionsPolicyMiddleware);
  app.use(corsMiddleware);

  // Límite estricto de payload JSON (OWASP A06 / A10)
  app.use(express.json({ limit: '64kb' }));

  const userRepository = repositories?.userRepository || createUserRepository(pool);
  const noteRepository = repositories?.noteRepository || createNoteRepository(pool);
  const passwordResetRepository =
    repositories?.passwordResetRepository || createPasswordResetRepository(pool);
  const securityEventRepository =
    repositories?.securityEventRepository || createSecurityEventRepository(pool);
  const loginAttemptRepository =
    repositories?.loginAttemptRepository || createLoginAttemptRepository(pool);

  const encryptionService = createEncryptionService(config.crypto);
  const emailService = createEmailService(config, logger, emailTransporter);
  const auditService = createAuditService(securityEventRepository, logger);
  const alertService = createAlertService(config, auditService, emailService, logger, fetchImpl);

  const rateLimiters = createRateLimiters(rateLimitOverrides);
  const authenticateUser = createAuthenticateUser({ userRepository, config });
  const { requireAdmin } = createAuthorizeRole({ auditService });
  const verifyOwnership = createVerifyNoteOwnership({ noteRepository, alertService });
  const csrfProtection = createCsrfProtection({ auditService });

  const authController = createAuthController({
    config,
    userRepository,
    loginAttemptRepository,
    encryptionService,
    auditService,
    alertService
  });

  const passwordController = createPasswordController({
    config,
    userRepository,
    passwordResetRepository,
    emailService,
    auditService
  });

  const userController = createUserController({
    config,
    userRepository,
    encryptionService,
    auditService
  });

  const noteController = createNoteController({
    noteRepository,
    encryptionService,
    auditService
  });

  const adminController = createAdminController({
    userRepository,
    noteRepository,
    securityEventRepository,
    encryptionService,
    auditService,
    alertService
  });

  // Endpoint de salud sin exposición de datos sensibles ni limitador agresivo
  app.use('/', createHealthRoutes());

  app.use('/api', rateLimiters.globalLimiter);
  app.use(sessionMiddleware);

  app.use(
    '/api/auth',
    createAuthRoutes({
      authController,
      passwordController,
      authenticateUser,
      csrfProtection,
      authLimiter: rateLimiters.authLimiter,
      passwordResetLimiter: rateLimiters.passwordResetLimiter
    })
  );

  app.use(
    '/api/users',
    createUserRoutes({
      userController,
      authenticateUser,
      csrfProtection,
      authLimiter: rateLimiters.authLimiter
    })
  );

  app.use(
    '/api/notes',
    createNoteRoutes({
      noteController,
      authenticateUser,
      verifyOwnership,
      csrfProtection,
      noteWriteLimiter: rateLimiters.noteWriteLimiter
    })
  );

  app.use(
    '/api/admin',
    createAdminRoutes({
      adminController,
      authenticateUser,
      requireAdmin,
      csrfProtection
    })
  );

  app.use('/api', (req, res, next) => {
    next(notFound('Endpoint no encontrado.', 'ROUTE_NOT_FOUND'));
  });

  // Servir build estático de React + Vite en producción / mismo origen (compatible Express 5)
  if (fs.existsSync(frontendDistPath)) {
    app.use(express.static(frontendDistPath, { index: 'index.html', maxAge: '1h' }));
    app.use((req, res, next) => {
      if (req.method !== 'GET' || req.path.startsWith('/api/') || req.path === '/health') {
        return next();
      }
      return res.sendFile(path.join(frontendDistPath, 'index.html'));
    });
  }

  app.use(createErrorHandler(logger));

  return {
    app,
    services: {
      encryptionService,
      auditService,
      alertService,
      emailService
    }
  };
}
