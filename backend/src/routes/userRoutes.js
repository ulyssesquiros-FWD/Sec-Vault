import { Router } from 'express';
import { validateRequest } from '../middlewares/validateRequest.js';
import {
  updateProfileSchema,
  changePasswordSchema,
  revealPhoneSchema,
  mfaEnableSchema,
  mfaDisableSchema
} from '../validators/userValidators.js';

export function createUserRoutes({
  userController,
  authenticateUser,
  csrfProtection,
  authLimiter
}) {
  const router = Router();

  router.use(authenticateUser);

  router.get('/me', userController.getProfile);
  router.put('/me', csrfProtection, validateRequest({ body: updateProfileSchema }), userController.updateProfile);

  router.post(
    '/me/reveal-phone',
    authLimiter,
    csrfProtection,
    validateRequest({ body: revealPhoneSchema }),
    userController.revealPhone
  );

  router.put(
    '/me/password',
    authLimiter,
    csrfProtection,
    validateRequest({ body: changePasswordSchema }),
    userController.changePassword
  );

  router.post('/me/mfa/setup', csrfProtection, userController.setupMfa);
  router.post(
    '/me/mfa/enable',
    csrfProtection,
    validateRequest({ body: mfaEnableSchema }),
    userController.enableMfa
  );
  router.post(
    '/me/mfa/disable',
    authLimiter,
    csrfProtection,
    validateRequest({ body: mfaDisableSchema }),
    userController.disableMfa
  );

  return router;
}
