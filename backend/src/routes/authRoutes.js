import { Router } from 'express';
import { validateRequest } from '../middlewares/validateRequest.js';
import { requireJsonContentType } from '../middlewares/csrfProtection.js';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  mfaVerifySchema
} from '../validators/authValidators.js';

export function createAuthRoutes({
  authController,
  passwordController,
  authenticateUser,
  csrfProtection,
  authLimiter,
  passwordResetLimiter
}) {
  const router = Router();

  router.post(
    '/register',
    authLimiter,
    requireJsonContentType,
    validateRequest({ body: registerSchema }),
    authController.register
  );

  router.post(
    '/login',
    authLimiter,
    requireJsonContentType,
    validateRequest({ body: loginSchema }),
    authController.login
  );

  router.post(
    '/mfa/verify',
    authLimiter,
    csrfProtection,
    validateRequest({ body: mfaVerifySchema }),
    authController.verifyMfa
  );

  router.post('/logout', csrfProtection, authController.logout);

  router.get('/me', authenticateUser, authController.me);

  router.post(
    '/forgot-password',
    passwordResetLimiter,
    requireJsonContentType,
    validateRequest({ body: forgotPasswordSchema }),
    passwordController.forgotPassword
  );

  router.post(
    '/reset-password',
    passwordResetLimiter,
    requireJsonContentType,
    validateRequest({ body: resetPasswordSchema }),
    passwordController.resetPassword
  );

  return router;
}
