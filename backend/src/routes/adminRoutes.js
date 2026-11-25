import { Router } from 'express';
import { validateRequest } from '../middlewares/validateRequest.js';
import {
  userIdParamSchema,
  updateRoleSchema,
  listUsersQuerySchema,
  listEventsQuerySchema
} from '../validators/adminValidators.js';

export function createAdminRoutes({
  adminController,
  authenticateUser,
  requireAdmin,
  csrfProtection
}) {
  const router = Router();

  router.use(authenticateUser, requireAdmin);

  router.get('/stats', adminController.getStats);

  router.get(
    '/users',
    validateRequest({ query: listUsersQuerySchema }),
    adminController.listUsers
  );

  router.patch(
    '/users/:id/role',
    csrfProtection,
    validateRequest({ params: userIdParamSchema, body: updateRoleSchema }),
    adminController.updateUserRole
  );

  router.get(
    '/events',
    validateRequest({ query: listEventsQuerySchema }),
    adminController.listEvents
  );

  router.post('/crypto/rotate', csrfProtection, adminController.rotateEncryptionKeys);

  return router;
}
