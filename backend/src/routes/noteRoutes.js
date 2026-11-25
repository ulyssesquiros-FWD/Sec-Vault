import { Router } from 'express';
import { validateRequest } from '../middlewares/validateRequest.js';
import { noteIdParamSchema, noteBodySchema } from '../validators/noteValidators.js';

export function createNoteRoutes({
  noteController,
  authenticateUser,
  verifyOwnership,
  csrfProtection,
  noteWriteLimiter
}) {
  const router = Router();

  router.use(authenticateUser);

  router.get('/', noteController.listNotes);

  router.post(
    '/',
    noteWriteLimiter,
    csrfProtection,
    validateRequest({ body: noteBodySchema }),
    noteController.createNote
  );

  router.get(
    '/:id',
    validateRequest({ params: noteIdParamSchema }),
    verifyOwnership,
    noteController.getNote
  );

  router.put(
    '/:id',
    noteWriteLimiter,
    csrfProtection,
    validateRequest({ params: noteIdParamSchema, body: noteBodySchema }),
    verifyOwnership,
    noteController.updateNote
  );

  router.delete(
    '/:id',
    noteWriteLimiter,
    csrfProtection,
    validateRequest({ params: noteIdParamSchema }),
    verifyOwnership,
    noteController.deleteNote
  );

  return router;
}
