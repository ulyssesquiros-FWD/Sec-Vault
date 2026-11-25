import { forbidden, notFound, unauthorized } from '../utils/errors.js';
import { extractClientIp } from '../utils/sanitize.js';

/**
 * Middleware anti-IDOR (OWASP A01:2025): verifica que el recurso pertenezca al usuario autenticado.
 * El administrador tampoco tiene acceso automático a notas privadas de otros usuarios.
 */
export function createVerifyNoteOwnership({ noteRepository, alertService }) {
  return async function verifyOwnership(req, res, next) {
    try {
      if (!req.user) {
        return next(unauthorized('No autenticado.', 'UNAUTHENTICATED'));
      }

      const noteId = req.validated?.params?.id ?? Number(req.params.id);
      const record = await noteRepository.findOwnerById(noteId);

      if (!record) {
        return next(notFound('Nota no encontrada.', 'NOTE_NOT_FOUND'));
      }

      if (Number(record.owner_id) !== Number(req.user.id)) {
        await alertService.triggerSecurityAlert({
          actorId: req.user.id,
          eventType: 'IDOR_ATTEMPT',
          severity: 'HIGH',
          description: `Intento de acceso no autorizado (IDOR) a nota #${noteId}`,
          metadata: { targetNoteId: noteId, method: req.method },
          ipAddress: extractClientIp(req)
        });

        return next(forbidden('No tienes autorización para acceder a esta nota.', 'IDOR_FORBIDDEN'));
      }

      return next();
    } catch (err) {
      return next(err);
    }
  };
}
