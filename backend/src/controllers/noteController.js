import { MAX_NOTES_PER_USER } from '../repositories/noteRepository.js';
import { extractClientIp } from '../utils/sanitize.js';
import { notFound } from '../utils/errors.js';

export function createNoteController({
  noteRepository,
  encryptionService,
  auditService
}) {
  async function decryptAndMaybeRotate(row, ownerId) {
    const aad = `note:${row.id}:owner:${ownerId}`;
    const content = encryptionService.decryptData(row.encrypted_content, aad);

    if (encryptionService.needsReencryption(row.encrypted_content)) {
      const rotated = encryptionService.encryptData(content, aad);
      await noteRepository.updateRotatedContent({
        noteId: row.id,
        ownerId,
        encryptedContent: rotated,
        keyVersion: encryptionService.activeKeyVersion
      });
    }

    return {
      id: Number(row.id),
      title: row.title,
      content,
      keyVersion: encryptionService.needsReencryption(row.encrypted_content)
        ? encryptionService.activeKeyVersion
        : row.key_version,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async function listNotes(req, res, next) {
    try {
      const rows = await noteRepository.findAllByOwner(req.user.id);
      const notes = [];
      for (const row of rows) {
        notes.push(await decryptAndMaybeRotate(row, req.user.id));
      }

      return res.status(200).json({
        notes,
        limits: {
          current: notes.length,
          maxNotes: MAX_NOTES_PER_USER
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function getNote(req, res, next) {
    try {
      const noteId = req.validated.params.id;
      const row = await noteRepository.findByIdAndOwner(noteId, req.user.id);
      if (!row) {
        return next(notFound('Nota no encontrada.', 'NOTE_NOT_FOUND'));
      }

      const note = await decryptAndMaybeRotate(row, req.user.id);
      return res.status(200).json({ note });
    } catch (err) {
      return next(err);
    }
  }

  async function createNote(req, res, next) {
    try {
      const { title, content } = req.validated.body;
      const ip = extractClientIp(req);

      const created = await noteRepository.createNote({
        ownerId: req.user.id,
        title,
        content,
        encryptionService
      });

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'NOTE_CREATED',
        severity: 'INFO',
        description: `Nota privada #${created.id} creada y cifrada con AES-256-GCM`,
        metadata: { noteId: Number(created.id), keyVersion: created.key_version },
        ipAddress: ip
      });

      return res.status(201).json({
        note: {
          id: Number(created.id),
          title: created.title,
          content,
          keyVersion: created.key_version,
          createdAt: created.created_at,
          updatedAt: created.updated_at
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function updateNote(req, res, next) {
    try {
      const noteId = req.validated.params.id;
      const { title, content } = req.validated.body;
      const ip = extractClientIp(req);

      const encryptedContent = encryptionService.encryptData(
        content,
        `note:${noteId}:owner:${req.user.id}`
      );

      const updated = await noteRepository.updateNote({
        noteId,
        ownerId: req.user.id,
        title,
        encryptedContent,
        keyVersion: encryptionService.activeKeyVersion
      });

      if (!updated) {
        return next(notFound('Nota no encontrada.', 'NOTE_NOT_FOUND'));
      }

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'NOTE_UPDATED',
        severity: 'INFO',
        description: `Nota privada #${noteId} actualizada y re-cifrada`,
        metadata: { noteId, keyVersion: encryptionService.activeKeyVersion },
        ipAddress: ip
      });

      return res.status(200).json({
        note: {
          id: Number(updated.id),
          title: updated.title,
          content,
          keyVersion: updated.key_version,
          createdAt: updated.created_at,
          updatedAt: updated.updated_at
        }
      });
    } catch (err) {
      return next(err);
    }
  }

  async function deleteNote(req, res, next) {
    try {
      const noteId = req.validated.params.id;
      const ip = extractClientIp(req);

      const deleted = await noteRepository.deleteNote({
        noteId,
        ownerId: req.user.id
      });

      if (!deleted) {
        return next(notFound('Nota no encontrada.', 'NOTE_NOT_FOUND'));
      }

      await auditService.recordEvent({
        actorId: req.user.id,
        eventType: 'NOTE_DELETED',
        severity: 'INFO',
        description: `Nota privada #${noteId} eliminada`,
        metadata: { noteId },
        ipAddress: ip
      });

      return res.status(200).json({ message: 'Nota eliminada correctamente.' });
    } catch (err) {
      return next(err);
    }
  }

  return {
    listNotes,
    getNote,
    createNote,
    updateNote,
    deleteNote
  };
}
