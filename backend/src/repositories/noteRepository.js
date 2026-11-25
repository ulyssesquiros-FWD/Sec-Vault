import { withTransaction } from '../config/database.js';
import { AppError } from '../utils/errors.js';

export const MAX_NOTES_PER_USER = 50;

/**
 * Repositorio MySQL para notas privadas cifradas.
 * Toda consulta enlaza explícitamente `owner_id = ?` para defensa en profundidad anti-IDOR.
 */
export function createNoteRepository(pool) {
  async function findAllByOwner(ownerId) {
    const [rows] = await pool.execute(
      `SELECT id, owner_id, title, encrypted_content, key_version, created_at, updated_at
       FROM notes
       WHERE owner_id = ?
       ORDER BY updated_at DESC, id DESC`,
      [Number(ownerId)]
    );
    return rows;
  }

  async function findByIdAndOwner(noteId, ownerId) {
    const [rows] = await pool.execute(
      `SELECT id, owner_id, title, encrypted_content, key_version, created_at, updated_at
       FROM notes
       WHERE id = ? AND owner_id = ?
       LIMIT 1`,
      [Number(noteId), Number(ownerId)]
    );
    return rows[0] || null;
  }

  async function findOwnerById(noteId) {
    const [rows] = await pool.execute(
      'SELECT id, owner_id FROM notes WHERE id = ? LIMIT 1',
      [Number(noteId)]
    );
    return rows[0] || null;
  }

  async function createNote({ ownerId, title, content, encryptionService }) {
    return withTransaction(pool, async (conn) => {
      const [countRows] = await conn.execute(
        'SELECT COUNT(*) AS total FROM notes WHERE owner_id = ? FOR UPDATE',
        [Number(ownerId)]
      );
      if (Number(countRows[0]?.total || 0) >= MAX_NOTES_PER_USER) {
        throw new AppError(
          `Has alcanzado el límite máximo de ${MAX_NOTES_PER_USER} notas privadas.`,
          400,
          'NOTE_LIMIT_REACHED'
        );
      }

      const [insertResult] = await conn.execute(
        `INSERT INTO notes (owner_id, title, encrypted_content, key_version)
         VALUES (?, ?, '', ?)`,
        [Number(ownerId), title, encryptionService.activeKeyVersion]
      );

      const noteId = Number(insertResult.insertId);
      const encryptedContent = encryptionService.encryptData(
        content,
        `note:${noteId}:owner:${Number(ownerId)}`
      );

      await conn.execute(
        'UPDATE notes SET encrypted_content = ?, key_version = ? WHERE id = ? AND owner_id = ?',
        [encryptedContent, encryptionService.activeKeyVersion, noteId, Number(ownerId)]
      );

      const [rows] = await conn.execute(
        `SELECT id, owner_id, title, encrypted_content, key_version, created_at, updated_at
         FROM notes
         WHERE id = ? AND owner_id = ?
         LIMIT 1`,
        [noteId, Number(ownerId)]
      );

      return rows[0];
    });
  }

  async function updateNote({ noteId, ownerId, title, encryptedContent, keyVersion }) {
    const [result] = await pool.execute(
      `UPDATE notes
       SET title = ?, encrypted_content = ?, key_version = ?
       WHERE id = ? AND owner_id = ?`,
      [title, encryptedContent, keyVersion, Number(noteId), Number(ownerId)]
    );
    if (result.affectedRows === 0) {
      return null;
    }
    return findByIdAndOwner(noteId, ownerId);
  }

  async function deleteNote({ noteId, ownerId }) {
    const [result] = await pool.execute(
      'DELETE FROM notes WHERE id = ? AND owner_id = ?',
      [Number(noteId), Number(ownerId)]
    );
    return result.affectedRows > 0;
  }

  async function listNotesNeedingKeyRotation(activeKeyVersion) {
    const [rows] = await pool.execute(
      `SELECT id, owner_id, encrypted_content, key_version
       FROM notes
       WHERE key_version <> ?`,
      [activeKeyVersion]
    );
    return rows;
  }

  async function updateRotatedContent({ noteId, ownerId, encryptedContent, keyVersion }) {
    await pool.execute(
      `UPDATE notes SET encrypted_content = ?, key_version = ? WHERE id = ? AND owner_id = ?`,
      [encryptedContent, keyVersion, Number(noteId), Number(ownerId)]
    );
  }

  return {
    findAllByOwner,
    findByIdAndOwner,
    findOwnerById,
    createNote,
    updateNote,
    deleteNote,
    listNotesNeedingKeyRotation,
    updateRotatedContent
  };
}
