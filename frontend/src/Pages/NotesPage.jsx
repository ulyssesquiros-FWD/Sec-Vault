import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Edit3, Plus, Search, Trash2 } from 'lucide-react';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { ConfirmModal } from '../Components/ConfirmModal.jsx';
import { SecurityBadge } from '../Components/SecurityBadge.jsx';

export function NotesPage() {
  const [notes, setNotes] = useState([]);
  const [limits, setLimits] = useState({ current: 0, maxNotes: 50 });
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [noteToDelete, setNoteToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const loadNotes = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await apiClient.notes.list();
      setNotes(data.notes || []);
      if (data.limits) setLimits(data.limits);
    } catch (err) {
      setError(err.message || 'No se pudieron cargar tus notas.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadNotes();
  }, [loadNotes]);

  async function confirmDelete() {
    if (!noteToDelete) return;
    setDeleting(true);
    setError('');
    setSuccess('');
    try {
      await apiClient.notes.remove(noteToDelete.id);
      setSuccess(`Nota "${noteToDelete.title}" eliminada de forma permanente.`);
      setNoteToDelete(null);
      await loadNotes();
    } catch (err) {
      setError(err.message || 'No fue posible eliminar la nota.');
    } finally {
      setDeleting(false);
    }
  }

  const filtered = notes.filter((n) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return n.title.toLowerCase().includes(q) || n.content.toLowerCase().includes(q);
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Notas Privadas Cifradas</h1>
          <p className="page-description">
            Uso actual: {limits.current} de {limits.maxNotes} notas permitidas. Solo tú puedes descifrarlas.
          </p>
        </div>
        <Link to="/notes/new" className="btn btn-primary">
          <Plus size={16} />
          <span>Nueva Nota</span>
        </Link>
      </div>

      <AlertBanner type="error" message={error} />
      <AlertBanner type="success" message={success} />

      <div className="toolbar">
        <div className="password-wrap">
          <input
            type="search"
            className="input"
            aria-label="Buscar notas"
            placeholder="Filtrar por título o contenido..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <span className="muted">
          <Search size={14} aria-hidden="true" /> {filtered.length} resultado(s)
        </span>
      </div>

      {loading ? (
        <div className="card">
          <p className="muted">Descifrando bóveda desde MySQL...</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="card">
          <p className="muted">
            {notes.length === 0
              ? 'Tu bóveda está vacía. Crea tu primera nota privada cifrada.'
              : 'No hay notas que coincidan con la búsqueda.'}
          </p>
        </div>
      ) : (
        <div className="notes-grid">
          {filtered.map((note) => (
            <article key={note.id} className="note-card">
              <div>
                <h2 className="note-title">{note.title}</h2>
                <p className="note-preview">{note.content}</p>
              </div>

              <div className="note-meta">
                <SecurityBadge variant="emerald" icon="lock">
                  AES-256-GCM · {note.keyVersion}
                </SecurityBadge>
                <div className="row-actions">
                  <Link to={`/notes/${note.id}/edit`} className="btn btn-secondary btn-sm">
                    <Edit3 size={14} />
                    <span>Editar</span>
                  </Link>
                  <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    onClick={() => setNoteToDelete(note)}
                  >
                    <Trash2 size={14} />
                    <span>Eliminar</span>
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}

      <ConfirmModal
        open={Boolean(noteToDelete)}
        title="Eliminar nota cifrada"
        message={`¿Seguro que deseas eliminar permanentemente la nota "${noteToDelete?.title || ''}"? Esta acción no se puede deshacer.`}
        confirmLabel="Eliminar nota"
        busy={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setNoteToDelete(null)}
      />
    </div>
  );
}
