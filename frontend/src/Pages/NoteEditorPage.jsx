import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Save } from 'lucide-react';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';

const MAX_CONTENT = 20000;

export function NoteEditorPage() {
  const { id } = useParams();
  const isEditing = Boolean(id);
  const navigate = useNavigate();

  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(isEditing);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isEditing) return;
    let active = true;
    setLoading(true);
    apiClient.notes
      .get(id)
      .then((res) => {
        if (!active) return;
        setTitle(res.note.title);
        setContent(res.note.content);
      })
      .catch((err) => {
        if (active) setError(err.message || 'No fue posible cargar la nota.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [id, isEditing]);

  async function handleSubmit(event) {
    event.preventDefault();
    setError('');

    if (!title.trim() || !content.trim()) {
      setError('El título y el contenido son obligatorios.');
      return;
    }

    setSaving(true);
    try {
      if (isEditing) {
        await apiClient.notes.update(id, { title: title.trim(), content });
      } else {
        await apiClient.notes.create({ title: title.trim(), content });
      }
      navigate('/notes', { replace: true });
    } catch (err) {
      setError(err.message || 'No fue posible guardar la nota cifrada.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">{isEditing ? 'Editar Nota Cifrada' : 'Crear Nueva Nota Cifrada'}</h1>
          <p className="page-description">
            El contenido se cifra con AES-256-GCM antes de almacenarse en MySQL.
          </p>
        </div>
        <Link to="/notes" className="btn btn-secondary">
          <ArrowLeft size={16} />
          <span>Volver a notas</span>
        </Link>
      </div>

      <AlertBanner type="error" message={error} />

      <section className="card">
        {loading ? (
          <p className="muted">Descifrando nota...</p>
        ) : (
          <form className="form-stack" onSubmit={handleSubmit} noValidate>
            <div className="form-group">
              <label className="form-label" htmlFor="note-title">
                Título (máx. 150 caracteres)
              </label>
              <input
                id="note-title"
                type="text"
                className="input"
                maxLength={150}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Ej. Credenciales servidor respaldo"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="note-content">
                Contenido privado ({content.length} / {MAX_CONTENT} caracteres)
              </label>
              <textarea
                id="note-content"
                className="textarea"
                maxLength={MAX_CONTENT}
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Escribe aquí información confidencial..."
                required
              />
            </div>

            <div className="row-actions">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                <Save size={16} />
                <span>{saving ? 'Cifrando y guardando...' : 'Guardar nota cifrada'}</span>
              </button>
              <Link to="/notes" className="btn btn-secondary">
                Cancelar
              </Link>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
