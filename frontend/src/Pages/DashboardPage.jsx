import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileLock2, Lock, Plus, ShieldCheck, UserCheck } from 'lucide-react';
import { useAuth } from '../Hooks/useAuth.js';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { SecurityBadge } from '../Components/SecurityBadge.jsx';

export function DashboardPage() {
  const { user, logout } = useAuth();
  const [notesData, setNotesData] = useState({ notes: [], limits: { current: 0, maxNotes: 50 } });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    apiClient.notes
      .list()
      .then((res) => {
        if (active) setNotesData(res);
      })
      .catch((err) => {
        if (active) setError(err.message || 'No se pudo cargar el resumen de la bóveda.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Bienvenido, {user?.name}</h1>
          <p className="page-description">
            Estado criptográfico y resumen en tiempo real de tu bóveda privada.
          </p>
        </div>
        <div className="row-actions">
          <Link to="/notes/new" className="btn btn-primary">
            <Plus size={16} />
            <span>Nueva Nota Cifrada</span>
          </Link>
          <button type="button" className="btn btn-secondary" onClick={logout}>
            Cerrar sesión
          </button>
        </div>
      </div>

      <AlertBanner type="error" message={error} />

      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-label">Notas Protegidas</span>
          <span className="stat-value">
            {loading ? '...' : `${notesData.limits.current} / ${notesData.limits.maxNotes}`}
          </span>
          <span className="stat-hint">Cifradas con AES-256-GCM e IV único</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Segundo Factor MFA</span>
          <span className="stat-value">{user?.mfaEnabled ? 'Activo' : 'Opcional'}</span>
          <span className="stat-hint">
            <Link to="/profile">{user?.mfaEnabled ? 'Gestionar TOTP' : 'Activar TOTP ahora'}</Link>
          </span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Rol Verificado</span>
          <span className="stat-value">{user?.role === 'admin' ? 'Administrador' : 'Usuario'}</span>
          <span className="stat-hint">Verificado en servidor mediante sesión MySQL</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Protección Activa</span>
          <span className="stat-value">OWASP 2025</span>
          <span className="stat-hint">Anti-IDOR, CSRF, CSP y Rate Limit</span>
        </div>
      </div>

      <div className="grid-2">
        <section className="card">
          <h2 className="card-title">
            <FileLock2 size={18} />
            <span>Notas recientes</span>
          </h2>
          {loading ? (
            <p className="muted">Descifrando registros autorizados...</p>
          ) : notesData.notes.length === 0 ? (
            <div>
              <p className="muted">Todavía no has guardado notas cifradas en tu bóveda.</p>
              <Link to="/notes/new" className="btn btn-secondary btn-sm">
                Crear mi primera nota
              </Link>
            </div>
          ) : (
            <div className="form-stack">
              {notesData.notes.slice(0, 4).map((note) => (
                <div key={note.id} className="note-card">
                  <div>
                    <h3 className="note-title">{note.title}</h3>
                    <p className="note-preview">{note.content}</p>
                  </div>
                  <div className="note-meta">
                    <SecurityBadge variant="emerald" icon="lock">
                      Llave {note.keyVersion}
                    </SecurityBadge>
                    <Link to={`/notes/${note.id}/edit`}>Abrir / Editar</Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="card">
          <h2 className="card-title">
            <ShieldCheck size={18} />
            <span>Estado de Seguridad de la Cuenta</span>
          </h2>
          <div className="form-stack">
            <div className="row-actions">
              <SecurityBadge variant="emerald" icon="shield">
                Sesión HttpOnly MySQL
              </SecurityBadge>
              <SecurityBadge variant="cyan" icon="lock">
                bcrypt Costo &ge; 12
              </SecurityBadge>
            </div>
            <p className="muted">
              Todas tus notas privadas y tu teléfono se cifran antes de persistirse en MySQL usando
              AES-256-GCM con Datos Autenticados Adicionales (AAD) ligados a tu identificador de usuario.
            </p>
            <div className="row-actions">
              <Link to="/profile" className="btn btn-secondary btn-sm">
                <UserCheck size={15} />
                <span>Revisar Perfil y Teléfono Enmascarado</span>
              </Link>
              <Link to="/notes" className="btn btn-secondary btn-sm">
                <Lock size={15} />
                <span>Ver todas las notas</span>
              </Link>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
