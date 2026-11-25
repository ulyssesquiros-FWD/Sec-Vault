import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, KeyRound, RefreshCw, ShieldAlert, Users } from 'lucide-react';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { SecurityBadge } from '../Components/SecurityBadge.jsx';

export function AdminDashboardPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const loadStats = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await apiClient.admin.stats();
      setStats(data.stats);
    } catch (err) {
      setError(err.message || 'No se pudieron cargar las métricas administrativas.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  async function handleRotateKeys() {
    setRotating(true);
    setError('');
    setSuccess('');
    try {
      const res = await apiClient.admin.rotateKeys();
      setSuccess(
        `Rotación completada hacia ${res.activeKeyVersion}: ${res.rotatedUsers} usuario(s) y ${res.rotatedNotes} nota(s) migradas.`
      );
      await loadStats();
    } catch (err) {
      setError(err.message || 'No fue posible ejecutar la rotación de llaves.');
    } finally {
      setRotating(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Centro de Control Administrativo</h1>
          <p className="page-description">
            Métricas globales, auditoría de eventos y gestión de llaves sin acceso a notas privadas ajenas.
          </p>
        </div>
        <div className="row-actions">
          <Link to="/admin/users" className="btn btn-secondary">
            <Users size={16} />
            <span>Gestionar Usuarios</span>
          </Link>
          <Link to="/admin/events" className="btn btn-primary">
            <Activity size={16} />
            <span>Ver Bitácora</span>
          </Link>
        </div>
      </div>

      <AlertBanner type="error" message={error} />
      <AlertBanner type="success" message={success} />

      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-label">Total de Usuarios</span>
          <span className="stat-value">{loading ? '...' : stats?.totalUsers ?? 0}</span>
          <span className="stat-hint">Registrados en MySQL</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Administradores</span>
          <span className="stat-value">{loading ? '...' : stats?.adminCount ?? 0}</span>
          <span className="stat-hint">Cuentas con rol admin</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Usuarios Normales</span>
          <span className="stat-value">{loading ? '...' : stats?.normalUserCount ?? 0}</span>
          <span className="stat-hint">Cuentas con rol user</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Eventos de Seguridad</span>
          <span className="stat-value">{loading ? '...' : stats?.totalSecurityEvents ?? 0}</span>
          <span className="stat-hint">Bitácora persistente MySQL</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Intentos Fallidos Auth</span>
          <span className="stat-value">{loading ? '...' : stats?.failedAuthAttempts ?? 0}</span>
          <span className="stat-hint">LOGIN_FAILED y MFA_FAILED</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Eventos Alta Severidad</span>
          <span className="stat-value">{loading ? '...' : stats?.highSeverityEvents ?? 0}</span>
          <span className="stat-hint">HIGH / CRITICAL registrados</span>
        </div>
      </div>

      <div className="grid-2">
        <section className="card">
          <h2 className="card-title">
            <KeyRound size={18} />
            <span>Gestión y Rotación de Llaves AES-256-GCM</span>
          </h2>
          <p className="muted">
            Versión de llave activa en el servidor:{' '}
            <SecurityBadge variant="cyan" icon="lock">
              {stats?.activeEncryptionKeyVersion || 'v1'}
            </SecurityBadge>
          </p>
          <p className="muted">
            Si actualizaste <code>ENCRYPTION_KEY_VERSION</code> manteniendo llaves previas en{' '}
            <code>DATA_ENCRYPTION_PREVIOUS_KEYS</code>, ejecuta la migración progresiva controlada:
          </p>
          <button type="button" className="btn btn-secondary" onClick={handleRotateKeys} disabled={rotating}>
            <RefreshCw size={15} />
            <span>{rotating ? 'Rotando registros cifrados...' : 'Re-cifrar registros pendientes'}</span>
          </button>
        </section>

        <section className="card">
          <h2 className="card-title">
            <ShieldAlert size={18} />
            <span>Principio de Separación de Privilegios</span>
          </h2>
          <p className="muted">
            El panel administrativo permite auditar eventos, estadísticas y asignar roles, pero bloquea
            estrictamente la lectura de notas privadas pertenecientes a otros usuarios (OWASP A01:2025).
          </p>
        </section>
      </div>
    </div>
  );
}
