import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';

const SEVERITY_CLASS = {
  INFO: 'badge-neutral',
  WARNING: 'badge-warning',
  HIGH: 'badge-danger',
  CRITICAL: 'badge-danger'
};

export function AdminEventsPage() {
  const [events, setEvents] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [severity, setSeverity] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadEvents = useCallback(async (page = 1) => {
    setLoading(true);
    setError('');
    try {
      const data = await apiClient.admin.events({ severity, search, page, limit: 25 });
      setEvents(data.events || []);
      setPagination(data.pagination || { page: 1, totalPages: 1, total: 0 });
    } catch (err) {
      setError(err.message || 'No se pudo cargar la bitácora de seguridad.');
    } finally {
      setLoading(false);
    }
  }, [severity, search]);

  useEffect(() => {
    loadEvents(1);
  }, [loadEvents]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Bitácora de Eventos de Seguridad</h1>
          <p className="page-description">
            Registro persistente en MySQL (OWASP A09:2025). Eventos totales encontrados: {pagination.total}.
          </p>
        </div>
      </div>

      <AlertBanner type="error" message={error} />

      <div className="toolbar">
        <input
          type="search"
          className="input"
          aria-label="Buscar eventos"
          placeholder="Buscar por tipo, descripción o correo..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="select"
          aria-label="Filtrar por severidad"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">Todas las severidades</option>
          <option value="INFO">INFO</option>
          <option value="WARNING">WARNING</option>
          <option value="HIGH">HIGH</option>
          <option value="CRITICAL">CRITICAL</option>
        </select>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Severidad</th>
              <th>Evento</th>
              <th>Actor</th>
              <th>Descripción</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} className="muted">
                  Consultando eventos en MySQL...
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted">
                  Sin eventos registrados para el filtro seleccionado.
                </td>
              </tr>
            ) : (
              events.map((ev) => (
                <tr key={ev.id}>
                  <td className="mono muted">{new Date(ev.createdAt).toLocaleString()}</td>
                  <td>
                    <span className={`badge ${SEVERITY_CLASS[ev.severity] || 'badge-neutral'}`}>
                      {ev.severity}
                    </span>
                  </td>
                  <td className="mono">{ev.eventType}</td>
                  <td className="mono">{ev.actorEmail || (ev.actorId ? `#${ev.actorId}` : 'Anónimo')}</td>
                  <td>{ev.description}</td>
                  <td className="mono muted">{ev.ipAddress || '-'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="toolbar">
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={pagination.page <= 1}
          onClick={() => loadEvents(pagination.page - 1)}
        >
          Anterior
        </button>
        <span className="muted">
          Página {pagination.page} de {pagination.totalPages}
        </span>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={pagination.page >= pagination.totalPages}
          onClick={() => loadEvents(pagination.page + 1)}
        >
          Siguiente
        </button>
      </div>
    </div>
  );
}
