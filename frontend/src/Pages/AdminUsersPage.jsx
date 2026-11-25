import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../Hooks/useAuth.js';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { ConfirmModal } from '../Components/ConfirmModal.jsx';
import { SecurityBadge } from '../Components/SecurityBadge.jsx';

export function AdminUsersPage() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [roleChangeTarget, setRoleChangeTarget] = useState(null);
  const [updating, setUpdating] = useState(false);

  const loadUsers = useCallback(async (page = 1) => {
    setLoading(true);
    setError('');
    try {
      const data = await apiClient.admin.users({ search, role: roleFilter, page, limit: 15 });
      setUsers(data.users || []);
      setPagination(data.pagination || { page: 1, totalPages: 1, total: 0 });
    } catch (err) {
      setError(err.message || 'No se pudo obtener la lista de usuarios.');
    } finally {
      setLoading(false);
    }
  }, [search, roleFilter]);

  useEffect(() => {
    loadUsers(1);
  }, [loadUsers]);

  async function confirmRoleChange() {
    if (!roleChangeTarget) return;
    setUpdating(true);
    setError('');
    setSuccess('');
    try {
      await apiClient.admin.updateRole(roleChangeTarget.id, roleChangeTarget.nextRole);
      setSuccess(
        `Rol de ${roleChangeTarget.email} actualizado a "${roleChangeTarget.nextRole}" y registrado en bitácora.`
      );
      setRoleChangeTarget(null);
      await loadUsers(pagination.page);
    } catch (err) {
      setError(err.message || 'No fue posible actualizar el rol.');
    } finally {
      setUpdating(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Gestión de Usuarios y Roles</h1>
          <p className="page-description">
            Total listado: {pagination.total}. Nunca se exponen hashes bcrypt ni contenido de notas privadas.
          </p>
        </div>
      </div>

      <AlertBanner type="error" message={error} />
      <AlertBanner type="success" message={success} />

      <div className="toolbar">
        <input
          type="search"
          className="input"
          aria-label="Buscar usuarios"
          placeholder="Buscar por nombre o correo..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="select"
          aria-label="Filtrar por rol"
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
        >
          <option value="">Todos los roles</option>
          <option value="user">Solo user</option>
          <option value="admin">Solo admin</option>
        </select>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Nombre</th>
              <th>Correo</th>
              <th>Rol</th>
              <th>MFA</th>
              <th>Registro</th>
              <th>Acción</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} className="muted">
                  Cargando usuarios...
                </td>
              </tr>
            ) : users.length === 0 ? (
              <tr>
                <td colSpan={7} className="muted">
                  No se encontraron usuarios.
                </td>
              </tr>
            ) : (
              users.map((u) => {
                const isSelf = Number(u.id) === Number(currentUser?.id);
                const nextRole = u.role === 'admin' ? 'user' : 'admin';
                return (
                  <tr key={u.id}>
                    <td className="mono">{u.id}</td>
                    <td>{u.name}</td>
                    <td className="mono">{u.email}</td>
                    <td>
                      <SecurityBadge variant={u.role === 'admin' ? 'cyan' : 'emerald'} icon="shield">
                        {u.role}
                      </SecurityBadge>
                    </td>
                    <td>{u.mfaEnabled ? 'Activo' : 'No'}</td>
                    <td className="muted">{new Date(u.createdAt).toLocaleDateString()}</td>
                    <td>
                      {isSelf ? (
                        <span className="muted">Sesión actual</span>
                      ) : (
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => setRoleChangeTarget({ ...u, nextRole })}
                        >
                          Cambiar a {nextRole}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <ConfirmModal
        open={Boolean(roleChangeTarget)}
        title="Confirmar cambio de rol"
        message={`¿Confirmas cambiar el rol de "${roleChangeTarget?.email || ''}" a "${roleChangeTarget?.nextRole || ''}"? Esta acción revocará sus sesiones activas y quedará auditada.`}
        confirmLabel="Aplicar cambio"
        danger={false}
        busy={updating}
        onConfirm={confirmRoleChange}
        onCancel={() => setRoleChangeTarget(null)}
      />
    </div>
  );
}
