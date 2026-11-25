import { NavLink } from 'react-router-dom';
import {
  Activity,
  FileLock2,
  LayoutDashboard,
  PlusCircle,
  ShieldCheck,
  UserCog,
  Users
} from 'lucide-react';
import { useAuth } from '../Hooks/useAuth.js';

export function Sidebar({ open, onNavigate }) {
  const { user } = useAuth();

  return (
    <aside className={`sidebar ${open ? 'open' : ''}`} aria-label="Navegación principal">
      <div>
        <div className="nav-section-label">Bóveda Personal</div>
        <nav className="nav-list">
          <NavLink to="/dashboard" className="nav-link" onClick={onNavigate}>
            <LayoutDashboard size={17} />
            <span>Panel Principal</span>
          </NavLink>
          <NavLink to="/notes" end className="nav-link" onClick={onNavigate}>
            <FileLock2 size={17} />
            <span>Notas Cifradas</span>
          </NavLink>
          <NavLink to="/notes/new" className="nav-link" onClick={onNavigate}>
            <PlusCircle size={17} />
            <span>Nueva Nota</span>
          </NavLink>
          <NavLink to="/profile" className="nav-link" onClick={onNavigate}>
            <UserCog size={17} />
            <span>Perfil y MFA</span>
          </NavLink>
        </nav>
      </div>

      {user?.role === 'admin' && (
        <div>
          <div className="nav-section-label">Administración</div>
          <nav className="nav-list">
            <NavLink to="/admin" end className="nav-link" onClick={onNavigate}>
              <ShieldCheck size={17} />
              <span>Panel Admin</span>
            </NavLink>
            <NavLink to="/admin/users" className="nav-link" onClick={onNavigate}>
              <Users size={17} />
              <span>Gestión de Usuarios</span>
            </NavLink>
            <NavLink to="/admin/events" className="nav-link" onClick={onNavigate}>
              <Activity size={17} />
              <span>Bitácora de Seguridad</span>
            </NavLink>
          </nav>
        </div>
      )}
    </aside>
  );
}
