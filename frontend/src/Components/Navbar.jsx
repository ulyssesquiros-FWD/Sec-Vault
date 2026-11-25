import { LogOut, Menu, Shield } from 'lucide-react';
import { useAuth } from '../Hooks/useAuth.js';
import { SecurityBadge } from './SecurityBadge.jsx';

export function Navbar({ onToggleMenu }) {
  const { user, logout } = useAuth();

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          type="button"
          className="btn btn-secondary btn-sm menu-btn"
          onClick={onToggleMenu}
          aria-label="Abrir menú de navegación"
        >
          <Menu size={16} />
        </button>
        <div className="brand-icon" aria-hidden="true">
          <Shield size={20} />
        </div>
        <div>
          <p className="brand-title">SecureVault</p>
          <p className="brand-subtitle">AES-256-GCM · bcrypt · OWASP 2025</p>
        </div>
      </div>

      <div className="topbar-right">
        {user && (
          <>
            <SecurityBadge variant={user.role === 'admin' ? 'cyan' : 'emerald'} icon="shield">
              {user.role === 'admin' ? 'ADMIN' : 'USER'}
            </SecurityBadge>
            <span className="muted">{user.name}</span>
            <button type="button" className="btn btn-secondary btn-sm" onClick={logout}>
              <LogOut size={15} />
              <span>Salir</span>
            </button>
          </>
        )}
      </div>
    </header>
  );
}
