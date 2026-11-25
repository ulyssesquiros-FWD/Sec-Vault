import { useState } from 'react';
import { Navbar } from './Navbar.jsx';
import { Sidebar } from './Sidebar.jsx';

export function Layout({ children }) {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="app-shell">
      <Navbar onToggleMenu={() => setMenuOpen((prev) => !prev)} />
      <Sidebar open={menuOpen} onNavigate={() => setMenuOpen(false)} />
      <main className="main-content">{children}</main>
    </div>
  );
}
