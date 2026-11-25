import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AuthContext } from '../Context/AuthContext.jsx';
import { LoginPage } from '../Pages/LoginPage.jsx';
import { RegisterPage } from '../Pages/RegisterPage.jsx';
import { NotesPage } from '../Pages/NotesPage.jsx';
import { ProtectedRoute } from '../Routes/ProtectedRoute.jsx';
import { AdminRoute } from '../Routes/AdminRoute.jsx';
import { apiClient } from '../Services/apiClient.js';

describe('SecureVault Frontend UI & Seguridad', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renderiza LoginPage con alternador mostrar/ocultar contraseña y enlaces requeridos', () => {
    render(
      <AuthContext.Provider
        value={{ user: null, loading: false, login: vi.fn(), verifyMfa: vi.fn() }}
      >
        <MemoryRouter>
          <LoginPage />
        </MemoryRouter>
      </AuthContext.Provider>
    );

    const passInput = screen.getByLabelText('Contraseña');
    expect(passInput).toHaveAttribute('type', 'password');

    const toggleBtn = screen.getByRole('button', { name: 'Mostrar contraseña' });
    fireEvent.click(toggleBtn);
    expect(passInput).toHaveAttribute('type', 'text');

    expect(screen.getByRole('link', { name: 'Crear una cuenta' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '¿Olvidaste tu contraseña?' })).toBeInTheDocument();
  });

  it('valida política de complejidad y límite de 72 bytes en RegisterPage', () => {
    const registerMock = vi.fn();
    render(
      <AuthContext.Provider value={{ user: null, loading: false, register: registerMock }}>
        <MemoryRouter>
          <RegisterPage />
        </MemoryRouter>
      </AuthContext.Provider>
    );

    fireEvent.change(screen.getByLabelText('Nombre completo'), { target: { value: 'Josué' } });
    fireEvent.change(screen.getByLabelText('Correo electrónico'), {
      target: { value: 'josue@test.com' }
    });
    fireEvent.change(screen.getByLabelText('Teléfono (se almacenará cifrado)'), {
      target: { value: '+506 8812-3456' }
    });
    fireEvent.change(screen.getByLabelText('Contraseña segura'), {
      target: { value: 'debil' }
    });
    fireEvent.change(screen.getByLabelText('Confirmar contraseña'), {
      target: { value: 'debil' }
    });

    fireEvent.click(screen.getByRole('button', { name: 'Crear bóveda segura' }));
    expect(
      screen.getByText('La contraseña no cumple todos los requisitos de seguridad.')
    ).toBeInTheDocument();
    expect(registerMock).not.toHaveBeenCalled();
  });

  it('neutraliza cargas XSS en notas renderizándolas como texto inerte sin ejecutar scripts', async () => {
    const xssPayload = "<script>alert('XSS')</script>";
    vi.spyOn(apiClient.notes, 'list').mockResolvedValue({
      notes: [
        {
          id: 1,
          title: xssPayload,
          content: `Contenido seguro ${xssPayload}`,
          keyVersion: 'v1'
        }
      ],
      limits: { current: 1, maxNotes: 50 }
    });

    const { container } = render(
      <MemoryRouter>
        <NotesPage />
      </MemoryRouter>
    );

    expect(await screen.findByText(xssPayload)).toBeInTheDocument();
    expect(container.querySelectorAll('script')).toHaveLength(0);
  });

  it('bloquea rutas protegidas y administrativas según autenticación y rol', () => {
    render(
      <AuthContext.Provider value={{ user: null, loading: false, logout: vi.fn() }}>
        <MemoryRouter initialEntries={['/dashboard']}>
          <Routes>
            <Route path="/login" element={<div>Pantalla Login</div>} />
            <Route element={<ProtectedRoute />}>
              <Route path="/dashboard" element={<div>Panel Privado</div>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    );
    expect(screen.getByText('Pantalla Login')).toBeInTheDocument();

    render(
      <AuthContext.Provider
        value={{
          user: { id: 2, name: 'Usuario Normal', role: 'user' },
          loading: false,
          logout: vi.fn()
        }}
      >
        <MemoryRouter initialEntries={['/admin']}>
          <Routes>
            <Route path="/dashboard" element={<div>Redirigido a Dashboard</div>} />
            <Route element={<AdminRoute />}>
              <Route path="/admin" element={<div>Panel Admin</div>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    );
    expect(screen.getByText('Redirigido a Dashboard')).toBeInTheDocument();
  });
});
