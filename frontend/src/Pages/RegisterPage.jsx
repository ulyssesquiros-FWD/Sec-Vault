import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldPlus } from 'lucide-react';
import { useAuth } from '../Hooks/useAuth.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { PasswordInput } from '../Components/PasswordInput.jsx';
import { evaluatePasswordPolicy } from '../Utils/passwordStrength.js';

export function RegisterPage() {
  const navigate = useNavigate();
  const { register } = useAuth();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const policy = evaluatePasswordPolicy(password);
  const passwordsMatch = password.length > 0 && password === confirmPassword;

  async function handleSubmit(event) {
    event.preventDefault();
    setError('');

    if (!policy.valid) {
      setError('La contraseña no cumple todos los requisitos de seguridad.');
      return;
    }
    if (!passwordsMatch) {
      setError('Las contraseñas no coinciden.');
      return;
    }

    setSubmitting(true);
    try {
      await register({
        name: name.trim(),
        email: email.trim(),
        phone: phone.trim(),
        password
      });
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'No fue posible completar el registro.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <section className="auth-card" aria-labelledby="register-heading">
        <div className="brand-header">
          <div className="brand-icon" aria-hidden="true">
            <ShieldPlus size={22} />
          </div>
          <div>
            <h1 id="register-heading" className="brand-title">
              Crear cuenta en SecureVault
            </h1>
            <p className="brand-subtitle">Contraseña con bcrypt (costo 12) y teléfono cifrado AES-256-GCM</p>
          </div>
        </div>

        <AlertBanner type="error" message={error} />

        <form className="form-stack" onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label className="form-label" htmlFor="reg-name">
              Nombre completo
            </label>
            <input
              id="reg-name"
              type="text"
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Ej. Josué Varela"
              autoComplete="name"
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="reg-email">
              Correo electrónico
            </label>
            <input
              id="reg-email"
              type="email"
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="usuario@ejemplo.com"
              autoComplete="email"
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="reg-phone">
              Teléfono (se almacenará cifrado)
            </label>
            <input
              id="reg-phone"
              type="tel"
              className="input"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="+506 8812-3456"
              autoComplete="tel"
              required
            />
          </div>

          <div>
            <PasswordInput
              id="reg-password"
              label="Contraseña segura"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Mínimo 12 caracteres"
              autoComplete="new-password"
            />
            <ul className="checklist" aria-label="Requisitos de contraseña">
              <li className={`checklist-item ${policy.checks.minLength ? 'valid' : ''}`}>
                • Mínimo 12 caracteres
              </li>
              <li className={`checklist-item ${policy.checks.maxBytes ? 'valid' : 'invalid'}`}>
                • Máximo 72 bytes ({policy.byteLength}/72)
              </li>
              <li className={`checklist-item ${policy.checks.hasUpper ? 'valid' : ''}`}>
                • Al menos 1 mayúscula
              </li>
              <li className={`checklist-item ${policy.checks.hasLower ? 'valid' : ''}`}>
                • Al menos 1 minúscula
              </li>
              <li className={`checklist-item ${policy.checks.hasNumber ? 'valid' : ''}`}>
                • Al menos 1 número
              </li>
              <li className={`checklist-item ${policy.checks.hasSymbol ? 'valid' : ''}`}>
                • Al menos 1 símbolo
              </li>
            </ul>
          </div>

          <PasswordInput
            id="reg-confirm"
            label="Confirmar contraseña"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Repite la contraseña"
            autoComplete="new-password"
          />

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Registrando cuenta...' : 'Crear bóveda segura'}
          </button>
        </form>

        <div className="auth-footer">
          <span>¿Ya tienes cuenta?</span>
          <Link to="/login">Iniciar sesión</Link>
        </div>
      </section>
    </div>
  );
}
