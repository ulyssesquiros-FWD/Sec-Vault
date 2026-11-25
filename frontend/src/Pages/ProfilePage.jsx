import { useCallback, useEffect, useState } from 'react';
import { Eye, KeyRound, ShieldCheck, Smartphone, UserCog } from 'lucide-react';
import { useAuth } from '../Hooks/useAuth.js';
import { apiClient } from '../Services/apiClient.js';
import { AlertBanner } from '../Components/AlertBanner.jsx';
import { PasswordInput } from '../Components/PasswordInput.jsx';
import { SecurityBadge } from '../Components/SecurityBadge.jsx';
import { evaluatePasswordPolicy } from '../Utils/passwordStrength.js';

export function ProfilePage() {
  const { refreshUser } = useAuth();

  const [profile, setProfile] = useState(null);
  const [name, setName] = useState('');
  const [phoneInput, setPhoneInput] = useState('');
  const [revealPassword, setRevealPassword] = useState('');
  const [revealedPhone, setRevealedPhone] = useState('');

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');

  const [mfaSetup, setMfaSetup] = useState(null);
  const [mfaCode, setMfaCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [disableMfaPassword, setDisableMfaPassword] = useState('');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const loadProfile = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiClient.users.getProfile();
      setProfile(data.profile);
      setName(data.profile.name);
    } catch (err) {
      setError(err.message || 'No se pudo cargar el perfil.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProfile();
  }, [loadProfile]);

  async function handleRevealPhone(event) {
    event.preventDefault();
    setError('');
    setSuccess('');
    try {
      const res = await apiClient.users.revealPhone({ currentPassword: revealPassword });
      setRevealedPhone(res.phone);
      setPhoneInput(res.phone);
      setRevealPassword('');
      setSuccess('Teléfono descifrado temporalmente tras verificar contraseña.');
    } catch (err) {
      setError(err.message || 'No se pudo verificar la contraseña.');
    }
  }

  async function handleUpdateProfile(event) {
    event.preventDefault();
    setError('');
    setSuccess('');
    if (!phoneInput.trim()) {
      setError('Ingresa el número telefónico completo para actualizar tu perfil.');
      return;
    }
    try {
      const res = await apiClient.users.updateProfile({
        name: name.trim(),
        phone: phoneInput.trim()
      });
      setProfile(res.profile);
      setRevealedPhone('');
      await refreshUser();
      setSuccess('Perfil y teléfono cifrado actualizados correctamente.');
    } catch (err) {
      setError(err.message || 'No se pudo actualizar el perfil.');
    }
  }

  async function handleChangePassword(event) {
    event.preventDefault();
    setError('');
    setSuccess('');
    const policy = evaluatePasswordPolicy(newPassword);
    if (!policy.valid) {
      setError('La nueva contraseña no cumple las políticas de seguridad.');
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setError('La confirmación de la nueva contraseña no coincide.');
      return;
    }
    try {
      const res = await apiClient.users.changePassword({ currentPassword, newPassword });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
      setSuccess(res.message);
    } catch (err) {
      setError(err.message || 'No se pudo actualizar la contraseña.');
    }
  }

  async function handleSetupMfa() {
    setError('');
    setSuccess('');
    setRecoveryCodes([]);
    try {
      const data = await apiClient.users.setupMfa();
      setMfaSetup(data);
    } catch (err) {
      setError(err.message || 'No se pudo generar la configuración MFA.');
    }
  }

  async function handleEnableMfa(event) {
    event.preventDefault();
    setError('');
    setSuccess('');
    try {
      const res = await apiClient.users.enableMfa({ code: mfaCode.trim() });
      setRecoveryCodes(res.recoveryCodes || []);
      setMfaSetup(null);
      setMfaCode('');
      await loadProfile();
      await refreshUser();
      setSuccess(res.message);
    } catch (err) {
      setError(err.message || 'No se pudo activar MFA.');
    }
  }

  async function handleDisableMfa(event) {
    event.preventDefault();
    setError('');
    setSuccess('');
    try {
      const res = await apiClient.users.disableMfa({ currentPassword: disableMfaPassword });
      setDisableMfaPassword('');
      setRecoveryCodes([]);
      await loadProfile();
      await refreshUser();
      setSuccess(res.message);
    } catch (err) {
      setError(err.message || 'No se pudo desactivar MFA.');
    }
  }

  if (loading) {
    return (
      <div className="card">
        <p className="muted">Cargando perfil seguro...</p>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Perfil y Seguridad de Cuenta</h1>
          <p className="page-description">
            El teléfono se almacena cifrado con AES-256-GCM y se muestra enmascarado por defecto.
          </p>
        </div>
        <SecurityBadge variant={profile?.mfaEnabled ? 'emerald' : 'warning'} icon="shield">
          MFA {profile?.mfaEnabled ? 'Activado' : 'Desactivado'}
        </SecurityBadge>
      </div>

      <AlertBanner type="error" message={error} />
      <AlertBanner type="success" message={success} />

      <div className="grid-2">
        <section className="card">
          <h2 className="card-title">
            <UserCog size={18} />
            <span>Información Personal y Teléfono Cifrado</span>
          </h2>
          <p className="muted">
            Correo: <strong className="mono">{profile?.email}</strong> · Rol:{' '}
            <strong>{profile?.role}</strong>
          </p>
          <p className="muted">
            Teléfono registrado:{' '}
            <strong className="mono">{revealedPhone || profile?.maskedPhone}</strong>
          </p>

          {!revealedPhone && (
            <form className="form-stack" onSubmit={handleRevealPhone}>
              <PasswordInput
                id="reveal-phone-pass"
                label="Confirmar contraseña para revelar teléfono completo"
                value={revealPassword}
                onChange={(e) => setRevealPassword(e.target.value)}
                placeholder="Tu contraseña actual"
              />
              <button type="submit" className="btn btn-secondary btn-sm">
                <Eye size={15} />
                <span>Revelar teléfono autorizado</span>
              </button>
            </form>
          )}

          <hr />

          <form className="form-stack" onSubmit={handleUpdateProfile}>
            <div className="form-group">
              <label className="form-label" htmlFor="profile-name">
                Nombre
              </label>
              <input
                id="profile-name"
                type="text"
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="profile-phone">
                Nuevo número telefónico (se cifrará en MySQL)
              </label>
              <input
                id="profile-phone"
                type="tel"
                className="input"
                value={phoneInput}
                onChange={(e) => setPhoneInput(e.target.value)}
                placeholder="+506 8812-3456"
                required
              />
            </div>

            <button type="submit" className="btn btn-primary">
              Guardar cambios de perfil
            </button>
          </form>
        </section>

        <div className="form-stack">
          <section className="card">
            <h2 className="card-title">
              <KeyRound size={18} />
              <span>Cambiar Contraseña</span>
            </h2>
            <form className="form-stack" onSubmit={handleChangePassword}>
              <PasswordInput
                id="cp-current"
                label="Contraseña actual"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
              <PasswordInput
                id="cp-new"
                label="Nueva contraseña (mín. 12 chars, máx. 72 bytes)"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                autoComplete="new-password"
              />
              <PasswordInput
                id="cp-confirm"
                label="Confirmar nueva contraseña"
                value={confirmNewPassword}
                onChange={(e) => setConfirmNewPassword(e.target.value)}
                autoComplete="new-password"
              />
              <button type="submit" className="btn btn-primary">
                Actualizar contraseña y revocar otras sesiones
              </button>
            </form>
          </section>

          <section className="card">
            <h2 className="card-title">
              <Smartphone size={18} />
              <span>Autenticación Multifactor (MFA TOTP)</span>
            </h2>

            {!profile?.mfaEnabled ? (
              <div className="form-stack">
                {!mfaSetup ? (
                  <button type="button" className="btn btn-secondary" onClick={handleSetupMfa}>
                    <ShieldCheck size={16} />
                    <span>Configurar aplicación autenticadora</span>
                  </button>
                ) : (
                  <form className="form-stack" onSubmit={handleEnableMfa}>
                    <p className="muted">
                      Escanea el código QR con Google Authenticator, Authy o FreeOTP:
                    </p>
                    <div className="qr-box">
                      <img src={mfaSetup.qrDataUrl} alt="Código QR TOTP para SecureVault" width={190} height={190} />
                    </div>
                    <p className="muted">
                      Secreto manual: <code className="mono">{mfaSetup.secret}</code>
                    </p>
                    <div className="form-group">
                      <label className="form-label" htmlFor="enable-totp-code">
                        Código de 6 dígitos generado
                      </label>
                      <input
                        id="enable-totp-code"
                        type="text"
                        className="input mono"
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value)}
                        placeholder="123456"
                        required
                      />
                    </div>
                    <button type="submit" className="btn btn-primary">
                      Confirmar y activar MFA
                    </button>
                  </form>
                )}
              </div>
            ) : (
              <form className="form-stack" onSubmit={handleDisableMfa}>
                <p className="muted">Tu cuenta requiere verificación TOTP al iniciar sesión.</p>
                <PasswordInput
                  id="disable-mfa-pass"
                  label="Contraseña actual para desactivar MFA"
                  value={disableMfaPassword}
                  onChange={(e) => setDisableMfaPassword(e.target.value)}
                />
                <button type="submit" className="btn btn-danger btn-sm">
                  Desactivar MFA
                </button>
              </form>
            )}

            {recoveryCodes.length > 0 && (
              <div>
                <p className="muted">
                  <strong>Códigos de recuperación de un solo uso (guárdalos ahora):</strong>
                </p>
                <div className="recovery-grid">
                  {recoveryCodes.map((code) => (
                    <div key={code} className="recovery-code">
                      {code}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
