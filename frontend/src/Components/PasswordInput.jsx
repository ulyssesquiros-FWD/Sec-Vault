import { useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';

export function PasswordInput({
  id,
  label,
  value,
  onChange,
  placeholder = '',
  autoComplete = 'current-password',
  required = true,
  disabled = false
}) {
  const [visible, setVisible] = useState(false);

  return (
    <div className="form-group">
      {label && (
        <label className="form-label" htmlFor={id}>
          {label}
        </label>
      )}
      <div className="password-wrap">
        <input
          id={id}
          type={visible ? 'text' : 'password'}
          className="input"
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          required={required}
          disabled={disabled}
        />
        <button
          type="button"
          className="password-toggle"
          onClick={() => setVisible((prev) => !prev)}
          aria-label={visible ? 'Ocultar contraseña' : 'Mostrar contraseña'}
        >
          {visible ? <EyeOff size={17} /> : <Eye size={17} />}
        </button>
      </div>
    </div>
  );
}
