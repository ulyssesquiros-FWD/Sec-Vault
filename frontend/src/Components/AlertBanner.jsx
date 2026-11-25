import { AlertTriangle, CheckCircle2, Info, XCircle } from 'lucide-react';

export function AlertBanner({ type = 'info', message }) {
  if (!message) return null;

  const icons = {
    error: <XCircle size={18} aria-hidden="true" />,
    success: <CheckCircle2 size={18} aria-hidden="true" />,
    warning: <AlertTriangle size={18} aria-hidden="true" />,
    info: <Info size={18} aria-hidden="true" />
  };

  return (
    <div className={`alert alert-${type}`} role={type === 'error' ? 'alert' : 'status'}>
      {icons[type] || icons.info}
      <span>{message}</span>
    </div>
  );
}
