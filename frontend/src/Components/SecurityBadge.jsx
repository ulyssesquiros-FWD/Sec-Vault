import { Lock, ShieldCheck, ShieldAlert } from 'lucide-react';

export function SecurityBadge({ variant = 'emerald', icon = 'lock', children }) {
  const icons = {
    lock: <Lock size={12} aria-hidden="true" />,
    shield: <ShieldCheck size={12} aria-hidden="true" />,
    alert: <ShieldAlert size={12} aria-hidden="true" />
  };

  return (
    <span className={`badge badge-${variant}`}>
      {icons[icon] || icons.lock}
      <span>{children}</span>
    </span>
  );
}
