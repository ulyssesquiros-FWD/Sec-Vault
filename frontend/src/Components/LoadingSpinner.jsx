export function LoadingSpinner({ label = 'Cargando entorno seguro...' }) {
  return (
    <div className="spinner-wrap" role="status" aria-live="polite">
      <p>{label}</p>
    </div>
  );
}
