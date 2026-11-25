-- ==============================================================================
-- SecureVault - Migración 002: Soporte MFA TOTP (Bonificación 1)
-- ==============================================================================

ALTER TABLE users
  ADD COLUMN mfa_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER session_version,
  ADD COLUMN mfa_secret_encrypted TEXT NULL AFTER mfa_enabled,
  ADD COLUMN mfa_recovery_hashes JSON NULL AFTER mfa_secret_encrypted;
