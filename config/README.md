
# Runtime configuration

Environment variables are read on startup. The root .env.example lists the local values. Set variables in the same PowerShell session used to run the scripts. The example file is a reference and is not loaded automatically.

- TTX_DATA_DIR selects the local database and evidence vault directory.
- TTX_MAX_UPLOAD_MIB sets the maximum original file size.
- TTX_SESSION_HOURS controls session expiry.
- TTX_ORIGINS is a comma-delimited browser allowlist.
- TTX_SECURE_COOKIE enables HTTPS-only cookies.
- TTX_SETUP_PASSWORD is an optional noninteractive seeding input. The setup CLI prompts securely when the variable is absent.

SQLite is the supported database. A DSN hook exists for future database profiles. PostgreSQL and remote deployment have not been verified.

The synthetic demo uses a separate local SQLite profile. Use the dedicated demo launcher for interactive setup. Direct seed automation must set TTX_DATA_DIR to an isolated directory and supply its own temporary password. Keep TTX_SETUP_PASSWORD out of source control, shared environments, and shell histories.
