
# Security

The supported environment is a trusted local workstation. Backend and frontend scripts bind to 127.0.0.1. The backend accepts only loopback Host values. Choose a unique local administrator password during account setup. Passwords are hashed using scrypt with a per-user salt. Session tokens are random, their hashes are stored in SQLite, and the browser stores the token in an expiring HttpOnly SameSite cookie. All browser writes require the ThreatTrace request header and an allowed Origin. Use the default same-origin proxy when possible.

The synthetic demo launcher prompts for a unique local password for the demo administrator and uses a dedicated SQLite profile under the ignored runtime directory. The repository contains no shared demo password. The demo backend rejects non-loopback clients, external configured browser origins, and database overrides outside its profile. Keep the demo off shared networks and do not expose it through a reverse proxy or tunnel.

Keep the data directory private to the service user and authorized backups. The application stores evidence and protected case metadata in plaintext on the local filesystem. Case access is checked on all case routes. The administrator has access to all local cases. Audit and custody records identify authenticated application accounts. Physical identification and legal admissibility require independent processes.

Administrators can disable or re-enable another account and reset its password after re-entering their current password. Disabling or resetting revokes the target's sessions. After reset, the temporary password grants access only to session and password-change actions until replaced. A password change revokes all sessions for that account. Disabling keeps case ownership, explicit grants and historical audit records intact. The account and access audit log records the actor, action and target without credentials. Out-of-band delivery of a temporary password is the administrator's responsibility.

Upload files collected for an authorized investigation. Parsing is offline and treats logs and packets as passive inputs. The vault serves originals only through an authenticated attachment endpoint. HTML exports escape evidence content. The export endpoint applies a sandbox policy, and CSV fields are guarded against spreadsheet formula interpretation.

For a vulnerability in the application, contact the repository owner privately through a channel they control. Provide version, impact, relevant source paths, and a safe description of the issue. Keep evidence, credentials and identifiers out of public reports.

Remote or shared multi-tenant deployment requires additional hardening, including HTTPS and secure cookies, rate limits, workload isolation and an independent audit anchor. See [the threat model](THREAT_MODEL.md).
