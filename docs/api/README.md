
# REST API

The interactive schema is available on the running backend at [OpenAPI](http://127.0.0.1:8000/docs). All application routes use the prefix /api/v1. Public routes are health and the login action. A successful login sets an HttpOnly cookie. For a write in Swagger, enter `1` in the `X-TTX-Request` header field. Sign in through Swagger on the same backend origin so the browser receives its session cookie. The examples use synthetic values and placeholder credentials. Supported browser origins are configured by TTX_ORIGINS.

| Resource | Representative routes |
| --- | --- |
| Session and user administration | /auth/login, /auth/me, /auth/logout, /auth/password, /users, /users/audit, /users/{user_id}/status, /users/{user_id}/password |
| Case management | /cases, /cases/{case_id}, /cases/{case_id}/access, /cases/{case_id}/access/{user_id} |
| Evidence and custody | /cases/{case_id}/evidence, /cases/{case_id}/evidence/{evidence_id}/verify, /custody under evidence |
| Timeline and events | /cases/{case_id}/events, /timeline under case, event detail by ID, POST /cases/{case_id}/timeline/export |
| Analysis and rules | /cases/{case_id}/analyze, /findings under case, /rules |
| Graph and entities | /cases/{case_id}/correlation, /entities under case |
| Network and indicators | /cases/{case_id}/network, /intelligence under case |
| Notes and export | /cases/{case_id}/notes, /reports under case, /reports/{format} under case |
| Dashboard and research | /dashboard, /research, /research/{format}, /research/multi-seed |

Collection responses with pagination include items, page, limit and total. Invalid inputs return HTTP 422. Duplicate imports return 409. Case references outside the caller's visible scope give 404. For a custom file upload send multipart evidence file, format and source, and optional collection_at, timezone_offset (minutes) and clock_offset (seconds).

## Export scope

`GET /cases/{case_id}/timeline` and `POST /cases/{case_id}/timeline/export` accept the same search, category, severity, host, account, evidence and time filters. The export includes all matching rows in timeline order. Its audit entry records the result count and filter names. `POST /cases/{case_id}/reports/events.csv` exports the full case timeline.
