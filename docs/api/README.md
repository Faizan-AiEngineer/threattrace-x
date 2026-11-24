
# REST API

The interactive schema is available on the running backend at [OpenAPI](http://127.0.0.1:8000/docs). All application routes use the prefix /api/v1. Public routes are health and the login action. A successful login sets an HttpOnly cookie. Send X-TTX-Request with value 1 on write requests and retain the session cookie. Supported browser origins are configured by TTX_ORIGINS.

| Resource | Representative routes |
| --- | --- |
| Session and user administration | /auth/login, /auth/me, /auth/logout, /users |
| Case management | /cases, /cases/{case_id}, /cases/{case_id}/access/{user_id} |
| Evidence and custody | /cases/{case_id}/evidence, /cases/{case_id}/evidence/{evidence_id}/verify, /custody under evidence |
| Timeline and events | /cases/{case_id}/events, /timeline under case, event detail by ID |
| Analysis and rules | /cases/{case_id}/analyze, /findings under case, /rules |
| Graph and entities | /cases/{case_id}/correlation, /entities under case |
| Network and indicators | /cases/{case_id}/network, /intelligence under case |
| Notes and export | /cases/{case_id}/notes, /reports under case, /reports/{format} under case |
| Dashboard and research | /dashboard, /research, /research/{format} |

Collection responses with pagination include items, page, limit and total. Invalid inputs return HTTP 422. Duplicate imports return 409. Case references outside the caller's visible scope give 404. For a custom file upload send multipart evidence file, format and source, and optional collection_at, timezone_offset (minutes) and clock_offset (seconds).
