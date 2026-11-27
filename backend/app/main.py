from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import db, settings
from .api import router


@asynccontextmanager
async def lifespan(_app):
    if settings.DEMO_PROFILE.is_file():
        settings.validate_demo_configuration()
    db.initialize()
    yield


class RequestTooLarge(Exception):
    pass


class RequestGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        if settings.DEMO_PROFILE.is_file() and (
            request.client is None
            or request.client.host not in settings.LOOPBACK_CLIENTS
        ):
            await JSONResponse({"detail": "The synthetic demo is local-only"}, 403)(
                scope, receive, send
            )
            return
        method = scope["method"]
        is_write = method not in {"GET", "HEAD", "OPTIONS"}
        own_origin = f"{request.url.scheme}://{request.url.netloc}"
        origin = request.headers.get("origin")
        if is_write and (
            request.headers.get("x-ttx-request") != "1"
            or origin
            and origin not in [own_origin, *settings.ORIGINS]
        ):
            await JSONResponse({"detail": "Cross-origin request rejected"}, 403)(
                scope, receive, send
            )
            return
        maximum = (
            settings.MAX_BYTES + 131072
            if scope["path"].endswith("/evidence")
            else 2 * 1024 * 1024
        )
        try:
            if int(request.headers.get("content-length", "0")) > maximum:
                raise RequestTooLarge
        except (RequestTooLarge, ValueError):
            await JSONResponse({"detail": "Request exceeds the size limit"}, 413)(
                scope, receive, send
            )
            return
        total = 0
        started = False
        exceeded = False

        async def bounded_receive():
            nonlocal total, exceeded
            message = await receive()
            total += len(message.get("body", b""))
            if total > maximum:
                exceeded = True
                raise RequestTooLarge
            return message

        async def send_response(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                if exceeded:
                    message["status"] = 413
                message["headers"] = [
                    *message.get("headers", []),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (b"x-frame-options", b"DENY"),
                ]
            await send(message)

        try:
            await self.app(scope, bounded_receive, send_response)
        except RequestTooLarge:
            if not started:
                await JSONResponse({"detail": "Request exceeds the size limit"}, 413)(
                    scope, receive, send
                )


app = FastAPI(
    title="ThreatTrace X",
    version=settings.VERSION,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "System Health"},
        {"name": "Authentication"},
        {"name": "User and Access Management"},
        {"name": "Investigation Cases"},
        {"name": "Digital Evidence and Chain of Custody"},
        {"name": "Events and Timeline"},
        {"name": "Detection and Findings"},
        {"name": "Correlation and Network Forensics"},
        {"name": "Threat Intelligence"},
        {"name": "Reporting and Research"},
    ],
    description=(
        "Local digital forensics, incident reconstruction and threat intelligence. "
        "In Swagger, run Authentication → Login to set a session cookie before calling protected routes. "
        "For write requests, enter 1 for X-TTX-Request. Use synthetic examples in this documentation."
    ),
)
app.add_middleware(RequestGuard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-TTX-Request"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
app.include_router(router)


def documented_schema():
    if app.openapi_schema is not None:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )
    error_body = {
        "application/json": {
            "schema": {
                "type": "object",
                "required": ["detail"],
                "properties": {"detail": {"type": "string"}},
            }
        }
    }
    for path, operations in schema["paths"].items():
        for method, operation in operations.items():
            responses = operation["responses"]
            if path != "/api/v1/health":
                responses.setdefault(
                    "401",
                    {
                        "description": "Missing or invalid session or credentials",
                        "content": error_body,
                    },
                )
            if method in {"post", "put", "patch", "delete"}:
                operation.setdefault("parameters", []).append(
                    {
                        "name": "X-TTX-Request",
                        "in": "header",
                        "required": True,
                        "description": "Cross-origin write safeguard. Use the value 1.",
                        "schema": {"type": "string", "enum": ["1"]},
                        "example": "1",
                    }
                )
                responses.setdefault(
                    "403",
                    {
                        "description": "Write origin rejected or access insufficient",
                        "content": error_body,
                    },
                )
            elif path != "/api/v1/health" and path != "/api/v1/auth/me":
                responses.setdefault(
                    "403",
                    {
                        "description": "Access insufficient or temporary password must be changed",
                        "content": error_body,
                    },
                )
            if "{case_id}" in path or "{item_id}" in path or "{user_id}" in path:
                responses.setdefault(
                    "404",
                    {
                        "description": "Resource does not exist or is outside your case access",
                        "content": error_body,
                    },
                )
            if "422" in responses or method in {"post", "put", "patch"}:
                responses["422"] = {
                    "description": "Input validation failed",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["detail"],
                                "properties": {
                                    "detail": {
                                        "anyOf": [
                                            {"type": "string"},
                                            {
                                                "type": "array",
                                                "items": {
                                                    "$ref": "#/components/schemas/ValidationError"
                                                },
                                            },
                                        ]
                                    },
                                },
                            }
                        },
                    },
                }
    app.openapi_schema = schema
    return schema


app.openapi = documented_schema


@app.exception_handler(RequestValidationError)
async def invalid_request(_request, error):
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {key: issue[key] for key in ("loc", "msg", "type")}
                for issue in error.errors()
            ]
        },
    )


@app.get("/", include_in_schema=False)
def root():
    return Response(status_code=307, headers={"Location": "/docs"})
