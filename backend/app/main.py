from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import db, settings
from .api import router


@asynccontextmanager
async def lifespan(_app):
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
    version="0.1.0",
    lifespan=lifespan,
    description="Local digital forensics, incident reconstruction and threat intelligence.",
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
