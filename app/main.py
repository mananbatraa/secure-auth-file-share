"""Application factory."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import audit, auth, files, health, mfa, users
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.core.logging import configure_logging
from app.resources import Resources

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(settings: Settings | None = None, resources: Resources | None = None) -> FastAPI:
    settings = settings or (resources.settings if resources else get_settings())
    configure_logging(settings.log_level, json=settings.environment == "production")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = resources is None
        res = resources or Resources.build(settings)
        app.state.resources = res
        if settings.s3_create_bucket:
            await res.storage.ensure_bucket()
        try:
            yield
        finally:
            if owned:
                await res.aclose()

    app = FastAPI(
        title="Secure Auth & File Share",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None,
    )
    if resources is not None:
        app.state.resources = resources

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            # Credentials so browsers send the refresh cookie; origins are explicit.
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Token-Delivery"],
        )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.clear_contextvars()
        response.headers["X-Request-ID"] = request_id
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    @app.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            {"error": {"code": exc.code, "message": exc.message}},
            status_code=exc.status_code,
            headers=exc.headers,
        )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(mfa.router)
    app.include_router(users.router)
    app.include_router(audit.router)
    app.include_router(files.router)
    app.include_router(files.public_router)
    return app


def app_factory() -> FastAPI:  # uvicorn --factory app.main:app_factory
    return create_app()
