"""Authenticated local REST API for frontend integration with the simulator."""
from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from importlib.resources import files

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ehls import __version__
from ehls.security import SessionBoundaryMiddleware
from ehls.simulator import SimulationManager, SimulationRequest, SessionCapacityError, SessionView


def create_app(*, api_token: str, allowed_origins: list[str] | None = None,
               memory_lock: bool = True) -> FastAPI:
    if (not api_token or len(api_token) < 24
            or any(not 33 <= ord(char) <= 126 for char in api_token)):
        raise ValueError("EHLS_API_TOKEN must contain at least 24 printable ASCII characters without spaces")
    manager = SimulationManager(memory_lock=memory_lock)

    @asynccontextmanager
    async def lifespan(app):
        yield
        await manager.close()

    app = FastAPI(title="EHLS Integration API", version=__version__, lifespan=lifespan,
                  description="Local simulator API. No printer connection or physical execution.")
    app.state.manager = manager
    app.add_middleware(SessionBoundaryMiddleware, api_token=api_token)
    app.add_middleware(CORSMiddleware,
        allow_origins=allowed_origins if allowed_origins is not None else [
            "http://localhost:5173", "http://127.0.0.1:5173",
            "http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=False, allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"])
    bearer = HTTPBearer(auto_error=False)

    def authorize(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if (credentials is None or credentials.scheme.lower() != "bearer"
                or not hmac.compare_digest(credentials.credentials.encode(), api_token.encode())):
            raise HTTPException(status_code=401, detail="A valid EHLS bearer token is required",
                                headers={"WWW-Authenticate": "Bearer"})

    @app.middleware("http")
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def demo():
        return HTMLResponse(files("ehls").joinpath("static/index.html").read_text())

    @app.get("/sdk/client.js", include_in_schema=False)
    async def browser_sdk():
        return Response(files("ehls").joinpath("static/client.js").read_text(),
                        media_type="text/javascript")

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__, "adapter": "simulator",
                "memory_lock_requested": memory_lock}

    @app.post("/v1/simulations", status_code=202, response_model=SessionView,
              dependencies=[Depends(authorize)])
    async def start_simulation(request: SimulationRequest):
        try:
            return manager.create(request)
        except SessionCapacityError as exc:
            raise HTTPException(429, str(exc), headers={"Retry-After": "5"}) from exc

    @app.get("/v1/sessions/{session_id}", response_model=SessionView,
             dependencies=[Depends(authorize)])
    async def get_session(session_id: str):
        try:
            return manager.get(session_id)
        except KeyError:
            raise HTTPException(404, "Session not found or expired") from None

    @app.post("/v1/sessions/{session_id}/cancel", response_model=SessionView,
              dependencies=[Depends(authorize)])
    async def cancel_session(session_id: str):
        try:
            return manager.cancel(session_id)
        except KeyError:
            raise HTTPException(404, "Session not found or expired") from None

    return app
