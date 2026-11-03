"""Reject unauthenticated and oversized session requests before JSON parsing."""
from __future__ import annotations

import asyncio
import hmac

from starlette.datastructures import Headers
from starlette.responses import JSONResponse

MAX_SESSION_BODY_BYTES = 4096
SESSION_BODY_TIMEOUT_SECONDS = 10


class SessionBoundaryMiddleware:
    def __init__(self, app, *, api_token: str):
        self.app = app
        self._token = api_token.encode("ascii")

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or not scope["path"].startswith("/v1/")
                or scope["method"] == "OPTIONS"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        scheme, _, credential = headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(credential.encode(), self._token):
            await JSONResponse({"detail": "A valid EHLS bearer token is required"}, status_code=401,
                               headers={"WWW-Authenticate": "Bearer"})(scope, receive, send)
            return

        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
                if declared_length < 0:
                    raise ValueError
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
                return
            if declared_length > MAX_SESSION_BODY_BYTES:
                await JSONResponse({"detail": "Session request body exceeds 4096 bytes"}, status_code=413)(scope, receive, send)
                return

        async def collect():
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return None
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > MAX_SESSION_BODY_BYTES:
                    raise OverflowError
                body.extend(chunk)
                if not message.get("more_body", False):
                    return bytes(body)

        try:
            body = await asyncio.wait_for(collect(), timeout=SESSION_BODY_TIMEOUT_SECONDS)
        except OverflowError:
            await JSONResponse({"detail": "Session request body exceeds 4096 bytes"}, status_code=413)(scope, receive, send)
            return
        except asyncio.TimeoutError:
            await JSONResponse({"detail": "Session request body timed out"}, status_code=408)(scope, receive, send)
            return
        if body is None:
            return

        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
