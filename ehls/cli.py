"""Start the optional EHLS integration service."""
import argparse
import os
import secrets


def main():
    parser = argparse.ArgumentParser(description="EHLS simulator integration service")
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-memory-lock", action="store_true",
                        help="Use unlocked working buffers for a development simulation")
    args = parser.parse_args()
    try:
        import uvicorn
        from ehls.api import create_app
    except ImportError:
        parser.error('Install the API extra first: python -m pip install -e ".[api]"')
    token = os.environ.get("EHLS_API_TOKEN")
    if token is None:
        token = secrets.token_urlsafe(32)
        print("Temporary local API token (changes on restart):", token, flush=True)
    origins = os.environ.get("EHLS_ALLOWED_ORIGINS")
    allowed_origins = [s.strip() for s in origins.split(",") if s.strip()] if origins is not None else None
    memory_lock = not args.no_memory_lock and os.environ.get("EHLS_MEMORY_LOCK", "1") != "0"
    try:
        app = create_app(api_token=token, allowed_origins=allowed_origins, memory_lock=memory_lock)
    except ValueError as exc:
        parser.error(str(exc))
    if not memory_lock:
        print("Development simulation: memory locking disabled", flush=True)
    print(f"Browser demo: http://localhost:{args.port} | API docs: http://localhost:{args.port}/docs", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
