from dotenv import load_dotenv
load_dotenv()

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import config_store
from lists_manager import lists_manager
from api.health import router as health_router
from api.config_routes import router as config_router
from api.lists_routes import router as lists_router
from api.gateway import router as gateway_router
from api.dashboard_routes import router as dashboard_router
from api.audit_routes import router as audit_router
from api.collect_routes import router as collect_router
from api.cf_sync import router as cf_sync_router
from database import init_db
from ip_ranges import ip_range_checker
from rate_limiter import rate_limiter
from honeypot_ban import honeypot_ban
from pathlib import Path
from external.ipinfo_client import ipinfo_client
from external.ipqs_client import ipqs_client
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting server...")
    config_store.load()
    logger.info(f"Config loaded (scoreThreshold={config_store.engine.scoreThreshold})")
    await init_db()
    await lists_manager.load_all()
    await lists_manager.start_watcher(interval=5)
    ip_range_checker.load()
    await rate_limiter.connect()
    await honeypot_ban.connect()
    logger.info("Server ready")
    yield
    lists_manager.stop_watcher()
    await rate_limiter.close()
    await honeypot_ban.close()
    await ipinfo_client.close()
    await ipqs_client.close()
    logger.info("Server stopped")


app = FastAPI(
    title="APK Traffic Scoring Engine",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        skip_paths = ("/api/health", "/api/bans", "/api/config", "/api/lists",
                      "/api/offers", "/api/cf/", "/api/dashboard", "/api/audit",
                      "/api/form", "/api/collect")
        if any(request.url.path.startswith(p) for p in skip_paths):
            return await call_next(request)

        forwarded = request.headers.get("x-forwarded-for", "")
        real_ip = request.headers.get("x-real-ip", "")
        ip = forwarded.split(",")[0].strip() if forwarded else (
            real_ip or (request.client.host if request.client else "0.0.0.0")
        )

        if await honeypot_ban.is_banned(ip):
            safe_url = config_store.offers.safeUrl
            return RedirectResponse(url=safe_url, status_code=302)

        allowed, count = await rate_limiter.check(ip)
        if not allowed:
            safe_url = config_store.offers.safeUrl
            logger.warning(f"Rate limit exceeded: {ip} ({count} req/min)")
            return RedirectResponse(url=safe_url, status_code=302)

        response = await call_next(request)
        response.headers["X-RateLimit-Count"] = str(count)
        return response

app.add_middleware(RateLimitMiddleware)

app.include_router(health_router)
app.include_router(config_router)
app.include_router(lists_router)
app.include_router(dashboard_router)
app.include_router(audit_router)
app.include_router(collect_router)
app.include_router(cf_sync_router)

from api.honeypot import router as honeypot_router
app.include_router(honeypot_router)

app.include_router(gateway_router)

from fastapi.responses import FileResponse

JS_SCRIPTS_DIR = Path(__file__).parent.parent / "js-scripts"

@app.get("/tracker.js")
async def serve_tracker():
    obf = JS_SCRIPTS_DIR / "tracker.min.js"
    src = JS_SCRIPTS_DIR / "tracker.js"
    path = obf if obf.exists() else src
    return FileResponse(
        path,
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=3600"},
    )
