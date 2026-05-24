import logging
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from honeypot_ban import honeypot_ban
from request_logger import request_logger
from models import ScoringResult, ScoringDetail

logger = logging.getLogger("honeypot")

router = APIRouter()

HONEYPOT_PATHS = {
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/.env", "/.env.local", "/.env.production",
    "/config.php", "/config.yml", "/config.json",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/phpmyadmin", "/pma", "/myadmin",
    "/xmlrpc.php", "/wp-content", "/wp-includes",
    "/api/v1", "/api/v2",
    "/login", "/signin", "/register",
    "/debug", "/debug/vars", "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd",
    "/backup", "/dump.sql", "/db.sql",
    "/cgi-bin", "/shell", "/cmd",
}

FAKE_ROBOTS = """User-agent: *
Disallow: /api/
Disallow: /admin/
Disallow: /private/
Sitemap: https://example.com/sitemap.xml
"""

FAKE_SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
</urlset>"""

FAKE_WP_LOGIN = """<!DOCTYPE html>
<html><head><title>Log In</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found.</p></body>
</html>"""


def get_ip(request):
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    return forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )


async def trap(request, path):
    ip = get_ip(request)
    ua = request.headers.get("user-agent", "")

    await honeypot_ban.ban(ip, f"honeypot:{path}")

    result = ScoringResult(
        score=100,
        verdict="white",
        rejectionCode="honeypot",
        details=[ScoringDetail(
            check="honeypot_trap",
            points=100,
            reason=f"Honeypot: запрос на {path}",
        )],
    )

    await request_logger.log(
        ip=ip,
        result=result,
        user_agent=ua,
        headers={"source": "honeypot", "path": path},
    )

    logger.warning(f"HONEYPOT: {ip} → {path} (UA: {ua[:60]})")


@router.get("/robots.txt")
async def robots(request: Request):
    await trap(request, "/robots.txt")
    return PlainTextResponse(FAKE_ROBOTS, media_type="text/plain")


@router.get("/sitemap.xml")
@router.get("/sitemap_index.xml")
async def sitemap(request: Request):
    await trap(request, "/sitemap.xml")
    return PlainTextResponse(FAKE_SITEMAP, media_type="application/xml")


@router.get("/wp-admin")
@router.get("/wp-login.php")
@router.get("/wp-content/{path:path}")
@router.get("/wp-includes/{path:path}")
@router.get("/xmlrpc.php")
async def wp_trap(request: Request):
    await trap(request, request.url.path)
    return HTMLResponse(FAKE_WP_LOGIN, status_code=404)


@router.get("/admin")
@router.get("/administrator")
@router.get("/login")
@router.get("/signin")
@router.get("/register")
@router.get("/phpmyadmin")
@router.get("/pma")
@router.get("/myadmin")
async def admin_trap(request: Request):
    await trap(request, request.url.path)
    return HTMLResponse("<h1>403 Forbidden</h1>", status_code=403)


@router.get("/.env")
@router.get("/.env.local")
@router.get("/.env.production")
@router.get("/config.php")
@router.get("/config.yml")
@router.get("/.git/config")
@router.get("/.git/HEAD")
@router.get("/.gitignore")
@router.get("/.htaccess")
@router.get("/.htpasswd")
async def config_trap(request: Request):
    await trap(request, request.url.path)
    return PlainTextResponse("", status_code=403)


@router.get("/debug")
@router.get("/debug/vars")
@router.get("/server-status")
@router.get("/server-info")
@router.get("/cgi-bin/{path:path}")
@router.get("/shell")
@router.get("/cmd")
@router.get("/api/v1")
@router.get("/api/v1/{path:path}")
@router.get("/api/v2")
@router.get("/api/v2/{path:path}")
@router.get("/backup")
@router.get("/dump.sql")
@router.get("/db.sql")
async def generic_trap(request: Request):
    await trap(request, request.url.path)
    return JSONResponse({"error": "Not Found"}, status_code=404)
