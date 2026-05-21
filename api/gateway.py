from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from scoring_engine import scoring_engine
from request_logger import request_logger
from config import config_store

router = APIRouter()

FAKE_HTML = """<!DOCTYPE html>
<html><head><title>App</title></head>
<body><h1>Welcome</h1><p>Content not available.</p></body>
</html>"""


@router.get("/")
async def gateway(request: Request):
    headers = dict(request.headers)
    ip = request.client.host if request.client else "0.0.0.0"

    user_agent = headers.get("user-agent", "")
    accept_language = headers.get("accept-language", "")
    client_secret = headers.get("x-client-secret")
    device_model = headers.get("x-device-model", "")
    device_codename = headers.get("x-device-codename", "")
    gpu_renderer = headers.get("x-gpu-renderer", "")
    country = headers.get("x-country", "")
    country_code = headers.get("x-country-code", country.upper()[:2] if country else "")
    city = headers.get("x-city", "")
    isp = headers.get("x-isp", "")
    os_version = headers.get("x-os-version", "")

    result = await scoring_engine.score_request(
        user_agent=user_agent,
        accept_language=accept_language,
        client_secret=client_secret,
        device_model=device_model,
        device_codename=device_codename,
        gpu_renderer=gpu_renderer,
        country=country_code or country,
        city=city,
        isp=isp,
        ip=ip,
    )

    await request_logger.log(
        ip=ip,
        result=result,
        user_agent=user_agent,
        accept_language=accept_language,
        device_model=device_model,
        os_version=os_version,
        country=country,
        country_code=country_code,
        city=city,
        headers=headers,
    )

    offers = config_store.offers

    if result.verdict == "grey":
        return RedirectResponse(url=offers.targetUrl, status_code=302)

    flow = offers.whiteFlowType
    if flow == "show_403":
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    elif flow == "show_404":
        return JSONResponse(status_code=404, content={"error": "Not Found"})
    elif flow == "redirect_safe":
        return RedirectResponse(url=offers.safeUrl, status_code=302)
    elif flow == "fake_html":
        return HTMLResponse(content=FAKE_HTML, status_code=200)

    return JSONResponse(status_code=403, content={"error": "Forbidden"})


@router.get("/score-debug")
async def score_debug(request: Request):
    """Debug endpoint — показывает результат скоринга без редиректа."""
    headers = dict(request.headers)
    ip = request.client.host if request.client else "0.0.0.0"

    result = await scoring_engine.score_request(
        user_agent=headers.get("user-agent", ""),
        accept_language=headers.get("accept-language", ""),
        client_secret=headers.get("x-client-secret"),
        device_model=headers.get("x-device-model", ""),
        device_codename=headers.get("x-device-codename", ""),
        gpu_renderer=headers.get("x-gpu-renderer", ""),
        country=headers.get("x-country", ""),
        city=headers.get("x-city", ""),
        isp=headers.get("x-isp", ""),
        ip=ip,
    )

    await request_logger.log(
        ip=ip,
        result=result,
        user_agent=headers.get("user-agent", ""),
        device_model=headers.get("x-device-model", ""),
        os_version=headers.get("x-os-version", ""),
        country=headers.get("x-country", ""),
        country_code=headers.get("x-country-code", ""),
        city=headers.get("x-city", ""),
        headers=headers,
    )

    return {
        "ip": ip,
        "score": result.score,
        "threshold": config_store.engine.scoreThreshold,
        "verdict": result.verdict,
        "rejectionCode": result.rejectionCode,
        "details": [d.model_dump() for d in result.details],
    }
