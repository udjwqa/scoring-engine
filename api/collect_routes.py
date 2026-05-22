import logging
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from scoring_engine import scoring_engine
from request_logger import request_logger
from config import config_store

logger = logging.getLogger("collect")

router = APIRouter()


@router.post("/api/collect")
async def collect_metrics(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    ip = request.client.host if request.client else "0.0.0.0"
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        ip = forwarded.split(",")[0].strip()

    js_result = await scoring_engine.score_js_metrics(data, ip)

    await request_logger.log(
        ip=ip,
        result=js_result,
        user_agent=data.get("userAgent", ""),
        device_model=data.get("hardware", {}).get("platform", ""),
        os_version="",
        country="",
        country_code="",
        city="",
        headers={"source": "js-tracker"},
        js_metrics=data,
    )

    logger.info(f"[{ip}] JS metrics: score={js_result.score} verdict={js_result.verdict}")

    return {
        "received": True,
        "score": js_result.score,
        "verdict": js_result.verdict,
        "details": [d.model_dump() for d in js_result.details],
    }
