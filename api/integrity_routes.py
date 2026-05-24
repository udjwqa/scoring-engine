import logging
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from external.play_integrity import play_integrity_client
from config import config_store
from request_logger import request_logger
from models import ScoringResult, ScoringDetail

logger = logging.getLogger("integrity")

router = APIRouter()

AUTOBAN_SCORE = 100


class IntegrityRequest(BaseModel):
    integrityToken: str
    nonce: str = ""


@router.post("/api/integrity/verify")
async def verify_integrity(body: IntegrityRequest, request: Request):
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )

    if not play_integrity_client.available:
        return JSONResponse({
            "verified": False,
            "error": "Play Integrity not configured",
            "score": 0,
            "verdict": "grey",
        })

    verdict = await play_integrity_client.verify_token(body.integrityToken)

    if not verdict:
        return JSONResponse({
            "verified": False,
            "error": "Verification failed",
            "score": 0,
            "verdict": "grey",
        })

    cfg = config_store.engine
    details = []
    total = 0
    rejection_code = None

    min_integrity = cfg.minPlayIntegrity

    if min_integrity == "MEETS_STRONG_INTEGRITY" and not verdict.meets_strong:
        total += AUTOBAN_SCORE
        rejection_code = "integrity_fail"
        details.append(ScoringDetail(
            check="play_integrity_strong",
            points=AUTOBAN_SCORE,
            reason=f"Device integrity: {verdict.device_recognition} — не STRONG",
        ))
    elif min_integrity == "MEETS_DEVICE_INTEGRITY" and not verdict.meets_device:
        total += AUTOBAN_SCORE
        rejection_code = "integrity_fail"
        details.append(ScoringDetail(
            check="play_integrity_device",
            points=AUTOBAN_SCORE,
            reason=f"Device integrity: {verdict.device_recognition} — не DEVICE",
        ))
    elif min_integrity == "MEETS_BASIC_INTEGRITY" and not verdict.meets_basic:
        total += AUTOBAN_SCORE
        rejection_code = "integrity_fail"
        details.append(ScoringDetail(
            check="play_integrity_basic",
            points=AUTOBAN_SCORE,
            reason=f"Device integrity: {verdict.device_recognition} — не BASIC",
        ))

    if not verdict.is_recognized_app:
        total += 50
        rejection_code = rejection_code or "integrity_app_unrecognized"
        details.append(ScoringDetail(
            check="play_integrity_app",
            points=50,
            reason=f"App recognition: {verdict.app_recognition}",
        ))

    if not verdict.is_licensed:
        total += 30
        details.append(ScoringDetail(
            check="play_integrity_license",
            points=30,
            reason=f"App licensing: {verdict.app_licensing}",
        ))

    threshold = cfg.scoreThreshold
    final_verdict = "white" if total >= threshold else "grey"
    if final_verdict == "grey":
        rejection_code = None

    result = ScoringResult(
        score=total,
        verdict=final_verdict,
        rejectionCode=rejection_code,
        details=details,
    )

    await request_logger.log(
        ip=ip,
        result=result,
        headers={
            "source": "play_integrity",
            "app_recognition": verdict.app_recognition,
            "device_recognition": str(verdict.device_recognition),
            "app_licensing": verdict.app_licensing,
        },
        js_metrics={
            "playIntegrity": verdict.raw,
        },
    )

    logger.info(
        f"[{ip}] Integrity: score={total} verdict={final_verdict} "
        f"device={verdict.device_recognition} app={verdict.app_recognition}"
    )

    return {
        "verified": True,
        "score": total,
        "verdict": final_verdict,
        "rejectionCode": rejection_code,
        "integrity": {
            "deviceRecognition": verdict.device_recognition,
            "appRecognition": verdict.app_recognition,
            "appLicensing": verdict.app_licensing,
            "meetsBasic": verdict.meets_basic,
            "meetsDevice": verdict.meets_device,
            "meetsStrong": verdict.meets_strong,
        },
        "details": [d.model_dump() for d in details],
    }


@router.get("/api/integrity/status")
async def integrity_status():
    return {
        "available": play_integrity_client.available,
        "packageName": play_integrity_client._available and "configured" or "not set",
    }
