import os
import secrets
import hashlib
import logging
import redis.asyncio as aioredis
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
NONCE_TTL = int(os.getenv("NONCE_TTL", "300"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_redis = None


async def get_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis


@router.get("/api/integrity/nonce")
async def generate_nonce(request: Request):
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = request.headers.get("x-real-ip", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        real_ip or (request.client.host if request.client else "0.0.0.0")
    )

    raw = secrets.token_hex(32)
    nonce = hashlib.sha256(raw.encode()).hexdigest()

    try:
        r = await get_redis()
        await r.set(f"nonce:{nonce}", ip, ex=NONCE_TTL)
        logger.info(f"Nonce generated for {ip}: {nonce[:16]}... (TTL={NONCE_TTL}s)")
    except Exception as e:
        logger.error(f"Redis nonce write failed: {e}")

    return {"nonce": nonce, "ttl": NONCE_TTL}


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

    # === NONCE VALIDATION ===
    if body.nonce:
        try:
            r = await get_redis()
            nonce_ip = await r.get(f"nonce:{body.nonce}")

            if nonce_ip is None:
                logger.warning(f"[{ip}] Nonce unknown or expired: {body.nonce[:16]}...")
                return JSONResponse({
                    "verified": False,
                    "error": "Invalid or expired nonce (possible replay attack)",
                    "score": AUTOBAN_SCORE,
                    "verdict": "white",
                    "rejectionCode": "nonce_invalid",
                }, status_code=403)

            await r.delete(f"nonce:{body.nonce}")
            logger.info(f"[{ip}] Nonce consumed: {body.nonce[:16]}...")

        except Exception as e:
            logger.error(f"Redis nonce check failed: {e}")
    else:
        logger.warning(f"[{ip}] No nonce provided in integrity verify request")

    # === PLAY INTEGRITY ===
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

    # === NONCE MATCH CHECK ===
    if body.nonce and verdict.nonce and verdict.nonce != body.nonce:
        logger.warning(
            f"[{ip}] Nonce mismatch: sent={body.nonce[:16]} token={verdict.nonce[:16]}"
        )
        return JSONResponse({
            "verified": False,
            "error": "Nonce mismatch (token tampered)",
            "score": AUTOBAN_SCORE,
            "verdict": "white",
            "rejectionCode": "nonce_mismatch",
        }, status_code=403)

    # === SCORING ===
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
            "nonce_verified": "true",
        },
        js_metrics={"playIntegrity": verdict.raw},
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
