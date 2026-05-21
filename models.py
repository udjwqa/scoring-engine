from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Literal, List, Optional, Dict, Any
from datetime import datetime


class ScoringWeights(BaseModel):
    vpnProxyTor: int = 25
    suspiciousCity: int = 15
    englishWebView: int = 10
    suspiciousHosting: int = 20
    mouseWithoutTouch: int = 30
    timezoneMismatch: int = 15


class EngineConfig(BaseModel):
    scoreThreshold: int = 70
    ipqsFailOpen: bool = False
    minPlayIntegrity: Literal[
        "MEETS_BASIC_INTEGRITY",
        "MEETS_DEVICE_INTEGRITY",
        "MEETS_STRONG_INTEGRITY",
    ] = "MEETS_DEVICE_INTEGRITY"
    batteryChargeTimeout: int = 1800
    accelerometerIdleTime: int = 300
    clickSpeedLimit: int = 10
    timezoneDriftHours: int = 2
    weights: ScoringWeights = ScoringWeights()


class BlockList(BaseModel):
    id: str
    name: str
    filename: str
    description: str
    items: List[str]


class BlockListUpdate(BaseModel):
    items: List[str]


class OfferConfig(BaseModel):
    safeUrl: str = "https://play.google.com/store/apps/details?id=com.example.safe"
    targetUrl: str = "https://api.example.com/offer/target"
    whiteFlowType: Literal[
        "show_403", "show_404", "redirect_safe", "fake_html"
    ] = "redirect_safe"


class ScoringDetail(BaseModel):
    check: str
    points: int
    reason: str


class ScoringResult(BaseModel):
    score: int = 0
    verdict: Literal["grey", "white"] = "grey"
    rejectionCode: Optional[str] = None
    details: List[ScoringDetail] = []


class RequestLogEntry(BaseModel):
    id: str
    timestamp: str
    ip: str
    country: str = ""
    countryCode: str = ""
    deviceModel: str = ""
    os: str = ""
    score: int = 0
    verdict: Literal["grey", "white"] = "grey"
    rejectionCode: Optional[str] = None
    rawPayload: Dict[str, Any] = {}
