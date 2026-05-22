import uuid
import logging
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Optional
from models import RequestLogEntry, ScoringResult
from database import async_session
from db_models import RequestLog
from sqlalchemy import select, func, desc

logger = logging.getLogger("request_logger")

MAX_MEMORY_ENTRIES = 500


class RequestLogger:
    def __init__(self):
        self._recent = deque(maxlen=MAX_MEMORY_ENTRIES)

    async def log(
        self,
        ip: str,
        result: ScoringResult,
        user_agent: str = "",
        accept_language: str = "",
        device_model: str = "",
        os_version: str = "",
        country: str = "",
        country_code: str = "",
        city: str = "",
        headers: Optional[dict] = None,
        js_metrics: Optional[dict] = None,
    ):
        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        raw_payload = {
            "headers": headers or {},
            "scoringDetails": [d.model_dump() for d in result.details],
            "jsMetrics": js_metrics or {},
            "playIntegrity": {},
        }

        memory_entry = RequestLogEntry(
            id=entry_id,
            timestamp=now.isoformat() + "Z",
            ip=ip,
            country=country,
            countryCode=country_code,
            deviceModel=device_model,
            os=os_version,
            score=result.score,
            verdict=result.verdict,
            rejectionCode=result.rejectionCode,
            rawPayload=raw_payload,
        )
        self._recent.appendleft(memory_entry)

        try:
            async with async_session() as session:
                db_entry = RequestLog(
                    id=uuid.UUID(entry_id),
                    timestamp=now,
                    ip=ip,
                    country=country,
                    country_code=country_code,
                    city=city,
                    device_model=device_model,
                    os=os_version,
                    user_agent=user_agent,
                    score=result.score,
                    verdict=result.verdict,
                    rejection_code=result.rejectionCode,
                    raw_payload=raw_payload,
                )
                session.add(db_entry)
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to write to DB: {e}")

    def get_recent(self, limit: int = 50):
        return list(self._recent)[:limit]

    async def get_metrics(self):
        try:
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
            async with async_session() as session:
                total_q = await session.execute(
                    select(func.count()).select_from(RequestLog).where(RequestLog.timestamp > cutoff)
                )
                total = total_q.scalar() or 0

                grey_q = await session.execute(
                    select(func.count()).select_from(RequestLog).where(
                        RequestLog.timestamp > cutoff,
                        RequestLog.verdict == "grey",
                    )
                )
                grey = grey_q.scalar() or 0
                white = total - grey

                bans_q = await session.execute(
                    select(func.count()).select_from(RequestLog).where(
                        RequestLog.timestamp > cutoff,
                        RequestLog.score >= 100,
                    )
                )
                bans = bans_q.scalar() or 0

            grey_pct = round(grey / total * 100) if total > 0 else 0
            white_pct = 100 - grey_pct if total > 0 else 0

            return {
                "requests24h": total,
                "greyTraffic": {"count": grey, "percentage": grey_pct},
                "whiteTraffic": {"count": white, "percentage": white_pct},
                "activeBans24h": bans,
                "currentRps": 0,
            }
        except Exception as e:
            logger.error(f"get_metrics error: {e}")
            return {
                "requests24h": 0,
                "greyTraffic": {"count": 0, "percentage": 0},
                "whiteTraffic": {"count": 0, "percentage": 0},
                "activeBans24h": 0,
                "currentRps": 0,
            }

    async def get_rejections(self):
        labels = {
            "no_client_secret": "Нет клиентского секрета",
            "bot_user_agent": "Бот User-Agent",
            "country_blocked": "Страна заблокирована",
            "device_blocked": "Устройство заблокировано",
            "emulator_detected": "Эмулятор обнаружен",
            "emulator_gpu": "GPU эмулятора",
            "suspicious_hosting": "Подозрительный хостинг",
            "vpn_detected": "VPN обнаружен",
            "proxy_detected": "Proxy обнаружен",
            "tor_detected": "Tor обнаружен",
            "ipqs_high_fraud": "IPQS высокий fraud",
            "bot_detected": "Бот обнаружен",
        }
        try:
            async with async_session() as session:
                q = await session.execute(
                    select(
                        RequestLog.rejection_code,
                        func.count().label("cnt"),
                    )
                    .where(RequestLog.rejection_code.isnot(None))
                    .group_by(RequestLog.rejection_code)
                    .order_by(desc("cnt"))
                )
                rows = q.all()
            return [
                {"code": code, "label": labels.get(code, code), "count": cnt}
                for code, cnt in rows
            ]
        except Exception as e:
            logger.error(f"get_rejections error: {e}")
            return []

    async def query_logs(
        self,
        search: str = "",
        verdict: str = "all",
        rejection_code: Optional[str] = None,
        country: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        page: int = 1,
        page_size: int = 25,
    ):
        try:
            async with async_session() as session:
                base = select(RequestLog)
                count_base = select(func.count()).select_from(RequestLog)

                conditions = []
                if search:
                    pattern = f"%{search}%"
                    conditions.append(
                        RequestLog.ip.ilike(pattern)
                        | RequestLog.user_agent.ilike(pattern)
                        | RequestLog.device_model.ilike(pattern)
                    )
                if verdict and verdict != "all":
                    conditions.append(RequestLog.verdict == verdict)
                if rejection_code:
                    conditions.append(RequestLog.rejection_code == rejection_code)
                if country:
                    conditions.append(RequestLog.country_code == country.upper())
                if date_from:
                    conditions.append(
                        RequestLog.timestamp >= datetime.fromisoformat(date_from)
                    )
                if date_to:
                    conditions.append(
                        RequestLog.timestamp <= datetime.fromisoformat(date_to) + timedelta(days=1)
                    )

                for cond in conditions:
                    base = base.where(cond)
                    count_base = count_base.where(cond)

                total_q = await session.execute(count_base)
                total = total_q.scalar() or 0

                total_pages = max(1, -(-total // page_size))
                safe_page = min(page, total_pages)
                offset = (safe_page - 1) * page_size

                rows_q = await session.execute(
                    base.order_by(desc(RequestLog.timestamp))
                    .offset(offset)
                    .limit(page_size)
                )
                rows = rows_q.scalars().all()

            return {
                "entries": [r.to_dict() for r in rows],
                "total": total,
                "page": safe_page,
                "pageSize": page_size,
                "totalPages": total_pages,
            }
        except Exception as e:
            logger.error(f"query_logs error: {e}")
            return {
                "entries": [], "total": 0, "page": 1,
                "pageSize": page_size, "totalPages": 1,
            }


request_logger = RequestLogger()
