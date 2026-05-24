import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from database import Base


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip = Column(String(45), index=True)
    country = Column(String(100))
    country_code = Column(String(5), index=True)
    city = Column(String(200))
    device_model = Column(String(200))
    os = Column(String(100))
    user_agent = Column(Text)
    score = Column(Integer, default=0)
    verdict = Column(String(10), index=True)
    rejection_code = Column(String(50), index=True, nullable=True)
    raw_payload = Column(JSONB, default=dict)

    __table_args__ = (
        Index("idx_timestamp_verdict", "timestamp", "verdict"),
        Index("idx_ip_timestamp", "ip", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else "",
            "ip": self.ip or "",
            "country": self.country or "",
            "countryCode": self.country_code or "",
            "city": self.city or "",
            "deviceModel": self.device_model or "",
            "os": self.os or "",
            "score": self.score or 0,
            "verdict": self.verdict or "grey",
            "rejectionCode": self.rejection_code,
            "rawPayload": self.raw_payload or {},
        }


class BannedIP(Base):
    __tablename__ = "banned_ips"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip = Column(String(45), unique=True, index=True)
    reason = Column(String(200))
    source = Column(String(50))
    banned_at = Column(DateTime, default=datetime.utcnow)
    cf_rule_id = Column(String(100), nullable=True)

    def to_dict(self):
        return {
            "id": str(self.id),
            "ip": self.ip or "",
            "reason": self.reason or "",
            "source": self.source or "",
            "bannedAt": self.banned_at.isoformat() + "Z" if self.banned_at else "",
            "cfRuleId": self.cf_rule_id,
        }
