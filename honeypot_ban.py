import logging
import redis.asyncio as aioredis
from rate_limiter import REDIS_URL

logger = logging.getLogger("honeypot")

BAN_TTL = 86400 * 7


class HoneypotBan:
    def __init__(self):
        self._redis = None

    async def connect(self):
        try:
            self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            await self._redis.ping()
            logger.info("Honeypot ban list connected to Redis")
        except Exception as e:
            logger.warning(f"Redis unavailable for honeypot: {e}")
            self._redis = None

    async def close(self):
        if self._redis:
            await self._redis.aclose()

    async def ban(self, ip, reason="honeypot"):
        if not self._redis:
            return
        key = f"honeypot:ban:{ip}"
        await self._redis.set(key, reason, ex=BAN_TTL)
        await self._redis.sadd("honeypot:banned_ips", ip)
        logger.warning(f"HONEYPOT BAN: {ip} ({reason})")

    async def is_banned(self, ip):
        if not self._redis:
            return False
        return await self._redis.exists(f"honeypot:ban:{ip}")

    async def get_all_banned(self):
        if not self._redis:
            return []
        return list(await self._redis.smembers("honeypot:banned_ips"))

    async def unban(self, ip):
        if not self._redis:
            return
        await self._redis.delete(f"honeypot:ban:{ip}")
        await self._redis.srem("honeypot:banned_ips", ip)


honeypot_ban = HoneypotBan()
