import os
import logging
import redis.asyncio as aioredis

logger = logging.getLogger("rate_limiter")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "100"))
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))


class RateLimiter:
    def __init__(self):
        self._redis = None

    async def connect(self):
        try:
            self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            await self._redis.ping()
            logger.info(f"Redis connected ({REDIS_URL}), limit={RATE_LIMIT} req/{RATE_WINDOW}s")
        except Exception as e:
            logger.warning(f"Redis unavailable: {e} — rate limiting disabled")
            self._redis = None

    async def close(self):
        if self._redis:
            await self._redis.aclose()

    async def check(self, ip):
        if not self._redis:
            return True, 0

        key = f"rate:{ip}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, RATE_WINDOW)
            return count <= RATE_LIMIT, count
        except Exception as e:
            logger.error(f"Redis error: {e}")
            return True, 0


rate_limiter = RateLimiter()
