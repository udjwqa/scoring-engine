import os
import time
import logging
import httpx
from typing import Optional, Dict, Any

logger = logging.getLogger("ipinfo")

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
CACHE_TTL = int(os.getenv("IPINFO_CACHE_TTL_SECONDS", "86400"))
TIMEOUT = int(os.getenv("IPINFO_REQUEST_TIMEOUT_SECONDS", "5"))
FAIL_OPEN = os.getenv("IPINFO_FAIL_OPEN", "true").lower() == "true"


class IPInfoResult:
    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.ip = data.get("ip", "")
        self.country = data.get("country", "")
        self.city = data.get("city", "")
        self.region = data.get("region", "")
        self.org = data.get("org", "")
        self.timezone = data.get("timezone", "")

        privacy = data.get("privacy", {})
        self.vpn = privacy.get("vpn", False)
        self.proxy = privacy.get("proxy", False)
        self.hosting = privacy.get("hosting", False)
        self.relay = privacy.get("relay", False)
        self.tor = privacy.get("tor", False)

    @property
    def isp(self) -> str:
        org = self.org
        if org and " " in org:
            return org.split(" ", 1)[1]
        return org


class IPInfoClient:
    def __init__(self):
        self._cache: Dict[str, tuple] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=TIMEOUT)
        return self._client

    def _cache_get(self, ip: str) -> Optional[IPInfoResult]:
        entry = self._cache.get(ip)
        if entry is None:
            return None
        result, ts = entry
        if time.time() - ts > CACHE_TTL:
            del self._cache[ip]
            return None
        return result

    def _cache_set(self, ip: str, result: IPInfoResult):
        self._cache[ip] = (result, time.time())
        if len(self._cache) > 10000:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

    async def lookup(self, ip: str) -> Optional[IPInfoResult]:
        if not IPINFO_TOKEN:
            logger.debug("No IPINFO_TOKEN, skipping lookup")
            return None

        if ip in ("127.0.0.1", "0.0.0.0", "::1", "localhost"):
            return None

        cached = self._cache_get(ip)
        if cached:
            logger.debug(f"Cache hit for {ip}")
            return cached

        try:
            client = await self._get_client()
            resp = await client.get(
                f"https://ipinfo.io/{ip}",
                params={"token": IPINFO_TOKEN},
            )
            resp.raise_for_status()
            data = resp.json()

            result = IPInfoResult(data)
            self._cache_set(ip, result)
            logger.info(
                f"IPinfo {ip}: country={result.country} city={result.city} "
                f"vpn={result.vpn} proxy={result.proxy} hosting={result.hosting} "
                f"org={result.org}"
            )
            return result

        except Exception as e:
            logger.warning(f"IPinfo lookup failed for {ip}: {e}")
            if FAIL_OPEN:
                return None
            return IPInfoResult({"privacy": {"vpn": True}})

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


ipinfo_client = IPInfoClient()
