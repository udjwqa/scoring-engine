import os
import logging
import httpx
from fastapi import APIRouter

logger = logging.getLogger("cf_sync")

router = APIRouter()

CF_API_TOKEN = os.getenv("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID", "")
CF_KV_NAMESPACE_ID = os.getenv("CF_KV_NAMESPACE_ID", "")

CF_API_BASE = "https://api.cloudflare.com/client/v4"


async def put_kv(key, value):
    if not CF_API_TOKEN or not CF_ACCOUNT_ID or not CF_KV_NAMESPACE_ID:
        logger.warning("CF credentials not set, skipping KV sync")
        return False

    url = f"{CF_API_BASE}/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{CF_KV_NAMESPACE_ID}/values/{key}"
    async with httpx.AsyncClient() as client:
        resp = await client.put(
            url,
            content=value,
            headers={
                "Authorization": f"Bearer {CF_API_TOKEN}",
                "Content-Type": "text/plain",
            },
        )
        if resp.status_code == 200:
            logger.info(f"KV updated: {key}")
            return True
        else:
            logger.error(f"KV update failed: {key} → {resp.status_code} {resp.text}")
            return False


@router.put("/api/cf/sync")
async def sync_to_cloudflare():
    from config import config_store
    from lists_manager import lists_manager

    results = {}

    countries = lists_manager.get_list("countries_block")
    if countries:
        ok = await put_kv("BLOCKED_COUNTRIES", ",".join(countries.items))
        results["countries"] = ok

    ua = lists_manager.get_list("user_agents_block")
    if ua:
        ok = await put_kv("BLOCKED_UA", ",".join(ua.items))
        results["user_agents"] = ok

    offers = config_store.offers
    ok = await put_kv("SAFE_URL", offers.safeUrl)
    results["safe_url"] = ok

    ok = await put_kv("WHITE_FLOW_TYPE", offers.whiteFlowType)
    results["white_flow_type"] = ok

    if not CF_API_TOKEN:
        return {
            "synced": False,
            "message": "CF_API_TOKEN not configured. Set in .env to enable sync.",
            "results": results,
        }

    return {"synced": True, "results": results}


@router.put("/api/cf/panic")
async def set_panic_mode(enabled: bool = True):
    ok = await put_kv("PANIC_MODE", "true" if enabled else "false")
    return {"success": ok, "panic_mode": enabled}
