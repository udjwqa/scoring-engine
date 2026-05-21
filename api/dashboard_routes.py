from fastapi import APIRouter
from request_logger import request_logger

router = APIRouter()


@router.get("/api/dashboard/metrics")
async def get_metrics():
    return await request_logger.get_metrics()


@router.get("/api/dashboard/feed")
async def get_feed(limit: int = 50):
    return request_logger.get_recent(min(limit, 200))


@router.get("/api/dashboard/rejections")
async def get_rejections():
    return await request_logger.get_rejections()
