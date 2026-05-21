from fastapi import APIRouter
from models import EngineConfig, OfferConfig
from config import config_store

router = APIRouter()


@router.get("/api/config")
async def get_config() -> EngineConfig:
    return config_store.engine


@router.put("/api/config")
async def update_config(config: EngineConfig):
    config_store.update_engine(config)
    return {"success": True}


@router.get("/api/offers")
async def get_offers() -> OfferConfig:
    return config_store.offers


@router.put("/api/offers")
async def update_offers(config: OfferConfig):
    config_store.update_offers(config)
    return {"success": True}
