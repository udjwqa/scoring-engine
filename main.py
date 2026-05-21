from dotenv import load_dotenv
load_dotenv()

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import config_store
from lists_manager import lists_manager
from api.health import router as health_router
from api.config_routes import router as config_router
from api.lists_routes import router as lists_router
from api.gateway import router as gateway_router
from api.dashboard_routes import router as dashboard_router
from api.audit_routes import router as audit_router
from database import init_db
from external.ipinfo_client import ipinfo_client
from external.ipqs_client import ipqs_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting server...")
    config_store.load()
    logger.info(f"Config loaded (scoreThreshold={config_store.engine.scoreThreshold})")
    await init_db()
    await lists_manager.load_all()
    await lists_manager.start_watcher(interval=5)
    logger.info("Server ready")
    yield
    lists_manager.stop_watcher()
    await ipinfo_client.close()
    await ipqs_client.close()
    logger.info("Server stopped")


app = FastAPI(
    title="APK Traffic Scoring Engine",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3333",
        "http://31.76.251.103",
        "http://31.76.251.103:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(config_router)
app.include_router(lists_router)
app.include_router(dashboard_router)
app.include_router(audit_router)
app.include_router(gateway_router)
