import json
import os
from pathlib import Path
from models import EngineConfig, OfferConfig

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
OFFERS_FILE = BASE_DIR / "offers.json"


class ConfigStore:
    def __init__(self):
        self.engine: EngineConfig = EngineConfig()
        self.offers: OfferConfig = OfferConfig()

    def load(self):
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            self.engine = EngineConfig(**data)
        else:
            self.save_engine()

        if OFFERS_FILE.exists():
            data = json.loads(OFFERS_FILE.read_text(encoding="utf-8"))
            self.offers = OfferConfig(**data)
        else:
            self.save_offers()

    def save_engine(self):
        CONFIG_FILE.write_text(
            self.engine.model_dump_json(indent=2), encoding="utf-8"
        )

    def save_offers(self):
        OFFERS_FILE.write_text(
            self.offers.model_dump_json(indent=2), encoding="utf-8"
        )

    def update_engine(self, config: EngineConfig):
        self.engine = config
        self.save_engine()

    def update_offers(self, config: OfferConfig):
        self.offers = config
        self.save_offers()


config_store = ConfigStore()
