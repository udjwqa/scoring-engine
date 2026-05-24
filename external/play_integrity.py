import os
import json
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger("play_integrity")

GCP_KEY_PATH = os.getenv("GCP_KEY_PATH", "config/gcp-key.json")
PACKAGE_NAME = os.getenv("PACKAGE_NAME", "")


class IntegrityVerdict:
    def __init__(self, data):
        self.raw = data

        token_info = data.get("tokenPayloadExternal", {})

        req = token_info.get("requestDetails", {})
        self.package_name = req.get("requestPackageName", "")
        self.nonce = req.get("nonce", "")
        self.timestamp_millis = req.get("timestampMillis", "0")

        app = token_info.get("appIntegrity", {})
        self.app_recognition = app.get("appRecognitionVerdict", "UNEVALUATED")
        self.certificate_sha256 = app.get("certificateSha256Digest", [])
        self.version_code = app.get("versionCode", "")

        device = token_info.get("deviceIntegrity", {})
        self.device_recognition = device.get("deviceRecognitionVerdict", [])

        account = token_info.get("accountDetails", {})
        self.app_licensing = account.get("appLicensingVerdict", "UNEVALUATED")

    @property
    def meets_basic(self):
        return "MEETS_BASIC_INTEGRITY" in self.device_recognition

    @property
    def meets_device(self):
        return "MEETS_DEVICE_INTEGRITY" in self.device_recognition

    @property
    def meets_strong(self):
        return "MEETS_STRONG_INTEGRITY" in self.device_recognition

    @property
    def is_virtual_only(self):
        return (
            "MEETS_VIRTUAL_INTEGRITY" in self.device_recognition
            and "MEETS_DEVICE_INTEGRITY" not in self.device_recognition
            and "MEETS_STRONG_INTEGRITY" not in self.device_recognition
        )

    @property
    def is_empty_device(self):
        return len(self.device_recognition) == 0

    @property
    def is_recognized_app(self):
        return self.app_recognition == "PLAY_RECOGNIZED"

    @property
    def is_licensed(self):
        return self.app_licensing == "LICENSED"


class PlayIntegrityClient:
    def __init__(self):
        self._service = None
        self._available = False

    def init(self):
        key_path = Path(GCP_KEY_PATH)
        if not key_path.exists():
            logger.warning(f"GCP key not found at {GCP_KEY_PATH} — Play Integrity disabled")
            return

        if not PACKAGE_NAME:
            logger.warning("PACKAGE_NAME not set — Play Integrity disabled")
            return

        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            credentials = service_account.Credentials.from_service_account_file(
                str(key_path),
                scopes=["https://www.googleapis.com/auth/playintegrity"],
            )
            self._service = build("playintegrity", "v1", credentials=credentials)
            self._available = True
            logger.info(f"Play Integrity API initialized (package={PACKAGE_NAME})")
        except Exception as e:
            logger.error(f"Play Integrity init failed: {e}")

    @property
    def available(self):
        return self._available

    async def verify_token(self, integrity_token: str) -> Optional[IntegrityVerdict]:
        if not self._available or not self._service:
            logger.debug("Play Integrity not available, skipping verification")
            return None

        try:
            import asyncio
            loop = asyncio.get_event_loop()

            def _decode():
                return self._service.v1().decodeIntegrityToken(
                    packageName=PACKAGE_NAME,
                    body={"integrityToken": integrity_token},
                ).execute()

            result = await loop.run_in_executor(None, _decode)
            verdict = IntegrityVerdict(result)

            logger.info(
                f"Integrity: app={verdict.app_recognition} "
                f"device={verdict.device_recognition} "
                f"license={verdict.app_licensing}"
            )
            return verdict

        except Exception as e:
            logger.error(f"Play Integrity verify failed: {e}")
            return None


play_integrity_client = PlayIntegrityClient()
