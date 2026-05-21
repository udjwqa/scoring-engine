import logging
from typing import Optional
from models import ScoringResult, ScoringDetail
from config import config_store
from lists_manager import lists_manager
from external.ipinfo_client import ipinfo_client
from external.ipqs_client import ipqs_client

logger = logging.getLogger("scoring")

AUTOBAN_SCORE = 100


class ScoringEngine:

    async def score_request(
        self,
        user_agent: str = "",
        accept_language: str = "",
        client_secret: Optional[str] = None,
        device_model: str = "",
        device_codename: str = "",
        gpu_renderer: str = "",
        country: str = "",
        city: str = "",
        isp: str = "",
        ip: str = "",
    ) -> ScoringResult:
        cfg = config_store.engine
        details = []
        total = 0
        rejection_code = None

        # === БЛОК 1: Статические заголовки ===

        if not client_secret:
            pts = AUTOBAN_SCORE
            total += pts
            rejection_code = rejection_code or "no_client_secret"
            details.append(ScoringDetail(
                check="client_secret", points=pts,
                reason="Отсутствует X-Client-Secret заголовок",
            ))

        if user_agent:
            ua_lower = user_agent.lower()
            ua_list = lists_manager.get_list("user_agents_block")
            if ua_list:
                for bot in ua_list.items:
                    if bot.lower() in ua_lower:
                        pts = AUTOBAN_SCORE
                        total += pts
                        rejection_code = rejection_code or "bot_user_agent"
                        details.append(ScoringDetail(
                            check="user_agent_block", points=pts,
                            reason=f"User-Agent содержит '{bot}'",
                        ))
                        break

        if accept_language:
            primary_lang = accept_language.split(",")[0].strip().lower()
            if primary_lang.startswith("en"):
                pts = cfg.weights.englishWebView
                total += pts
                details.append(ScoringDetail(
                    check="english_language", points=pts,
                    reason=f"Первичный язык: {primary_lang}",
                ))

        if device_model:
            dm_list = lists_manager.get_list("device_models_block")
            if dm_list:
                for model in dm_list.items:
                    if model.lower() in device_model.lower():
                        pts = 40
                        total += pts
                        rejection_code = rejection_code or "device_blocked"
                        details.append(ScoringDetail(
                            check="device_model_block", points=pts,
                            reason=f"Модель '{device_model}' совпала с '{model}'",
                        ))
                        break

        if device_codename:
            if lists_manager.lookup("codenames_block", device_codename):
                pts = AUTOBAN_SCORE
                total += pts
                rejection_code = rejection_code or "emulator_detected"
                details.append(ScoringDetail(
                    check="codename_block", points=pts,
                    reason=f"Кодовое имя '{device_codename}' — эмулятор",
                ))

        if gpu_renderer:
            gpu_list = lists_manager.get_list("gpu_block")
            if gpu_list:
                gpu_lower = gpu_renderer.lower()
                for gpu in gpu_list.items:
                    if gpu.lower() in gpu_lower:
                        pts = AUTOBAN_SCORE
                        total += pts
                        rejection_code = rejection_code or "emulator_gpu"
                        details.append(ScoringDetail(
                            check="gpu_block", points=pts,
                            reason=f"GPU '{gpu_renderer}' — эмулятор ({gpu})",
                        ))
                        break

        # === БЛОК 2: Внешние API (IPinfo + IPQS) ===

        effective_country = country
        effective_city = city
        effective_isp = isp

        ipinfo_data = await ipinfo_client.lookup(ip)
        if ipinfo_data:
            effective_country = ipinfo_data.country or effective_country
            effective_city = ipinfo_data.city or effective_city
            effective_isp = ipinfo_data.isp or effective_isp

            if ipinfo_data.vpn:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "vpn_detected"
                details.append(ScoringDetail(
                    check="ipinfo_vpn", points=pts,
                    reason=f"IPinfo: VPN обнаружен ({ip})",
                ))

            if ipinfo_data.proxy:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "proxy_detected"
                details.append(ScoringDetail(
                    check="ipinfo_proxy", points=pts,
                    reason=f"IPinfo: Proxy обнаружен ({ip})",
                ))

            if ipinfo_data.tor:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "tor_detected"
                details.append(ScoringDetail(
                    check="ipinfo_tor", points=pts,
                    reason=f"IPinfo: Tor обнаружен ({ip})",
                ))

            if ipinfo_data.hosting:
                pts = cfg.weights.suspiciousHosting
                total += pts
                rejection_code = rejection_code or "suspicious_hosting"
                details.append(ScoringDetail(
                    check="ipinfo_hosting", points=pts,
                    reason=f"IPinfo: Hosting IP ({ipinfo_data.org})",
                ))

        ipqs_data = await ipqs_client.lookup(ip)
        if ipqs_data and ipqs_data.success:
            if ipqs_data.fraud_score > 75:
                pts = 50
                total += pts
                rejection_code = rejection_code or "ipqs_high_fraud"
                details.append(ScoringDetail(
                    check="ipqs_fraud_score", points=pts,
                    reason=f"IPQS fraud_score={ipqs_data.fraud_score}",
                ))

            if ipqs_data.vpn or ipqs_data.proxy or ipqs_data.tor:
                flags = []
                if ipqs_data.vpn:
                    flags.append("VPN")
                if ipqs_data.proxy:
                    flags.append("Proxy")
                if ipqs_data.tor:
                    flags.append("Tor")
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "vpn_detected"
                details.append(ScoringDetail(
                    check="ipqs_vpn_proxy", points=pts,
                    reason=f"IPQS: {', '.join(flags)} обнаружен",
                ))

            if ipqs_data.bot_status:
                pts = AUTOBAN_SCORE
                total += pts
                rejection_code = rejection_code or "bot_detected"
                details.append(ScoringDetail(
                    check="ipqs_bot", points=pts,
                    reason="IPQS: bot_status=true",
                ))

        # === БЛОК 3: Гео-проверки ===

        if effective_country:
            if lists_manager.lookup("countries_block", effective_country.upper()):
                pts = AUTOBAN_SCORE
                total += pts
                rejection_code = rejection_code or "country_blocked"
                details.append(ScoringDetail(
                    check="country_block", points=pts,
                    reason=f"Страна '{effective_country}' в чёрном списке",
                ))

        if effective_city:
            cities_list = lists_manager.get_list("cities_block")
            if cities_list:
                for c in cities_list.items:
                    if c.lower() == effective_city.lower():
                        pts = cfg.weights.suspiciousCity
                        total += pts
                        details.append(ScoringDetail(
                            check="city_block", points=pts,
                            reason=f"Город '{effective_city}' — город модерации",
                        ))
                        break

        if effective_isp:
            isp_list = lists_manager.get_list("isp_block")
            if isp_list:
                isp_lower = effective_isp.lower()
                for provider in isp_list.items:
                    if provider.lower() in isp_lower:
                        pts = cfg.weights.suspiciousHosting
                        total += pts
                        rejection_code = rejection_code or "suspicious_hosting"
                        details.append(ScoringDetail(
                            check="isp_block", points=pts,
                            reason=f"ISP '{effective_isp}' — подозрительный ({provider})",
                        ))
                        break

        # === Финальный вердикт ===
        threshold = cfg.scoreThreshold
        verdict = "white" if total >= threshold else "grey"

        if verdict == "grey":
            rejection_code = None

        logger.info(
            f"[{ip}] score={total} threshold={threshold} verdict={verdict} "
            f"rejection={rejection_code} checks={len(details)}"
        )

        return ScoringResult(
            score=total,
            verdict=verdict,
            rejectionCode=rejection_code,
            details=details,
        )


scoring_engine = ScoringEngine()
