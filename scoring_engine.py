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


    async def score_js_metrics(self, data: dict, ip: str = "") -> ScoringResult:
        from external.timezone_utils import compare_timezones

        cfg = config_store.engine
        details = []
        total = 0
        rejection_code = None

        MOTION_THRESHOLD = 0.08

        # 1. WebGL — renderer + vendor через стоп-лист
        webgl = data.get("webgl", {})
        renderer = webgl.get("renderer", "")
        vendor = webgl.get("vendor", "")
        webgl_combined = f"{vendor} {renderer}".lower()
        if webgl_combined.strip():
            gpu_list = lists_manager.get_list("gpu_block")
            if gpu_list:
                for gpu in gpu_list.items:
                    if gpu.lower() in webgl_combined:
                        pts = AUTOBAN_SCORE
                        total += pts
                        rejection_code = rejection_code or "emulator_gpu"
                        details.append(ScoringDetail(
                            check="js_webgl_gpu", points=pts,
                            reason=f"WebGL '{renderer}' (vendor: {vendor}) — эмулятор ({gpu})",
                        ))
                        break

        # 2. Акселерометр — static_device (< 0.08 m/s²)
        accel = data.get("accelerometer", {})
        avg_deviation = accel.get("averageDeviation", -1)
        samples = accel.get("samples", 0)
        if samples > 0 and 0 <= avg_deviation < MOTION_THRESHOLD:
            pts = cfg.weights.mouseWithoutTouch
            total += pts
            rejection_code = rejection_code or "static_device"
            details.append(ScoringDetail(
                check="js_static_device", points=pts,
                reason=f"Акселерометр: deviation={avg_deviation} m/s² < {MOTION_THRESHOLD} "
                       f"({samples} samples) — статичное устройство/эмулятор",
            ))

        # 3. Мышь без тача
        input_data = data.get("input", {})
        mouse = input_data.get("mouseClicks", 0)
        touch_events = input_data.get("touchEvents", 0)
        if mouse > 0 and touch_events == 0:
            pts = cfg.weights.mouseWithoutTouch
            total += pts
            rejection_code = rejection_code or "mouse_without_touch"
            details.append(ScoringDetail(
                check="js_mouse_no_touch", points=pts,
                reason=f"Клики мышью ({mouse}) без тач-событий",
            ))

        # 4. Батарея фейковая
        battery = data.get("battery", {})
        level = battery.get("level")
        charging_time = battery.get("chargingTime")
        if level is not None and level == 1.0 and charging_time == 0:
            pts = 50
            total += pts
            rejection_code = rejection_code or "emulator_battery"
            details.append(ScoringDetail(
                check="js_fake_battery", points=pts,
                reason="Батарея: level=100%, chargingTime=0 — паттерн эмулятора",
            ))

        # 5. IPinfo: гео-проверки (country/city/ISP) + таймзона
        js_tz = data.get("timezone", "")
        ipinfo_data = await ipinfo_client.lookup(ip)

        if ipinfo_data:
            # Country block
            if ipinfo_data.country:
                if lists_manager.lookup("countries_block", ipinfo_data.country.upper()):
                    pts = AUTOBAN_SCORE
                    total += pts
                    rejection_code = rejection_code or "country_blocked"
                    details.append(ScoringDetail(
                        check="js_country_block", points=pts,
                        reason=f"Страна '{ipinfo_data.country}' в чёрном списке (IPinfo)",
                    ))

            # City block
            if ipinfo_data.city:
                cities_list = lists_manager.get_list("cities_block")
                if cities_list:
                    for c in cities_list.items:
                        if c.lower() == ipinfo_data.city.lower():
                            pts = cfg.weights.suspiciousCity
                            total += pts
                            details.append(ScoringDetail(
                                check="js_city_block", points=pts,
                                reason=f"Город '{ipinfo_data.city}' — город модерации (IPinfo)",
                            ))
                            break

            # ISP block
            if ipinfo_data.isp:
                isp_list = lists_manager.get_list("isp_block")
                if isp_list:
                    isp_lower = ipinfo_data.isp.lower()
                    for provider in isp_list.items:
                        if provider.lower() in isp_lower:
                            pts = cfg.weights.suspiciousHosting
                            total += pts
                            rejection_code = rejection_code or "suspicious_hosting"
                            details.append(ScoringDetail(
                                check="js_isp_block", points=pts,
                                reason=f"ISP '{ipinfo_data.isp}' — подозрительный (IPinfo)",
                            ))
                            break

            # VPN/Proxy/Hosting
            if ipinfo_data.vpn:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "vpn_detected"
                details.append(ScoringDetail(
                    check="js_ipinfo_vpn", points=pts,
                    reason=f"IPinfo: VPN обнаружен ({ip})",
                ))
            if ipinfo_data.proxy:
                pts = cfg.weights.vpnProxyTor
                total += pts
                rejection_code = rejection_code or "proxy_detected"
                details.append(ScoringDetail(
                    check="js_ipinfo_proxy", points=pts,
                    reason=f"IPinfo: Proxy обнаружен ({ip})",
                ))
            if ipinfo_data.hosting:
                pts = cfg.weights.suspiciousHosting
                total += pts
                rejection_code = rejection_code or "suspicious_hosting"
                details.append(ScoringDetail(
                    check="js_ipinfo_hosting", points=pts,
                    reason=f"IPinfo: Hosting IP ({ipinfo_data.org})",
                ))

        # Timezone comparison
        if js_tz:
            ip_tz = ipinfo_data.timezone if ipinfo_data else ""

            if ip_tz:
                tz_diff = compare_timezones(js_tz, ip_tz)
                tolerance = cfg.timezoneDriftHours
                if tz_diff > tolerance:
                    pts = cfg.weights.timezoneMismatch
                    total += pts
                    rejection_code = rejection_code or "timezone_mismatch"
                    details.append(ScoringDetail(
                        check="js_timezone_mismatch", points=pts,
                        reason=f"Таймзона JS={js_tz} vs IP={ip_tz}, "
                               f"разница {tz_diff:.1f}ч > допуск {tolerance}ч",
                    ))
            else:
                known_suspicious = ["Etc/UTC", "UTC", "Etc/GMT"]
                if js_tz in known_suspicious:
                    pts = cfg.weights.timezoneMismatch
                    total += pts
                    details.append(ScoringDetail(
                        check="js_timezone_suspicious", points=pts,
                        reason=f"Подозрительная таймзона: {js_tz}",
                    ))

        # 6. Touch не поддерживается
        touch_supported = input_data.get("touchSupported", True)
        if not touch_supported:
            pts = 20
            total += pts
            details.append(ScoringDetail(
                check="js_no_touch_support", points=pts,
                reason="Устройство не поддерживает тач (десктоп/эмулятор)",
            ))

        threshold = cfg.scoreThreshold
        verdict = "white" if total >= threshold else "grey"
        if verdict == "grey":
            rejection_code = None

        logger.info(
            f"[{ip}] JS score={total} threshold={threshold} verdict={verdict} "
            f"checks={len(details)}"
        )

        return ScoringResult(
            score=total,
            verdict=verdict,
            rejectionCode=rejection_code,
            details=details,
        )


scoring_engine = ScoringEngine()
