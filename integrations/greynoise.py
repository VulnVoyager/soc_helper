import aiohttp
from .base import Integration
from config import GREYNOISE_API_KEY
from typing import Dict, Any

class GreyNoiseIntegration(Integration):
    name = "GreyNoise"
    COMMUNITY_URL = "https://api.greynoise.io/v3/community/"

    async def analyze(self, indicator: str, indicator_type: str) -> Dict[str, Any] | None:
        if indicator_type != "ip":
            return None

        headers = {
            "User-Agent": "SOC-Helper-Bot (https://github.com/yourname/soc_helper_bot)"
        }

        url = f"{self.COMMUNITY_URL}{indicator}"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, timeout=8) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 404:
                        return {"ip": indicator, "noise": False}
                    elif resp.status == 429:
                        return {"error": "Лимит запросов (Community API)"}
                    else:
                        return {"error": f"HTTP {resp.status}"}
            except Exception as e:
                return {"error": f"Сетевая ошибка: {str(e)}"}

    def _format(self, data: Dict[str, Any]) -> str:
        if "error" in data:
            return f"• {data['error']}"

        if data.get("noise") is False:
            return "• 🟢 Не в базе GreyNoise (обычный трафик)"

        classification = data.get("classification", "unknown").title()
        name = data.get("name", "–")
        last_seen = data.get("last_seen", "–")
        link = f"https://www.greynoise.io/viz/ip/{data.get('ip', '')}"

        return (
            f"• Класс: *{classification}*\n"
            f"• Источник: {name}\n"
            f"• Последнее: {last_seen}\n"
            f"• [Подробнее]({link})"
        )
