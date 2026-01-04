import aiohttp
from .base import Integration
from utils.validators import is_url

class URLHausIntegration(Integration):
    name = "URLhaus"
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    async def analyze(self, indicator: str, indicator_type: str) -> dict | None:
        async with aiohttp.ClientSession() as session:
            try:
                if indicator_type == "url":
                    payload = {"url": indicator}
                    api_endpoint = f"{self.BASE_URL}/url/"
                elif indicator_type == "domain":
                    payload = {"host": indicator}
                    api_endpoint = f"{self.BASE_URL}/host/"
                else:
                    return None

                async with session.post(api_endpoint, data=payload, timeout=10) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
            except Exception:
                return None

    def _format(self, data: dict) -> str:
        if data.get("query_status") in ("no_results", "invalid_host"):
            return "• Не найдено в URLhaus"

        if "url" in data:
            status = "🔴 Активен" if data.get("url_status") == "online" else "🟠 Оффлайн"
            tags = ", ".join(data.get("tags", [])) or "–"
            return f"• Статус: {status}\n• Теги: {tags}\n• [Отчёт]({data.get('urlhaus_link', '')})"

        if "host" in data:
            urls_count = data.get("url_count", 0)
            if urls_count == 0:
                return "• Не связан с вредоносными URL"
            return f"• Связан с *{urls_count}* вредоносными URL\n• [Отчёт](https://urlhaus.abuse.ch/host/{data['host']}/)"

        return "• Данные недоступны"
