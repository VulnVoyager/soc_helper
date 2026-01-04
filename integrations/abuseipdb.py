import aiohttp
from .base import Integration
from config import ABUSEIPDB_API_KEY

class AbuseIPDBIntegration(Integration):
    name = "AbuseIPDB"
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    async def analyze(self, indicator: str, indicator_type: str) -> dict | None:
        if not ABUSEIPDB_API_KEY or indicator_type != "ip":
            return None

        params = {"ipAddress": indicator, "maxAgeInDays": 90}
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.BASE_URL, headers=headers, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
            except Exception:
                return None

    def _format(self, data: dict) -> str:
        data = data.get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country = data.get("countryName", "N/A")
        isp = data.get("isp", "N/A")

        status = "🔴 Высокий риск" if abuse_score > 70 else "🟡 Средний" if abuse_score > 30 else "🟢 Низкий"

        return (
            f"• Доверие: *{abuse_score}%* ({status})\n"
            f"• Жалоб: *{total_reports}*\n"
            f"• Страна: {country}\n"
            f"• Провайдер: {isp}"
        )
