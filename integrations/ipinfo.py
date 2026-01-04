import aiohttp
from .base import Integration

class IPInfoIntegration(Integration):
    name = "IPinfo"
    BASE_URL = "https://ipinfo.io"

    async def analyze(self, indicator: str, indicator_type: str) -> dict | None:
        if indicator_type not in ("ip", "domain"):
            return None

        url = f"{self.BASE_URL}/{indicator}/json"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, timeout=8) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
            except Exception:
                return None

    def _format(self, data: dict) -> str:
        if "error" in data:
            return "• Недоступно"

        ip = data.get("ip", "N/A")
        city = data.get("city", "–")
        region = data.get("region", "–")
        country = data.get("country", "–")
        org = data.get("org", "–")
        loc = data.get("loc", None)

        msg = f"• Локация: {city}, {region}, {country}\n"
        msg += f"• Организация: {org}"
        if loc:
            lat, lon = loc.split(",")
            msg += f"\n• [Карта](https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=10)"
        return msg
