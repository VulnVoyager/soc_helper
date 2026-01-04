import aiohttp
from .base import Integration
from config import SHODAN_API_KEY

class ShodanIntegration(Integration):
    name = "Shodan"
    BASE_URL = "https://api.shodan.io/shodan/host"

    async def analyze(self, indicator: str, indicator_type: str) -> dict | None:
        if not SHODAN_API_KEY or indicator_type != "ip":
            return None

        url = f"{self.BASE_URL}/{indicator}"
        params = {"key": SHODAN_API_KEY}

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
            except Exception:
                return None

    def _format(self, data: dict) -> str:
        ip = data.get("ip_str", "N/A")
        os = data.get("os", "Unknown")
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        isp = data.get("isp", "N/A")

        msg = f"• ОС: {os}\n"
        msg += f"• Провайдер: {isp}\n"
        if ports:
            msg += f"• Открытые порты: `{', '.join(map(str, ports))}`\n"
        if hostnames:
            msg += f"• Хосты: {', '.join(hostnames)}\n"
        msg += f"• [Просмотр в Shodan](https://www.shodan.io/host/{ip})"
        return msg
