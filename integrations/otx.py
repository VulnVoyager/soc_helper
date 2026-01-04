import aiohttp
from .base import Integration

class OTXIntegration(Integration):
    name = "AlienVault OTX"
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    async def analyze(self, indicator: str, indicator_type: str) -> dict | None:
        otx_type_map = {
            "ip": "IPv4",
            "domain": "domain",
            "hash": "file",
            "url": "url"
        }

        otx_type = otx_type_map.get(indicator_type)
        if not otx_type:
            return {"error": "Тип индикатора не поддерживается"}

        url = f"{self.BASE_URL}/{otx_type}/{indicator}/general"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 404:
                        return {"error": "Индикатор не найден в OTX"}
                    else:
                        return {"error": f"Ошибка API: {resp.status}"}
            except Exception as e:
                return {"error": f"Сетевая ошибка: {str(e)}"}

    def _format(self, data: dict) -> str:
        if "error" in data:
            return f"• {data['error']}"

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count == 0:
            return "• Не упоминается в пульсах угроз"

        indicator_type = data.get("type")
        indicator_value = data.get("indicator")

        if indicator_type and indicator_value:
            link = f"https://otx.alienvault.com/indicator/{indicator_type}/{indicator_value}"
            return (
                f"• Упомянут в *{pulse_count}* пульсах угроз\n"
                f"• [Полный отчёт]({link})"
            )
        else:
            return f"• Упомянут в *{pulse_count}* пульсах угроз (ссылка недоступна)"
