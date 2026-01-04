import aiohttp
from .base import Integration
from config import VIRUSTOTAL_API_KEY
from typing import Dict, Any, Optional

class VirusTotalIntegration(Integration):
    name = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    async def analyze(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        if not VIRUSTOTAL_API_KEY:
            return {"error": "API-ключ VirusTotal не задан"}

        endpoint_map = {
            "ip": f"ip_addresses/{indicator}",
            "domain": f"domains/{indicator}",
            "url": f"urls/{indicator.replace('/', '_')}",
            "hash": f"files/{indicator}"
        }
        endpoint = endpoint_map.get(indicator_type)
        if not endpoint:
            return {"error": "Тип индикатора не поддерживается"}

        url = f"{self.BASE_URL}/{endpoint}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 403:
                        return {"error": "Неверный API-ключ или исчерпан лимит"}
                    elif resp.status == 404:
                        return {"error": "Индикатор не найден в VirusTotal"}
                    else:
                        return {"error": f"Ошибка API: {resp.status}"}
            except Exception as e:
                return {"error": f"Сетевая ошибка: {str(e)}"}

    def _format(self, data: Dict[str, Any]) -> str: 
        if "error" in data:
            return f"• {data['error']}"

        vt_data = data.get("data", {})
        attrs = vt_data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else "N/A"
        reputation = attrs.get("reputation", 0)

        lines = [f"• Зловредных: *{malicious}/{total}*"]
        if reputation != 0:
            lines.append(f"• Репутация: *{reputation}*")

        indicator_id = vt_data.get("id", "").strip()
        indicator_type = vt_data.get("type", "")
        report_url = ""
        if indicator_id:
            if indicator_type == "ip_address":
                report_url = f"https://www.virustotal.com/gui/ip-address/{indicator_id}"
            elif indicator_type == "domain":
                report_url = f"https://www.virustotal.com/gui/domain/{indicator_id}"
            elif indicator_type == "file":
                report_url = f"https://www.virustotal.com/gui/file/{indicator_id}"
            elif indicator_type == "url":
                report_url = f"https://www.virustotal.com/gui/search?query={indicator_id}"

        if report_url:
            lines.append(f"• [Полный отчёт]({report_url})")

        return "\n".join(lines)
