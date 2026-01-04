from typing import List, Dict, Any

def assess_risk(indicator_type: str, results: List[Dict[str, Any]]) -> str:
    """
    Оценивает общий риск на основе результатов интеграций.
    Возвращает: "🟢 Низкий", "🟡 Средний", "🔴 Высокий"
    """
    malicious_votes = 0
    threat_mentions = 0
    abuse_reports = 0

    for result in results:
        source = result.get("source", "")
        data = result.get("data", {})

        if source == "VirusTotal":
            if "error" not in data and data.get("query_status") != "error":
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    malicious_votes += 1

        elif source == "AlienVault OTX":
            if "error" not in data:
                pulses = data.get("pulse_info", {}).get("count", 0)
                if pulses > 0:
                    threat_mentions += 1

        elif source == "AbuseIPDB":
            if "error" not in data:
                reports = data.get("data", {}).get("totalReports", 0)
                if reports > 0:
                    abuse_reports += 1

        elif source == "GreyNoise":
            if "error" not in data:
                if data.get("noise") is True:
                    threat_mentions += 1
                if data.get("classification", "").lower() == "malicious":
                    malicious_votes += 1

    high_indicators = 0
    medium_indicators = 0

    if malicious_votes > 0:
        high_indicators += 1
    if threat_mentions > 0:
        medium_indicators += 1
    if abuse_reports > 0:
        medium_indicators += 1

    if high_indicators >= 1 and medium_indicators >= 1:
        return "🔴 Высокий"
    elif high_indicators >= 1 or medium_indicators >= 2:
        return "🟡 Средний"
    else:
        return "🟢 Низкий"
