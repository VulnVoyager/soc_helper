from .virustotal import VirusTotalIntegration
from .abuseipdb import AbuseIPDBIntegration
from .shodan import ShodanIntegration
from .otx import OTXIntegration
from .ipinfo import IPInfoIntegration
from .urlhaus import URLHausIntegration
from .greynoise import GreyNoiseIntegration

def get_integrations():
    integrations = []
    from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY

    if VIRUSTOTAL_API_KEY:
        integrations.append(VirusTotalIntegration())
    if ABUSEIPDB_API_KEY:
        integrations.append(AbuseIPDBIntegration())
    if SHODAN_API_KEY:
        integrations.append(ShodanIntegration())

    # Бесплатные/безключевые
    integrations.append(OTXIntegration())
    integrations.append(IPInfoIntegration())
    integrations.append(URLHausIntegration())
    integrations.append(GreyNoiseIntegration())

    return integrations
