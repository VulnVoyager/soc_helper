import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")

ALLOWED_USER_IDS = set(map(int, os.getenv("ALLOWED_USER_IDS", "").split(","))) if os.getenv("ALLOWED_USER_IDS") else None
