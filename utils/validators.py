import re
import validators

def is_ip(ip: str) -> bool:
    return bool(validators.ipv4(ip) or validators.ipv6(ip))

def is_domain(domain: str) -> bool:
    return bool(validators.domain(domain))

def is_hash(h: str) -> bool:
    h = h.lower()
    return bool(re.fullmatch(r"[a-f0-9]{32}", h) or      # MD5
                re.fullmatch(r"[a-f0-9]{40}", h) or      # SHA1
                re.fullmatch(r"[a-f0-9]{64}", h))        # SHA256

def is_url(u: str) -> bool:
    return bool(validators.url(u))
