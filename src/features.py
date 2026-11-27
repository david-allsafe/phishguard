"""TAR02 (P1) - Extração de features de um URL.

extract_features(url) devolve as features usadas pelo modelo.
Não acede à rede (REQ06). O treino e a app usam esta mesma função.

Porque é que só usamos o domínio:
No PhiUSIIL, os URLs legítimos são todos do tipo https://www.site.com, sem caminho.
Quando treinámos com o URL completo, o modelo classificava como phishing qualquer
URL com caminho (por exemplo, a Wikipedia). Por isso, o modelo só vê o domínio registado.
O resto do URL (https, @, subdomínios) serve apenas para explicar o resultado,
na função url_signals().
"""

import ipaddress
import math
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

import tldextract

# Usa a lista de sufixos incluída no tldextract, sem a descarregar da Internet (REQ06).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "account", "update", "secure", "bank",
    "confirm", "password", "wallet", "webscr", "billing", "support", "auth",
)

# TLDs frequentemente usados em phishing. Lista definida por nós, não exaustiva.
ABUSED_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "info", "online",
    "site", "live", "icu", "buzz", "rest", "shop", "work", "support", "cyou", "sbs",
}

FEATURE_NAMES = [
    "has_ip",
    "domain_length",
    "domain_num_hyphens",
    "domain_num_digits",
    "domain_digit_ratio",
    "domain_vowel_ratio",
    "domain_entropy",
    "domain_has_suspicious_word",
    "tld_length",
    "tld_num_labels",
    "tld_abused",
]


def _host(url: str) -> str:
    try:
        return (urlsplit(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def split_domain(url: str) -> tuple[str, str, str]:
    """Devolve (subdomínio, domínio, sufixo) sem aceder à rede."""
    host = _host(url)
    if not host:
        return "", "", ""
    if _is_ip(host):
        return "", host, ""
    ext = _EXTRACT(host)
    return ext.subdomain, ext.domain, ext.suffix


def extract_features(url: str) -> dict:
    host = _host(url)
    is_ip = bool(host) and _is_ip(host)
    _, domain, suffix = split_domain(url)
    letters = [c for c in domain if c.isalpha()]
    n_digits = sum(c.isdigit() for c in domain)
    last_tld = suffix.rsplit(".", 1)[-1] if suffix else ""
    return {
        "has_ip": float(is_ip),
        "domain_length": float(len(domain)),
        "domain_num_hyphens": float(domain.count("-")),
        "domain_num_digits": float(n_digits),
        "domain_digit_ratio": n_digits / len(domain) if domain else 0.0,
        "domain_vowel_ratio": sum(c in "aeiou" for c in letters) / len(letters) if letters else 0.0,
        "domain_entropy": _entropy(domain),
        "domain_has_suspicious_word": float(any(w in domain for w in SUSPICIOUS_WORDS)),
        "tld_length": float(len(suffix)),
        "tld_num_labels": float(len(suffix.split("."))) if suffix else 0.0,
        "tld_abused": float(last_tld in ABUSED_TLDS),
    }


def url_signals(url: str) -> dict:
    """Sinais do URL completo, para explicar o resultado (não entram no modelo)."""
    url = url.strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        parts = urlsplit("")
    sub, _, suffix = split_domain(url)
    sub_labels = [s for s in sub.split(".") if s and s != "www"]
    lower = url.lower()
    return {
        "has_ip": _is_ip(_host(url)) if _host(url) else False,
        "has_at": "@" in parts.netloc,
        "has_https": parts.scheme.lower() == "https",
        "num_subdomains": len(sub_labels),
        "suspicious_words": [w for w in SUSPICIOUS_WORDS if w in lower],
        "url_length": len(url),
        "num_query_params": len(parse_qsl(parts.query, keep_blank_values=True)),
        "tld_abused": (suffix.rsplit(".", 1)[-1] if suffix else "") in ABUSED_TLDS,
    }
