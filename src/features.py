"""TAR02 (P1) — Extração de features de um URL.

Contrato: extract_features(url: str) -> dict[str, float]
Regra: nunca aceder à rede (REQ06). As mesmas features são usadas no treino e na app.
"""

FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_subdomains",
    "has_ip",
    "has_at",
    "has_https",
    "num_digits",
    "num_special_chars",
]


def extract_features(url: str) -> dict:
    # STUB: valores fictícios até P1 implementar a versão real.
    return {name: 0.0 for name in FEATURE_NAMES}
