"""TAR06 (P2/P3) — Interface entre o modelo e a aplicação.

Contrato: predict(url: str) -> {"label": "phishing" | "legitimo", "prob": float, "razoes": list[str]}
"""

from src.features import extract_features


def predict(url: str) -> dict:
    features = extract_features(url)  # noqa: F841 — usado quando o modelo existir
    # STUB: resposta fixa até P2 exportar o modelo para models/.
    return {"label": "legitimo", "prob": 0.5, "razoes": []}
