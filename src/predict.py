"""TAR06 (P2/P3) - Ligação entre o modelo e a aplicação.

Contrato: predict(url: str) -> {"label": "phishing" | "legitimo", "prob": float, "razoes": list[str]}
"prob" é a probabilidade estimada de o URL ser phishing (0 a 1).

Segurança: o modelo é guardado em joblib (formato pickle), que pode executar código
ao ser carregado. Por isso, antes de o carregar, comparamos o SHA-256 do ficheiro
com o valor gerado no treino.
"""

import hashlib
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from src.features import FEATURE_NAMES, extract_features, url_signals

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_PATH = MODELS_DIR / "phishguard.joblib"
HASH_PATH = MODELS_DIR / "phishguard.joblib.sha256"
THRESHOLD = 0.5


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@lru_cache(maxsize=1)
def load_bundle(model_path: Path = MODEL_PATH, hash_path: Path = HASH_PATH) -> dict:
    if not model_path.exists():
        raise FileNotFoundError(
            f"Modelo não encontrado em {model_path}. Treine primeiro: python -m src.train"
        )
    expected = hash_path.read_text().split()[0].strip() if hash_path.exists() else None
    if expected is None or _sha256(model_path) != expected:
        raise RuntimeError("Falha na verificação de integridade do modelo (SHA-256).")
    bundle = joblib.load(model_path)
    if bundle.get("feature_names") != FEATURE_NAMES:
        raise RuntimeError("O modelo foi treinado com features diferentes das atuais.")
    return bundle


def explain(url: str, features: dict) -> list:
    """Gera as razões mostradas ao utilizador, com regras sobre o URL completo. Não depende do modelo."""
    s = url_signals(url)
    razoes = []
    if s["has_ip"]:
        razoes.append("Usa um endereço IP em vez de um domínio.")
    if s["has_at"]:
        razoes.append("Contém '@' antes do domínio, o que pode esconder o destino real.")
    if not s["has_https"]:
        razoes.append("Não usa HTTPS.")
    if s["num_subdomains"] >= 2:
        razoes.append(f"Tem {s['num_subdomains']} subdomínios.")
    if features["domain_num_hyphens"] >= 1:
        razoes.append("O domínio tem hífens (ex.: marca-segurança).")
    if features["domain_num_digits"] >= 3:
        razoes.append("O domínio tem vários dígitos.")
    if s["tld_abused"]:
        razoes.append("Usa um TLD frequentemente abusado em phishing.")
    if s["suspicious_words"]:
        razoes.append("Palavras típicas de phishing: " + ", ".join(s["suspicious_words"]) + ".")
    if s["url_length"] > 75:
        razoes.append(f"URL longo ({s['url_length']} caracteres).")
    if s["num_query_params"] >= 3:
        razoes.append(f"Muitos parâmetros na query ({s['num_query_params']}).")
    return razoes


def predict(url: str) -> dict:
    bundle = load_bundle()
    features = extract_features(url)
    X = pd.DataFrame([features], columns=FEATURE_NAMES)
    prob = float(bundle["model"].predict_proba(X)[0][1])
    return {
        "label": "phishing" if prob >= bundle.get("threshold", THRESHOLD) else "legitimo",
        "prob": prob,
        "razoes": explain(url, features),
    }
