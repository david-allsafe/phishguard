"""TAR07 (P4) — Testes aos contratos entre módulos."""

import pytest

from src.features import FEATURE_NAMES, extract_features
from src.predict import predict
from src.validation import validate_url


def test_extract_features_devolve_todas_as_features():
    f = extract_features("https://www.istec.pt")
    assert set(f) == set(FEATURE_NAMES)


def test_predict_respeita_contrato():
    r = predict("https://www.istec.pt")
    assert r["label"] in {"phishing", "legitimo"}
    assert 0.0 <= r["prob"] <= 1.0
    assert isinstance(r["razoes"], list)


@pytest.mark.parametrize(
    "entrada",
    ["", "   ", None, "a" * 3000],
    ids=["vazio", "espacos", "none", "demasiado_longo"],
)
def test_validacao_rejeita_entradas_invalidas(entrada):  # TST04 / REQ04
    with pytest.raises(ValueError):
        validate_url(entrada)