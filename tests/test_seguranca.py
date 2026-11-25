"""TAR07/TAR08 (P4) - Testes de features, validação e segurança."""

import shutil
import socket

import pytest

from src import predict as predict_mod
from src.features import extract_features, url_signals
from src.predict import predict
from src.validation import validate_url


# --- REQ06: análise estática, sem acesso à rede -------------------------------------

@pytest.fixture
def sem_rede(monkeypatch):
    def bloquear(*args, **kwargs):
        raise AssertionError("Tentativa de acesso à rede (viola REQ06)")
    monkeypatch.setattr(socket, "socket", bloquear)
    monkeypatch.setattr(socket, "create_connection", bloquear)
    monkeypatch.setattr(socket, "getaddrinfo", bloquear)


def test_req06_predict_nao_acede_a_rede(sem_rede):  # TST07 (parte automática)
    r = predict("http://secure-login.cgd-verify-account.xyz/update")
    assert r["label"] in {"phishing", "legitimo"}


# --- Features -------------------------------------------------------------------------

def test_features_ip():
    assert extract_features("http://192.168.10.5/login.php")["has_ip"] == 1.0
    assert extract_features("https://www.istec.pt")["has_ip"] == 0.0


def test_features_dominio_registado_ignora_subdominio_e_caminho():
    a = extract_features("https://www.istec.pt")
    b = extract_features("http://cursos.istec.pt/ctesp/ciberseguranca?x=1")
    assert a == b  # o modelo só usa o domínio registado (ver features.py)


def test_features_sufixo_composto():
    f = extract_features("https://www.exemplo.com.br")
    assert f["tld_num_labels"] == 2.0 and f["domain_length"] == len("exemplo")


def test_sinais_arroba_esconde_destino():
    s = url_signals("https://www.paypal.com@evil-example.tk/signin")
    assert s["has_at"] and s["tld_abused"] and "signin" in s["suspicious_words"]


# --- REQ04: validação de input ------------------------------------------------------

@pytest.mark.parametrize(
    "entrada",
    [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "exemplo.com",
        "http://",
        "https://exe mplo.com",
        "https://exemplo.com/\x00",
        "https://exemplo.com/\nSet-Cookie:x",
    ],
    ids=["javascript", "data", "file", "sem_esquema", "sem_dominio", "espaco", "nulo", "crlf"],
)
def test_req04_rejeita_entradas_maliciosas(entrada):  # TST04
    with pytest.raises(ValueError):
        validate_url(entrada)


def test_req04_aceita_url_normal():
    assert validate_url("  https://www.istec.pt/cursos  ") == "https://www.istec.pt/cursos"


# --- Integridade do modelo ----------------------------------------------------------

def test_modelo_alterado_e_rejeitado(tmp_path):  # TST08
    modelo = tmp_path / "m.joblib"
    shutil.copy(predict_mod.MODEL_PATH, modelo)
    with open(modelo, "ab") as f:
        f.write(b"adulterado")
    with pytest.raises(RuntimeError):
        predict_mod.load_bundle.__wrapped__(modelo, predict_mod.HASH_PATH)


# --- Sanidade: URLs fora do dataset -------------------------------------------------
# Exemplos construídos por nós para confirmar que o modelo não aprendeu a regra
# "URL com caminho = phishing" (ver Limitações no README).

@pytest.mark.parametrize("url", [
    "https://www.istec.pt",
    "https://pt.wikipedia.org/wiki/Phishing",
    "https://github.com/david-allsafe/phishguard/pull/10",
    "https://www.cgd.pt/Particulares/Pages/Particulares_v2.aspx",
])
def test_sanidade_legitimos_com_caminho(url):  # TST01
    assert predict(url)["label"] == "legitimo"


@pytest.mark.parametrize("url", [
    "http://192.168.10.5/paypal/login.php",
    "https://www.paypal.com@evil-example.tk/signin",
    "http://secure-login.cgd-verify-account.xyz/update",
])
def test_sanidade_phishing_construido(url):  # TST02
    assert predict(url)["label"] == "phishing"


# --- REQ05: tempo de resposta -------------------------------------------------------

def test_req05_tempo_de_resposta():  # TST06
    import time
    predict("https://www.istec.pt")  # o primeiro pedido carrega o modelo
    t0 = time.perf_counter()
    predict("http://secure-login.cgd-verify-account.xyz/update")
    assert time.perf_counter() - t0 < 1.0
