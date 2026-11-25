"""TAR05 (P3) - Interface web. Executar: streamlit run src/web.py

Usa as mesmas funções que a CLI (validate_url e predict). Não acede ao URL (REQ06).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # o Streamlit só adiciona src/ ao sys.path
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from src.predict import load_bundle, predict  # noqa: E402
from src.validation import validate_url  # noqa: E402

EXEMPLOS = [
    "https://pt.wikipedia.org/wiki/Phishing",
    "https://www.paypal.com@evil-example.tk/signin",
    "http://secure-login.cgd-verify-account.xyz/update",
]

st.set_page_config(page_title="PhishGuard", page_icon="🛡️")
st.title("PhishGuard")
st.caption("Deteção de URLs de phishing com Regressão Logística e Árvore de Decisão. "
           "Análise estática: o URL nunca é visitado.")

bundle = load_bundle()

with st.form("analise"):
    url = st.text_input("URL a analisar", placeholder="https://exemplo.com/login", max_chars=2048)
    enviado = st.form_submit_button("Analisar")

with st.expander("Exemplos para testar"):
    for e in EXEMPLOS:
        st.code(e, language=None)

if enviado:
    try:
        limpo = validate_url(url)
    except ValueError as e:
        st.error(str(e))
    else:
        r = predict(limpo)
        if r["label"] == "phishing":
            st.error(f"Provável phishing: probabilidade {r['prob']:.0%}")
        else:
            st.success(f"Provavelmente legítimo: probabilidade de phishing {r['prob']:.0%}")
        st.text(limpo)  # st.text mostra o texto sem interpretar Markdown nem HTML
        if r["razoes"]:
            st.subheader("Sinais encontrados")
            for razao in r["razoes"]:
                st.write("- " + razao)

res = bundle["resultados"]
with st.expander("Treino do modelo"):
    st.write(f"Modelo em uso: **{bundle['model_name'].replace('_', ' ')}** "
             f"(limiar {bundle.get('threshold', 0.5):.2f}), dataset PhiUSIIL "
             f"({res['dataset']['dominios_unicos_usados']} domínios únicos, divisão 70/15/15, semente {res['semente']}).")
    tabela = pd.DataFrame(res["teste"]).T[["accuracy", "precision", "recall", "f1", "roc_auc"]]
    tabela.index = ["Referência (classe maioritária)", "Regressão Logística", "Árvore de Decisão"]
    st.dataframe(tabela)
    st.caption("Métricas no conjunto de teste. O modelo usa apenas o domínio registado. "
               "Os restantes sinais do URL são mostrados como explicação e não entram na decisão.")
