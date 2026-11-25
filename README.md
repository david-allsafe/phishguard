# PhishGuard

Detetor de URLs de phishing com Regressão Logística e Árvore de Decisão.
Projeto de Desenvolvimento de Software III - CTeSP em Cibersegurança, ISTEC.

A análise é **estática**: o sistema nunca acede ao URL analisado.

## Estrutura

| Pasta / ficheiro | Responsável | Conteúdo |
|---|---|---|
| `data/` | P1 - Leo | Dataset (não versionado; ver origem e licença abaixo) |
| `src/features.py` | P1 - Leo | `extract_features(url) -> dict` |
| `src/train.py` | P2 - Luz | Treino e comparação LR vs DT |
| `src/predict.py` | Luz / Ricardo | `predict(url) -> {label, prob, razoes}` |
| `src/app.py`, `src/web.py`, `src/validation.py` | P3 - Ricardo | Interface (CLI e web) e validação de input |
| `tests/` | P4 - David | Testes unitários (pytest) |
| `evidencias/` | Todos | Evidências com o ID (ex.: `EVD03_matriz_confusao.png`) |

## Instalação

```bash
git clone https://github.com/david-allsafe/phishguard.git
cd phishguard
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Utilização

```bash
python -m src.train                          # treina e gera models/ e evidencias/ (precisa do dataset em data/)
python -m src.app "https://exemplo.com/login" # CLI
streamlit run src/web.py                     # interface web em http://localhost:8501
pytest -v                                    # testes
```

O modelo treinado (`models/phishguard.joblib`) está versionado. O formato joblib pode executar
código ao ser carregado, por isso o `predict.py` compara primeiro o SHA-256 do ficheiro com o valor
em `models/phishguard.joblib.sha256`. Um modelo alterado é rejeitado.

### Versão online

O protótipo está publicado no Streamlit Community Cloud: https://phishguard-istec.streamlit.app

O deploy é feito a partir deste repositório (ficheiro principal `src/web.py`). Cada push para o
ramo configurado atualiza a app.

### Docker

```bash
docker build -t phishguard .
docker run --rm -p 8501:8501 phishguard
```

## Resultados (conjunto de teste, 26 309 domínios)

| Modelo | Accuracy | Precision | Recall | F1 | ROC AUC |
|---|---|---|---|---|---|
| Referência (classe maioritária) | 0.753 | 0.000 | 0.000 | 0.000 | 0.500 |
| Regressão Logística (limiar 0.47) | 0.763 | 0.524 | 0.439 | 0.478 | 0.686 |
| **Árvore de Decisão** (prof. 10, limiar 0.51) | 0.785 | 0.590 | 0.428 | 0.496 | 0.708 |

Divisão 70/15/15 estratificada, semente 42 e pesos de classe equilibrados. A profundidade da
árvore e os limiares foram escolhidos no conjunto de validação. Os valores completos estão em
`evidencias/EVD03_resultados_treino.json` e `evidencias/EVD03_matriz_confusao.png`.

## Limitações

- **Fuga de informação no dataset.** No PhiUSIIL, todos os URLs legítimos são páginas iniciais
  `https://www.` sem caminho. A primeira versão, treinada com o URL completo, obteve 99,6% de
  accuracy, mas classificava `https://pt.wikipedia.org/wiki/Phishing` como phishing: o modelo
  tinha aprendido a regra "URL com caminho = phishing". Por isso, o modelo passou a usar apenas
  features do **domínio registado**. Os restantes sinais (HTTPS, `@`, subdomínios, palavras
  suspeitas) são mostrados como razões e não entram na decisão. Os testes `test_sanidade_*`
  confirmam este comportamento com URLs que não pertencem ao dataset.
- Usando apenas o domínio, o modelo não deteta cerca de 57% dos domínios de phishing do conjunto
  de teste (recall 0.43). Muitos destes domínios têm um aspeto normal e só se distinguem pelo
  conteúdo da página, que o projeto não analisa (REQ06).
- As listas de TLDs e de palavras suspeitas foram definidas por nós e não são exaustivas.

## Fluxo de trabalho

1. Pegar numa issue (TAR01–TAR09) e criar um ramo com o ID: `git checkout -b TAR02-features`
2. Commits com o ID: `TAR02: adicionar contagem de subdomínios`
3. Abrir pull request; revisão por outro elemento (P1↔P2, P3↔P4)
4. Merge para `main` só após aprovação

**Nunca** fazer commit de palavras-passe, tokens ou dados pessoais.

## Dataset

- Origem: PhiUSIIL Phishing URL Dataset - Prasad, A. & Chandra, S. (2024), *Computers & Security*,
  doi:10.1016/j.cose.2023.103545. UCI ML Repository (id 967) e Mendeley Data (doi:10.17632/shwpxscxy2).
  Cópia descarregada de `github.com/xxxinmeng02/phiusiil-phishing` (`CSCloud_data/data/original/phiusiil.zip`).
- Licença: CC BY 4.0
- Data de download: 2026-11-25
- Ficheiro: `data/PhiUSIIL_Phishing_URL_Dataset.csv`, SHA-256
  `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`
  (235 795 linhas: 134 850 legítimas e 100 945 de phishing, de acordo com os valores oficiais)
- Nota: no dataset, `label` 1 = legítimo e 0 = phishing. O `train.py` inverte para 1 = phishing.
