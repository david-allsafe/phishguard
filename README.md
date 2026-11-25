# PhishGuard

Detetor de URLs de phishing com Regressão Logística e Árvore de Decisão.
Projeto de Desenvolvimento de Software III — CTeSP em Cibersegurança, ISTEC.

A análise é **estática**: o sistema nunca acede ao URL analisado.

## Estrutura

| Pasta / ficheiro | Responsável | Conteúdo |
|---|---|---|
| `data/` | P1 — Leo | Dataset (não versionado; ver origem e licença abaixo) |
| `src/features.py` | P1 — Leo | `extract_features(url) -> dict` |
| `src/train.py` | P2 — Luz | Treino e comparação LR vs DT |
| `src/predict.py` | Luz / Ricardo | `predict(url) -> {label, prob, razoes}` |
| `src/app.py`, `src/web.py`, `src/validation.py` | P3 — Ricardo | Interface (CLI e web) e validação de input |
| `tests/` | P4 — David | Testes unitários (pytest) |
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

O modelo treinado (`models/phishguard.joblib`) está versionado. Antes de o carregar, `predict.py`
confirma o SHA-256 guardado em `models/phishguard.joblib.sha256`: um ficheiro joblib executa
código ao ser carregado, por isso um modelo alterado é rejeitado.

### Docker / Hugging Face Spaces

```bash
docker build -t phishguard .
docker run --rm -p 8501:8501 phishguard
```

Para publicar no Hugging Face Spaces, crie um Space do tipo **Docker** e envie `Dockerfile`,
`requirements.txt`, `src/` e `models/`. O README do Space precisa deste cabeçalho:

```yaml
---
title: PhishGuard
sdk: docker
app_port: 8501
---
```

## Resultados (conjunto de teste, 26 309 domínios)

| Modelo | Accuracy | Precision | Recall | F1 | ROC AUC |
|---|---|---|---|---|---|
| Referência (classe maioritária) | 0.753 | 0.000 | 0.000 | 0.000 | 0.500 |
| Regressão Logística (limiar 0.47) | 0.763 | 0.524 | 0.439 | 0.478 | 0.686 |
| **Árvore de Decisão** (prof. 10, limiar 0.51) | 0.785 | 0.590 | 0.428 | 0.496 | 0.708 |

Divisão 70/15/15 estratificada, semente 42, pesos de classe equilibrados; profundidade da
árvore e limiares escolhidos no conjunto de validação. Detalhes em
`evidencias/EVD02_resultados_treino.json` e `evidencias/EVD03_matriz_confusao.png`.

## Limitações

- **Fuga de informação no dataset.** No PhiUSIIL, 100% dos URLs legítimos são páginas iniciais
  `https://www.` sem caminho. Uma primeira versão com o URL completo teve 99,6% de accuracy, mas
  classificava `https://pt.wikipedia.org/wiki/Phishing` como phishing: tinha aprendido "URL com
  caminho = phishing". Por isso, o modelo usa apenas features do **domínio registado**, e os
  restantes sinais (HTTPS, `@`, subdomínios, palavras suspeitas) são mostrados como razões, sem
  entrarem na decisão. Os testes `test_sanidade_*` verificam isto com URLs fora do dataset.
- Só com o domínio, cerca de 57% dos domínios de phishing do teste não são detetados (recall
  0.43). Muitos domínios de phishing parecem normais e só se distinguem pelo conteúdo da página,
  que este projeto não analisa (por desenho, REQ06).
- A lista de TLDs abusados e de palavras suspeitas é heurística e não exaustiva.

## Fluxo de trabalho

1. Pegar numa issue (TAR01–TAR09) e criar um ramo com o ID: `git checkout -b TAR02-features`
2. Commits com o ID: `TAR02: adicionar contagem de subdomínios`
3. Abrir pull request; revisão por outro elemento (P1↔P2, P3↔P4)
4. Merge para `main` só após aprovação

**Nunca** fazer commit de palavras-passe, tokens ou dados pessoais.

## Dataset

- Origem: PhiUSIIL Phishing URL Dataset — Prasad, A. & Chandra, S. (2024), *Computers & Security*,
  doi:10.1016/j.cose.2023.103545. UCI ML Repository (id 967) e Mendeley Data (doi:10.17632/shwpxscxy2).
  Cópia obtida a partir de `github.com/xxxinmeng02/phiusiil-phishing` (`CSCloud_data/data/original/phiusiil.zip`).
- Licença: CC BY 4.0
- Data de download: 2026-11-25
- Ficheiro: `data/PhiUSIIL_Phishing_URL_Dataset.csv`, SHA-256
  `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`
  (235 795 linhas: 134 850 legítimas, 100 945 phishing, igual aos valores oficiais)
- Atenção: no dataset, `label` 1 = legítimo e 0 = phishing. O `train.py` inverte para 1 = phishing.
