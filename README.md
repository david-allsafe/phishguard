# PhishGuard

Detetor de URLs de phishing com Regressão Logística e Árvore de Decisão.
Projeto de Desenvolvimento de Software III — CTeSP em Cibersegurança, ISTEC.

A análise é **estática**: o sistema nunca acede ao URL analisado.

## Estrutura

| Pasta / ficheiro | Responsável | Conteúdo |
|---|---|---|
| `data/` | P1 | Dataset (não versionado; ver origem e licença abaixo) |
| `src/features.py` | P1 | `extract_features(url) -> dict` |
| `src/train.py` | P2 | Treino e comparação LR vs DT |
| `src/predict.py` | P2/P3 | `predict(url) -> {label, prob, razoes}` |
| `src/app.py`, `src/validation.py` | P3 | Interface e validação de input |
| `tests/` | P4 | Testes unitários (pytest) |
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
python -m src.app "https://exemplo.com/login"
pytest -v
```

## Fluxo de trabalho

1. Pegar numa issue (TAR01–TAR09) e criar um ramo com o ID: `git checkout -b TAR02-features`
2. Commits com o ID: `TAR02: adicionar contagem de subdomínios`
3. Abrir pull request; revisão por outro elemento (P1↔P2, P3↔P4)
4. Merge para `main` só após aprovação

**Nunca** fazer commit de palavras-passe, tokens ou dados pessoais.

## Dataset

- Origem: _[a preencher — PhiUSIIL Phishing URL ou UCI Phishing Websites]_
- Licença: _[a preencher]_
- Data de download: _[a preencher]_
