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
| `src/app.py`, `src/validation.py` | P3 — Ricardo | Interface e validação de input |
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

## Conjunto de Dados — TAR01

### Origem dos Dados

- **Nome:** PhiUSIIL Phishing URL Dataset
- **Fonte:** UCI Machine Learning Repository
- **Referência:** FNT01
- **Ligação:** https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- **Licença:** Creative Commons Atribuição 4.0 Internacional (CC BY 4.0)
- **Data de transferência:** 04/11/2026

### Seleção do Conjunto de Dados

O conjunto de dados PhiUSIIL foi selecionado por disponibilizar endereços URL em formato de texto, permitindo extrair características diretamente a partir dos mesmos, sem necessidade de aceder aos respetivos sítios Web.

Esta abordagem permite cumprir o requisito REQ06, que estabelece que a análise dos endereços URL deve ser realizada sem efetuar pedidos de rede aos sítios analisados.

### Preparação e Limpeza dos Dados

O conjunto de dados original continha **235 795 registos e 56 colunas**.

Durante a preparação e limpeza dos dados, foram realizadas as seguintes operações:

1. Seleção das colunas `URL` e `label`, necessárias para o desenvolvimento do projeto.
2. Verificação da existência de valores nulos.
3. Identificação de endereços URL duplicados.
4. Verificação da existência de endereços URL com classificações contraditórias.
5. Remoção de 425 ocorrências duplicadas.
6. Verificação da existência de endereços URL vazios, sem os prefixos HTTP/HTTPS ou com classificações inválidas.

Após estas operações, obteve-se um conjunto de dados limpo com **235 370 registos**.

### Classificação dos Endereços URL

O conjunto de dados utiliza duas classes:

- `0` — *Phishing*: endereço URL associado a uma tentativa de fraude.
- `1` — *Legítimo*: endereço URL considerado legítimo.

Esta classificação será utilizada no treino e na avaliação dos modelos de aprendizagem automática do projeto PhishGuard.

### Reprodução do Processo de Preparação dos Dados

Devido à
