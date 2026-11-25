"""TAR03/TAR04 (P2) — Treino e comparação: Regressão Logística vs Árvore de Decisão.

Divisão 70/15/15 estratificada, semente fixa. Exporta o melhor modelo para models/.
Executar: python -m src.train [--data caminho.csv]
"""

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
import sklearn  # noqa: E402
from sklearn.dummy import DummyClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    ConfusionMatrixDisplay,
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402

from src.features import FEATURE_NAMES, extract_features, split_domain  # noqa: E402
from src.predict import HASH_PATH, MODEL_PATH, _sha256  # noqa: E402

SEED = 42
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
EVID = ROOT / "evidencias"
DT_DEPTHS = [4, 6, 8, 10, 12, 16]


def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series, dict]:
    df = pd.read_csv(path, usecols=["URL", "label"], encoding="utf-8-sig")
    n_raw = len(df)
    df = df.dropna().drop_duplicates(subset="URL")
    n_urls = len(df)
    # O modelo só vê o domínio registado. Vários URLs do mesmo domínio seriam linhas
    # iguais, que podiam cair no treino e no teste ao mesmo tempo (fuga de informação).
    # Ficamos com uma linha por domínio e descartamos domínios com rótulos contraditórios.
    df["dominio"] = [".".join(p for p in split_domain(u)[1:] if p) for u in df["URL"]]
    df = df[df["dominio"] != ""]
    n_labels = df.groupby("dominio")["label"].nunique()
    contraditorios = set(n_labels[n_labels > 1].index)
    df = df[~df["dominio"].isin(contraditorios)].drop_duplicates(subset="dominio").reset_index(drop=True)
    # No PhiUSIIL, label 1 = legítimo e 0 = phishing. Aqui, 1 = phishing.
    y = (1 - df["label"]).astype(int)
    X = pd.DataFrame([extract_features(u) for u in df["URL"]], columns=FEATURE_NAMES)
    info = {"linhas_originais": n_raw, "urls_unicos": n_urls,
            "dominios_contraditorios_removidos": len(contraditorios),
            "dominios_unicos_usados": len(df),
            "phishing": int(y.sum()), "legitimo": int((y == 0).sum())}
    return X, y, info


def best_threshold(model, X, y) -> tuple[float, float]:
    """Limiar que maximiza o F1 no conjunto de validação."""
    prob = model.predict_proba(X)[:, 1]
    prec, rec, thr = precision_recall_curve(y, prob)
    f1 = 2 * prec * rec / (prec + rec + 1e-12)
    i = int(np.argmax(f1[:-1]))
    return float(thr[i]), float(f1[i])


def metrics(model, X, y, threshold: float = 0.5) -> dict:
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y, prob), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    args = ap.parse_args()

    print(f"A carregar {args.data} ...")
    X, y, info = load_dataset(args.data)
    info["sha256"] = _sha256(args.data)
    print(info)

    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=SEED)
    X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=SEED)
    info.update(treino=len(X_tr), validacao=len(X_val), teste=len(X_te))

    # Referência de comparação: prevê sempre a classe maioritária.
    baseline = DummyClassifier(strategy="most_frequent").fit(X_tr, y_tr)

    t0 = time.perf_counter()
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)).fit(X_tr, y_tr)
    t_lr = time.perf_counter() - t0

    # Escolha da profundidade da árvore com o conjunto de validação (o de teste não é usado aqui).
    depth_scores = {}
    for d in DT_DEPTHS:
        m = DecisionTreeClassifier(max_depth=d, min_samples_leaf=5, class_weight="balanced", random_state=SEED).fit(X_tr, y_tr)
        depth_scores[d] = f1_score(y_val, m.predict(X_val))
    best_depth = max(depth_scores, key=depth_scores.get)
    t0 = time.perf_counter()
    dt = DecisionTreeClassifier(max_depth=best_depth, min_samples_leaf=5, class_weight="balanced",
                                random_state=SEED).fit(X_tr, y_tr)
    t_dt = time.perf_counter() - t0

    candidatos = {"regressao_logistica": lr, "arvore_decisao": dt}
    # Classes desequilibradas (~25% phishing): pesos equilibrados e limiar escolhido na validação.
    limiares = {k: best_threshold(m, X_val, y_val) for k, m in candidatos.items()}
    val_f1 = {k: round(v[1], 4) for k, v in limiares.items()}
    best_name = max(val_f1, key=val_f1.get)
    thr = {k: round(v[0], 4) for k, v in limiares.items()}

    resultados = {
        "data_treino": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "semente": SEED,
        "sklearn": sklearn.__version__,
        "dataset": info,
        "features": FEATURE_NAMES,
        "arvore_f1_validacao_por_profundidade": {str(k): round(v, 4) for k, v in depth_scores.items()},
        "arvore_profundidade_escolhida": best_depth,
        "f1_validacao": val_f1,
        "limiar_escolhido_validacao": thr,
        "modelo_escolhido": best_name,
        "tempo_treino_s": {"regressao_logistica": round(t_lr, 2), "arvore_decisao": round(t_dt, 2)},
        "teste": {
            "baseline_classe_maioritaria": metrics(baseline, X_te, y_te),
            "regressao_logistica": metrics(lr, X_te, y_te, thr["regressao_logistica"]),
            "arvore_decisao": metrics(dt, X_te, y_te, thr["arvore_decisao"]),
        },
    }

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump({"model": candidatos[best_name], "model_name": best_name, "threshold": thr[best_name],
                 "feature_names": FEATURE_NAMES, "resultados": resultados}, MODEL_PATH)
    HASH_PATH.write_text(f"{_sha256(MODEL_PATH)}  {MODEL_PATH.name}\n")

    EVID.mkdir(exist_ok=True)
    (EVID / "EVD02_resultados_treino.json").write_text(json.dumps(resultados, indent=2, ensure_ascii=False))
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, (nome, m) in zip(axes, candidatos.items()):
        pred = (m.predict_proba(X_te)[:, 1] >= thr[nome]).astype(int)
        ConfusionMatrixDisplay.from_predictions(y_te, pred, display_labels=["legítimo", "phishing"],
                                                ax=ax, colorbar=False, values_format="d")
        ax.set_title(nome.replace("_", " ").capitalize() + " (teste)")
    fig.tight_layout()
    fig.savefig(EVID / "EVD03_matriz_confusao.png", dpi=150)

    print(json.dumps(resultados["teste"], indent=2))
    print(f"Modelo escolhido: {best_name} -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
