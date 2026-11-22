"""TAR05 (P3) — Interface CLI. Executar: python -m src.app "<url>" """

import argparse
import sys
import time

from src.predict import predict
from src.validation import validate_url


def analisar(url_bruto: str) -> int:
    try:
        url = validate_url(url_bruto)
    except ValueError as e:
        print(f"Erro: {e}")
        return 1

    inicio = time.perf_counter()
    try:
        r = predict(url)
    except Exception:
        print("Erro: não foi possível analisar o URL.")
        return 2
    duracao = time.perf_counter() - inicio

    print(f"URL:           {url}")
    print(f"Resultado:     {r['label'].upper()}")
    print(f"Probabilidade: {r['prob']:.0%}")
    print(f"Tempo:         {duracao:.3f} s")
    print("Razões:")
    if r["razoes"]:
        for razao in r["razoes"]:
            print(f"  - {razao}")
    else:
        print("  (sem razões disponíveis)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.app",
        description="PhishGuard: deteta URLs de phishing por análise estática (não acede ao URL).",
    )
    parser.add_argument("url", help='URL a analisar, entre aspas (ex.: "https://exemplo.pt")')
    args = parser.parse_args()
    return analisar(args.url)


if __name__ == "__main__":
    sys.exit(main())