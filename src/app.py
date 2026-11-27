"""TAR05 (P3) - Interface. Executar: python -m src.app <url>"""

import sys

from src.predict import predict
from src.validation import validate_url


def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: python -m src.app <url>")
        return 1
    try:
        url = validate_url(sys.argv[1])
    except ValueError as e:
        print(f"Erro: {e}")
        return 1
    r = predict(url)
    print(f"{r['label'].upper()} (probabilidade: {r['prob']:.2f})")
    for razao in r["razoes"]:
        print(f" - {razao}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
