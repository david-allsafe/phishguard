"""TAR05/TAR08 — Validação de input (REQ04)."""

MAX_URL_LENGTH = 2048


def validate_url(url: str) -> str:
    """Devolve o URL limpo ou lança ValueError com mensagem para o utilizador."""
    if url is None or not url.strip():
        raise ValueError("O URL não pode estar vazio.")
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"O URL excede {MAX_URL_LENGTH} caracteres.")
    return url
