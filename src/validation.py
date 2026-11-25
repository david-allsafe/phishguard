"""TAR05/TAR08 - Validação de input (REQ04)."""

from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}


def validate_url(url: str) -> str:
    """Devolve o URL limpo ou lança ValueError com mensagem para o utilizador.

    Aceita apenas URLs http ou https com domínio. Rejeita esquemas perigosos
    (javascript:, data:, file:) e caracteres de controlo. Não acede ao URL (REQ06).
    """
    if url is None or not str(url).strip():
        raise ValueError("O URL não pode estar vazio.")
    url = str(url).strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"O URL excede {MAX_URL_LENGTH} caracteres.")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in url):
        raise ValueError("O URL contém espaços ou caracteres de controlo.")
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise ValueError("O URL está mal formado.") from None
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("O URL tem de começar por http:// ou https://.")
    if not host:
        raise ValueError("O URL não tem domínio.")
    return url
