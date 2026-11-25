# Imagem do protótipo PhishGuard (serve para correr localmente e no Hugging Face Spaces).
FROM python:3.13-slim

RUN useradd -m -u 1000 app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app src/ src/
COPY --chown=app:app models/ models/

USER app
EXPOSE 8501
CMD ["streamlit", "run", "src/web.py", "--server.port=8501", "--server.address=0.0.0.0", "--browser.gatherUsageStats=false"]
