FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -c "from chromadb.utils.embedding_functions import DefaultEmbeddingFunction; DefaultEmbeddingFunction()(['warmup'])"
COPY seed.py .
# docs/ NO se copia: se monta como volumen desde el compose, así
# editar un documento del corpus no requiere rebuildear la imagen.
CMD ["python", "seed.py"]
