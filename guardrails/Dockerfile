FROM python:3.12-slim
WORKDIR /app
# spaCy y torch no traen wheel para esta combinación de arquitectura y
# Python: sin compilador, pip intenta buildear desde fuente y falla.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Modelo de NER en ESPAÑOL. La imagen oficial de Presidio trae el de inglés y
# sobre texto en castellano marca "¿Cuál es el" como persona. Acá el NER lo
# hacemos nosotros, en el idioma correcto.
RUN python -m spacy download es_core_news_md

# Embeddings multilingües para el RAG. No es opcional: el default de Chroma
# está entrenado en inglés y sobre un corpus en castellano no discrimina.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2')"

# Reranker multilingüe: reordena los candidatos que trajo el embedding.
RUN python -c "from sentence_transformers import CrossEncoder; \
    CrossEncoder('cross-encoder/mmarco-mMiniLMv2-L12-H384-v1', max_length=512)"

COPY app.py .
EXPOSE 8002
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8002"]
