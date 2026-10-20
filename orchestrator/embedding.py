"""Embedding multilingüe servido por el servicio de guardrails.

Se usa EXACTAMENTE el mismo modelo al indexar y al consultar. Si se indexa
con uno y se consulta con otro, las distancias no significan nada y el RAG
devuelve resultados plausibles pero equivocados, que es la peor falla posible
porque no se ve.
"""
import os

import httpx
import numpy as np

GUARDRAILS_URL = os.getenv("GUARDRAILS_URL", "http://guardrails:8002")


class EmbeddingRemoto:
    """Interfaz de embedding function de Chroma, resuelta por HTTP."""

    def __init__(self, url: str = None, timeout: float = 120.0):
        self.url = (url or GUARDRAILS_URL).rstrip("/") + "/embed"
        self.timeout = timeout

    def name(self) -> str:
        return "zt-multilingue"

    def __call__(self, input):
        textos = list(input)
        if not textos:
            return []
        r = httpx.post(self.url, json={"textos": textos}, timeout=self.timeout)
        r.raise_for_status()
        # Chroma espera ndarray: con listas de Python revienta en
        # convert_np_embeddings_to_list con "'list' object has no attribute 'tolist'".
        return [np.asarray(v, dtype=np.float32) for v in r.json()["vectores"]]


class EmbeddingsLangChain:
    """Misma función de embedding, con la interfaz que espera LangChain.

    Es el mismo servicio y el mismo modelo que usa la ingesta. Si LangChain
    trajera su propio embedding por defecto, estaríamos consultando con un
    modelo distinto del que indexó, y las distancias no significarían nada.
    """

    def __init__(self, url: str = None):
        self._ef = EmbeddingRemoto(url)

    def embed_documents(self, textos):
        return [v.tolist() for v in self._ef(textos)]

    def embed_query(self, texto):
        return self._ef([texto])[0].tolist()
