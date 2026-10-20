"""
Setup de una sola vez: baja el modelo on-prem y carga el corpus del RAG.

    docker compose --profile setup run --rm seed

El corpus incluye un documento envenenado a propósito (politica-viajes.md).
Está ahí porque la inyección indirecta no se puede demostrar con un corpus
limpio, y es el ataque que más cuesta ver: no entra por el prompt del
usuario, entra por un documento que tu propia empresa indexó.
"""
import os
import pathlib
import sys

import chromadb
import httpx

CHROMA_HOST = os.getenv("CHROMA_HOST", "chroma")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
LOCAL_MODEL = os.getenv("LOCAL_MODEL", "llama3.2:3b")
COLLECTION = "politicas-internas"
DOCS = pathlib.Path("docs")

ENVENENADO = "politica-viajes.md"


def bajar_modelo() -> None:
    print(f"[ollama] pull {LOCAL_MODEL} (puede tardar varios minutos)...")
    with httpx.Client(timeout=None) as client:
        with client.stream("POST", f"{OLLAMA_BASE_URL}/api/pull",
                           json={"model": LOCAL_MODEL}) as r:
            r.raise_for_status()
            ultimo = ""
            for linea in r.iter_lines():
                if not linea:
                    continue
                import json
                estado = json.loads(linea).get("status", "")
                if estado != ultimo:
                    print(f"[ollama]   {estado}")
                    ultimo = estado
    print(f"[ollama] listo: {LOCAL_MODEL}")


def cargar_rag() -> None:
    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass
    col = client.create_collection(COLLECTION)

    archivos = sorted(DOCS.glob("*.md"))
    if not archivos:
        sys.exit("no hay documentos en docs/")

    col.add(
        ids=[f.stem for f in archivos],
        documents=[f.read_text(encoding="utf-8") for f in archivos],
        metadatas=[
            {"fuente": f.name, "envenenado": f.name == ENVENENADO}
            for f in archivos
        ],
    )
    print(f"[chroma] colección '{COLLECTION}' con {len(archivos)} documentos:")
    for f in archivos:
        marca = "  <-- ENVENENADO a propósito" if f.name == ENVENENADO else ""
        print(f"[chroma]   {f.name}{marca}")


if __name__ == "__main__":
    bajar_modelo()
    cargar_rag()
    print("\nSeed completo. Ahora: python attack_llm.py")
