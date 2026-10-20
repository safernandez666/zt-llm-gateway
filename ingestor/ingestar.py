"""
Ingesta documental para el RAG: PDF, DOCX, Markdown y texto plano.

    docker compose run --rm ingestor

Toma todo lo que haya en /documentos, lo parte en chunks con metadata, lo
pasa por el escáner de contexto y lo indexa en ChromaDB.

Tres decisiones que vale la pena explicar:

1. EL CHUNK LLEVA SU PROCEDENCIA. Cada fragmento guarda archivo, tipo,
   sección o página, y el hash del documento del que salió. Sin eso, cuando
   el modelo cita algo no podés decir de dónde vino, y una respuesta que no
   se puede auditar no sirve para nada en una empresa.

2. SE ESCANEA EN LA INGESTA, NO SÓLO EN LA RECUPERACIÓN. Atajar un documento
   envenenado al indexarlo es más barato que atajarlo en cada consulta. Pero
   no reemplaza el escaneo en recuperación: un documento puede envenenarse
   DESPUÉS de indexado, y el índice no se entera. Hacen falta los dos.

3. LA INGESTA ES IDEMPOTENTE. El id del chunk se deriva del hash del archivo,
   así volver a correrla no duplica nada.
"""
import hashlib
import os
import pathlib
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

import chromadb

from embedding import EmbeddingRemoto
import httpx

CHROMA_HOST = os.getenv("CHROMA_HOST", "chroma")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
GUARDRAILS_URL = os.getenv("GUARDRAILS_URL", "http://guardrails:8002")
COLLECTION = os.getenv("COLLECTION", "politicas-internas")
DOCS = pathlib.Path(os.getenv("DOCS_DIR", "/documentos"))
# Por defecto NO bloquea: la POC necesita el documento envenenado adentro para
# poder demostrar la inyección indirecta. En una empresa esto va en 1.
BLOQUEAR = os.getenv("INGESTA_BLOQUEA", "0") == "1"
MAX_CHARS = int(os.getenv("CHUNK_CHARS", "600"))
# Solapamiento entre chunks: una frase partida al medio deja a las dos
# mitades sin sentido y ninguna matchea la pregunta.
OVERLAP = int(os.getenv("CHUNK_OVERLAP", "120"))


@dataclass
class Chunk:
    texto: str
    fuente: str
    tipo: str
    seccion: str
    orden: int
    sha_archivo: str
    alerta: str = ""
    metadatos_extra: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.sha_archivo[:12]}-{self.orden:04d}"


# ---------------------------------------------------------------------------
# Lectores por formato
# ---------------------------------------------------------------------------
def leer_markdown(path: pathlib.Path) -> list[tuple[str, str]]:
    """Parte por encabezados: la sección es una unidad semántica natural."""
    texto = path.read_text(encoding="utf-8", errors="replace")
    partes, seccion, buffer = [], path.stem, []
    for linea in texto.splitlines():
        if re.match(r"^#{1,3}\s+", linea):
            if buffer:
                partes.append((seccion, "\n".join(buffer).strip()))
                buffer = []
            seccion = re.sub(r"^#{1,3}\s+", "", linea).strip()
        else:
            buffer.append(linea)
    if buffer:
        partes.append((seccion, "\n".join(buffer).strip()))
    return [(s, t) for s, t in partes if t]


def _parece_encabezado(linea: str) -> bool:
    """Heurística: línea corta, sin punto final y que no termina en coma."""
    l = linea.strip()
    return bool(l) and len(l) < 60 and not l.endswith((".", ",", ";", ":"))


def leer_pdf(path: pathlib.Path) -> list[tuple[str, str]]:
    """Un PDF no tiene estructura: hay que inferirla.

    Devolver una página entera como una sola unidad hace que su embedding sea
    el promedio del documento, y entonces no matchea ninguna pregunta
    concreta. Partir por encabezados inferidos recupera la granularidad que
    el PDF perdió al generarse.
    """
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    salida = []
    for i, pagina in enumerate(reader.pages, start=1):
        texto = (pagina.extract_text() or "").strip()
        if not texto:
            continue
        seccion, buffer = f"página {i}", []
        for linea in texto.splitlines():
            if _parece_encabezado(linea) and buffer:
                salida.append((seccion, "\n".join(buffer).strip()))
                buffer, seccion = [], linea.strip()
            elif _parece_encabezado(linea):
                seccion = linea.strip()
            else:
                buffer.append(linea)
        if buffer:
            salida.append((seccion, "\n".join(buffer).strip()))
    return [(s, t) for s, t in salida if t]


def leer_docx(path: pathlib.Path) -> list[tuple[str, str]]:
    import docx

    doc = docx.Document(str(path))
    partes, seccion, buffer = [], path.stem, []
    for p in doc.paragraphs:
        if p.style.name.startswith("Heading"):
            if buffer:
                partes.append((seccion, "\n".join(buffer).strip()))
                buffer = []
            seccion = p.text.strip() or seccion
        elif p.text.strip():
            buffer.append(p.text)
    if buffer:
        partes.append((seccion, "\n".join(buffer).strip()))
    return [(s, t) for s, t in partes if t]


LECTORES = {
    ".md": ("markdown", leer_markdown),
    ".markdown": ("markdown", leer_markdown),
    ".txt": ("texto", leer_markdown),
    ".pdf": ("pdf", leer_pdf),
    ".docx": ("docx", leer_docx),
}


def partir_largo(texto: str, limite: int) -> list[str]:
    """Corta en párrafos (y si hace falta, en frases) con solapamiento.

    El tamaño del chunk no es un detalle de implementación: un PDF entero en
    un solo chunk tiene un embedding que es el promedio de todo el documento,
    y entonces no matchea NINGUNA pregunta específica. En la primera corrida
    la consulta por viáticos trajo la política de vacaciones por esto.
    """
    if len(texto) <= limite:
        return [texto]

    # Primero por párrafo; si un párrafo solo ya se pasa, por frase.
    unidades: list[str] = []
    for parrafo in texto.split("\n\n"):
        parrafo = parrafo.strip()
        if not parrafo:
            continue
        if len(parrafo) <= limite:
            unidades.append(parrafo)
        else:
            unidades.extend(re.findall(r"[^.!?]+[.!?]?\s*", parrafo))

    trozos, actual = [], ""
    for u in unidades:
        if len(actual) + len(u) + 1 > limite and actual:
            trozos.append(actual.strip())
            # Arrancar el siguiente con la cola del anterior.
            actual = actual[-OVERLAP:] if OVERLAP else ""
        actual += u + " "
    if actual.strip():
        trozos.append(actual.strip())
    return [t for t in trozos if t]


def escanear(texto: str) -> tuple[str, str]:
    """Devuelve (motivo, texto_saneado).

    Un chunk que hubo que SANEAR no es un chunk limpio: el escáner lo
    permitió sólo porque le sacó lo que molestaba. Contarlo como "sin
    hallazgos" hace que el reporte de ingesta diga que todo está bien
    mientras se indexa un documento con una inyección adentro.
    """
    try:
        r = httpx.post(f"{GUARDRAILS_URL}/scan/context", json={"text": texto}, timeout=30)
        v = r.json()
        if not v["allow"]:
            return v["reason"], ""
        if v.get("bloques_removidos"):
            return v.get("reason", "saneado"), v.get("sanitized", "")
        return "", ""
    except Exception as e:
        return f"no se pudo escanear: {e}", ""


def procesar(path: pathlib.Path) -> list[Chunk]:
    tipo, lector = LECTORES[path.suffix.lower()]
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    chunks, orden = [], 0
    for seccion, texto in lector(path):
        for trozo in partir_largo(texto, MAX_CHARS):
            motivo, saneado = escanear(trozo)
            # Con BLOQUEAR en 1 se indexa la versión saneada; con 0 se indexa
            # el original (la POC lo necesita para demostrar el ataque) y la
            # alerta viaja en la metadata.
            final = saneado if (BLOQUEAR and saneado) else trozo
            chunks.append(Chunk(texto=final, fuente=path.name, tipo=tipo,
                                seccion=seccion, orden=orden, sha_archivo=sha,
                                alerta=motivo))
            orden += 1
    return chunks


def main() -> None:
    if not DOCS.exists():
        sys.exit(f"no existe el directorio de documentos: {DOCS}")

    archivos = sorted(p for p in DOCS.rglob("*") if p.suffix.lower() in LECTORES)
    if not archivos:
        sys.exit(f"no hay documentos ingeribles en {DOCS} "
                 f"(formatos: {', '.join(sorted(LECTORES))})")

    client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass
    col = client.create_collection(COLLECTION, embedding_function=EmbeddingRemoto(GUARDRAILS_URL))

    ahora = datetime.now(timezone.utc).isoformat(timespec="seconds")
    indexados, cuarentena, alertados = 0, 0, 0

    print(f"{'archivo':<30}{'tipo':<10}{'chunks':>7}  alertas")
    print("-" * 64)

    for path in archivos:
        try:
            chunks = procesar(path)
        except Exception as e:
            print(f"{path.name:<30}{'ERROR':<10}{'':>7}  {e}")
            continue

        # Con BLOQUEAR, lo que no se pudo sanear directamente no entra.
        a_indexar = [c for c in chunks if not (BLOQUEAR and c.alerta and not c.texto)]
        cuarentena += len(chunks) - len(a_indexar)
        con_alerta = sum(1 for c in chunks if c.alerta)
        alertados += con_alerta

        if a_indexar:
            col.add(
                ids=[c.id for c in a_indexar],
                # El encabezado va DENTRO del texto embebido. Sin él, el chunk
                # "USD 80 por día en viajes nacionales, USD 120 en el exterior"
                # no contiene la palabra "viáticos" y no matchea la pregunta
                # que lo busca por nombre.
                documents=[f"[{c.seccion}] {c.texto}" for c in a_indexar],
                metadatas=[{
                    "fuente": c.fuente,
                    "tipo": c.tipo,
                    "seccion": c.seccion,
                    "orden": c.orden,
                    "sha_archivo": c.sha_archivo[:16],
                    "ingestado_en": ahora,
                    # La alerta viaja con el chunk: en recuperación se puede
                    # decidir qué hacer sabiendo que ya venía marcado.
                    "alerta_ingesta": c.alerta[:200],
                } for c in a_indexar],
            )
            indexados += len(a_indexar)

        marca = f"  ⚠ {con_alerta} con alerta" if con_alerta else ""
        print(f"{path.name:<30}{chunks[0].tipo if chunks else '-':<10}{len(chunks):>7}{marca}")

    print("-" * 64)
    print(f"{len(archivos)} archivos · {indexados} chunks indexados · "
          f"{alertados} con alerta · {cuarentena} en cuarentena")
    print(f"modo bloqueo en ingesta: {'ON' if BLOQUEAR else 'OFF'}"
          + ("" if BLOQUEAR else "  (la POC necesita el documento envenenado indexado)"))


if __name__ == "__main__":
    main()
