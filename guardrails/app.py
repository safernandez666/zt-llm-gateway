"""
Servicio de guardrails del Zero Trust LLM Gateway.

Tres trabajos distintos que la gente suele meter en la misma caja:

  1. PII  — detectar personas, mails, teléfonos, DNI, CUIT.
  2. PCI  — detectar PAN de tarjeta (Luhn) y CBU.
  3. Prompt injection — detectar que alguien intenta reescribir las reglas.

Los dos primeros son determinísticos (patrón + checksum): Presidio los
resuelve bien y sin falsos positivos raros. El tercero NO es un problema de
patrones, es un problema de clasificación — por eso acá hay un motor
heurístico (rápido, offline) y la opción de un clasificador entrenado.

Tratar los tres como "el guardrail" es el error más común del stack.

Endpoints:
  POST /scan/input    ¿dejo pasar esto al modelo?
  POST /scan/context  ¿el documento que trajo el RAG intenta darme órdenes?
  POST /scan/output   ¿qué tengo que tapar antes de devolverlo?
"""
import os
import re
from typing import Literal

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field

PRESIDIO_URL = os.getenv("PRESIDIO_URL", "http://presidio-analyzer:3000")
INJECTION_ENGINE = os.getenv("INJECTION_ENGINE", "heuristic")
INJECTION_THRESHOLD = float(os.getenv("INJECTION_THRESHOLD", "0.5"))

app = FastAPI(title="Zero Trust Guardrails", version="1.0")

# ---------------------------------------------------------------------------
# 1 y 2 — PII / PCI
# ---------------------------------------------------------------------------
# Presidio cubre lo universal (tarjeta con Luhn, mail, teléfono, IBAN).
# Lo local lo ponemos nosotros: Presidio no sabe qué es un DNI argentino.
PRESIDIO_ENTITIES = [
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
    # PERSON queda AFUERA a propósito.
    #
    # La imagen oficial de Presidio trae el modelo spaCy en inglés. Sobre texto
    # en español, su NER de personas marca cualquier cosa: en la prueba dio
    # PERSON con score 0.85 para "¿Cuál es el" y para "comidas de trabajo".
    # Un detector de PII que tapa frases al azar no se usa dos veces: el equipo
    # lo apaga y te quedás sin ningún control.
    #
    # Lo que detecta por patrón + checksum (tarjeta con Luhn, mail, teléfono,
    # IBAN) funciona igual en cualquier idioma, y eso es lo que dejamos.
    # Para detectar nombres en español hace falta una imagen de Presidio con
    # es_core_news_lg, que es trabajo aparte y conviene medir antes de activar.
]

# NER en español. Presidio resuelve lo que es patrón + checksum (tarjeta con
# Luhn, mail, teléfono, IBAN), que funciona igual en cualquier idioma. Los
# nombres NO son un patrón: son un problema de modelo, y el modelo tiene que
# estar en el idioma del texto. Por eso va acá y no en Presidio.
_nlp = None


def nlp():
    global _nlp
    if _nlp is None:
        import spacy
        _nlp = spacy.load("es_core_news_md")
    return _nlp


SPACY_A_ENTIDAD = {"PER": "PERSONA", "LOC": "UBICACION", "ORG": "ORGANIZACION"}

# Términos técnicos que el NER confunde con nombres propios. es_core_news_md
# etiqueta "Zero Trust" como PERSONA, y entonces la consulta que sale es
# "explicame qué es <<PERSONA_1>>" — el modelo responde que es "una persona
# clave de la organización" y el asistente queda haciendo papelones.
#
# Esto es un parche y tiene su propio agujero: si mañana un cliente se llama
# como un término de la lista, su nombre viaja en claro. Por eso la lista es
# corta, explícita y versionada, y NO reemplaza la tokenización por esquema:
# todo lo que sale de una columna de la base no pasa por el NER.
NUNCA_SON_PII = {x.strip().lower() for x in os.getenv(
    "NUNCA_SON_PII",
    "zero trust,kubernetes,docker,python,javascript,linux,windows,active directory,"
    "machine learning,open source,prompt injection,single sign-on,llm,rag"
).split(",") if x.strip()}


def detectar_nombres(text: str) -> list["Finding"]:
    try:
        doc = nlp()(text)
    except Exception:
        return []
    out = []
    for ent in doc.ents:
        entidad = SPACY_A_ENTIDAD.get(ent.label_)
        if not entidad:
            continue
        if ent.text.strip().lower() in NUNCA_SON_PII:
            continue
        out.append(Finding(entity=entidad, start=ent.start_char, end=ent.end_char,
                           score=0.80, clase="PII", text=ent.text))
    return out


LOCAL_RECOGNIZERS: list[tuple[str, re.Pattern]] = [
    # CUIT/CUIL: 20-30111222-3 (también sin guiones).
    ("CUIT_AR", re.compile(r"\b(?:20|23|24|27|30|33|34)[-\s]?\d{8}[-\s]?\d\b")),
    # CBU: 22 dígitos corridos.
    ("CBU_AR", re.compile(r"\b\d{22}\b")),
    # DNI: 7 u 8 dígitos, con o sin puntos. Va último para no comerse CUIT/CBU.
    ("DNI_AR", re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}\b")),
]

# Qué es PCI y qué es PII cambia la obligación legal, el plazo de retención
# y a quién hay que avisar. Por eso se etiquetan distinto en la redacción.
PCI_ENTITIES = {"CREDIT_CARD", "CBU_AR", "IBAN_CODE"}
PII_ENTITIES = {"EMAIL_ADDRESS", "PHONE_NUMBER", "DNI_AR", "CUIT_AR",
                "PERSONA", "UBICACION", "ORGANIZACION"}


class Finding(BaseModel):
    entity: str
    start: int
    end: int
    score: float
    clase: Literal["PCI", "PII"]
    text: str = ""


def _clase(entity: str) -> Literal["PCI", "PII"]:
    return "PCI" if entity in PCI_ENTITIES else "PII"


async def detect_entities(text: str) -> list[Finding]:
    """Presidio para lo universal + regex locales para lo argentino."""
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                f"{PRESIDIO_URL}/analyze",
                json={
                    "text": text,
                    "language": "en",  # el modelo spaCy de la imagen oficial es en_core_web_lg
                    "entities": PRESIDIO_ENTITIES,
                    "score_threshold": 0.45,
                },
            )
            r.raise_for_status()
            for item in r.json():
                ent = item["entity_type"]
                findings.append(
                    Finding(
                        entity=ent,
                        start=item["start"],
                        end=item["end"],
                        score=item["score"],
                        clase=_clase(ent),
                        text=text[item["start"]:item["end"]],
                    )
                )
    except Exception:
        # Si Presidio se cae, los regex locales siguen tapando lo más grave.
        # Fallar abierto en PCI no es opción: lo registramos como hallazgo.
        findings.append(
            Finding(entity="PRESIDIO_UNAVAILABLE", start=0, end=0, score=1.0, clase="PII")
        )

    findings.extend(detectar_nombres(text))

    for name, pattern in LOCAL_RECOGNIZERS:
        for m in pattern.finditer(text):
            findings.append(
                Finding(
                    entity=name,
                    start=m.start(),
                    end=m.end(),
                    score=0.85,
                    clase=_clase(name),
                    text=m.group(),
                )
            )

    return _fuera_de_tokens(text, _dedupe(findings))


TOKEN_RE = re.compile(r"<<[A-Z_]+_\d+>>|<<DATO_PCI_REMOVIDO>>")


def _fuera_de_tokens(text: str, findings: list[Finding]) -> list[Finding]:
    """Descarta hallazgos que caen adentro de un token de pseudonimización."""
    rangos = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
    if not rangos:
        return findings
    return [f for f in findings
            if not any(f.start >= a and f.end <= b for a, b in rangos)]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Se queda con el span más largo cuando dos reconocedores se pisan.

    Un CBU de 22 dígitos también matchea como DNI. Gana el más específico,
    que acá es siempre el más largo.
    """
    real = [f for f in findings if f.end > f.start]
    real.sort(key=lambda f: (f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    for f in real:
        if any(f.start >= k.start and f.end <= k.end for k in kept):
            continue
        kept.append(f)
    kept.extend(f for f in findings if f.end <= f.start)
    return kept


def redact(text: str, findings: list[Finding], allow: set[str]) -> tuple[str, list[Finding]]:
    """Reemplaza por [REDACTED:PCI] / [REDACTED:PII] lo que el rol no puede ver."""
    tapar = [f for f in findings if f.entity not in allow and f.end > f.start]
    tapar.sort(key=lambda f: f.start, reverse=True)
    out = text
    for f in tapar:
        out = out[: f.start] + f"[REDACTED:{f.clase}]" + out[f.end:]
    return out, tapar


# ---------------------------------------------------------------------------
# 3 — Prompt injection
# ---------------------------------------------------------------------------
# Cada patrón suma. Ninguno solo alcanza para bloquear: "ignorá" puede ser
# una palabra normal. La combinación es la señal.
INJECTION_PATTERNS: list[tuple[str, float, re.Pattern]] = [
    ("override_instrucciones", 0.50, re.compile(
        r"\b(ignor|olvid|descart|desestim)\w*\b[^.]{0,40}\b"
        r"(instruccion|indicacion|regla|prompt|anterior|previo|todo lo anterior)", re.I)),
    ("override_instructions_en", 0.50, re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.]{0,40}\b"
        r"(previous|prior|above|all)\b[^.]{0,20}\b(instruction|prompt|rule)", re.I)),
    ("revelar_system_prompt", 0.40, re.compile(
        r"(system prompt|prompt del sistema|tus instrucciones|your instructions|"
        r"initial prompt|reglas que te dieron)", re.I)),
    ("cambio_de_rol", 0.35, re.compile(
        r"\b(act[uú][aá]|comport[aá]te|hac[eé] de cuenta|pretend|act as|you are now|"
        r"ahora sos|a partir de ahora sos)\b", re.I)),
    ("jailbreak_conocido", 0.50, re.compile(
        r"\b(DAN mode|developer mode|jailbreak|do anything now|sin restricciones|"
        r"modo desarrollador|unfiltered)\b", re.I)),
    ("desactivar_controles", 0.50, re.compile(
        r"(no apliques|sin aplicar|desactiv[aá]|omit[ií]|salte[aá]te|bypass)\b[^.]{0,30}"
        r"\b(filtro|guardrail|control|pol[ií]tica|restricci[oó]n|censura|policy|filter)", re.I)),
    # Deliberadamente agresivo: no hay motivo legítimo para pedirle al
    # asistente interno que empuje datos a una URL externa. Bloquea solo.
    ("exfiltracion", 0.55, re.compile(
        r"(envi[aá]|mand[aá]|post[eé]a|send|exfiltrat|sube|upload)\b[^.]{0,40}"
        r"(http://|https://|webhook|pastebin|attacker)", re.I)),
    ("volcado_masivo", 0.40, re.compile(
        r"(list[aá]|dame|mostrame|dump|devolv[eé]|export[aá])\b[^.]{0,30}\b"
        r"(todos|todas|all)\b[^.]{0,30}\b"
        r"(tarjeta|card|cliente|customer|usuario|password|credencial|dni|cuit|saldo)", re.I)),
    ("delimitadores_falsos", 0.35, re.compile(
        r"(<\|im_start\|>|<\|system\|>|\[/?INST\]|###\s*(system|instruction)|"
        r"BEGIN SYSTEM|</?system>)", re.I)),
    # Específico de inyección indirecta: un documento no le habla al modelo.
    ("documento_que_da_ordenes", 0.55, re.compile(
        r"\b(asistente|assistant|modelo|chatbot)\b[^.]{0,30}\b"
        r"(deb[eé]\w*|ten[eé]s que|tiene que|must|should|always|siempre que)", re.I)),
]

_ml_pipeline = None


def _heuristic_score(text: str) -> tuple[float, list[str]]:
    score, hits = 0.0, []
    for name, weight, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            score += weight
            hits.append(name)
    return min(score, 1.0), hits


def _model_score(text: str) -> tuple[float, list[str]]:
    """Clasificador deberta. Sólo disponible en el profile guardrails-ml."""
    global _ml_pipeline
    if _ml_pipeline is None:
        from transformers import pipeline  # import tardío: no existe en la imagen base

        _ml_pipeline = pipeline(
            "text-classification",
            model="protectai/deberta-v3-base-prompt-injection-v2",
            truncation=True,
            max_length=512,
        )
    result = _ml_pipeline(text)[0]
    if result["label"] == "INJECTION":
        return float(result["score"]), ["clasificador:INJECTION"]
    return 1.0 - float(result["score"]), []


MOTORES = {
    "heuristic": _heuristic_score,
    "model": _model_score,
}


def score_injection(text: str, engine: str | None = None) -> tuple[float, list[str]]:
    """El motor puede venir por request, para poder compararlos sin redeployar."""
    nombre = engine or INJECTION_ENGINE
    fn = MOTORES.get(nombre)
    if fn and nombre != "heuristic":
        try:
            return fn(text)
        except Exception as e:
            # Nunca quedarse sin ningún control: si el modelo no carga, las
            # heurísticas siguen de pie y el motivo queda registrado.
            return _heuristic_score(text)[0], [f"fallback_heuristico({nombre}: {type(e).__name__}: {e})"]
    return _heuristic_score(text)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    text: str
    # Permite pedir un motor puntual sin redeployar: sirve para comparar.
    engine: str | None = None
    # Valores que el llamador ya sabe que son PII, con su tipo.
    forzar: list[tuple[str, str]] = Field(default_factory=list)
    # Entidades que este rol SÍ puede ver. Lo decide el policy engine, no acá.
    allow_entities: list[str] = Field(default_factory=list)
    threshold: float | None = None


class InputScanResponse(BaseModel):
    allow: bool
    injection_score: float
    injection_hits: list[str]
    findings: list[Finding]
    reason: str = ""
    # Sólo para /scan/context: el documento con los bloques inyectados fuera.
    sanitized: str = ""
    bloques_removidos: int = 0
    # El score del texto YA SANEADO. Separado del original a propósito:
    # devolver sólo este hacía que un documento detectado y limpiado se
    # viera igual que uno que nunca disparó nada.
    score_saneado: float | None = None


class OutputScanResponse(BaseModel):
    text: str
    redacted: bool
    findings: list[Finding]


@app.get("/health")
def health():
    return {"status": "ok", "injection_engine": INJECTION_ENGINE,
            "motores": sorted(MOTORES)}


@app.post("/scan/input", response_model=InputScanResponse)
async def scan_input(req: ScanRequest):
    """Lo que escribe el usuario, antes de tocar el modelo."""
    threshold = req.threshold if req.threshold is not None else INJECTION_THRESHOLD
    score, hits = score_injection(req.text, req.engine)
    findings = await detect_entities(req.text)

    if score >= threshold:
        return InputScanResponse(
            allow=False, injection_score=score, injection_hits=hits, findings=findings,
            reason=f"prompt injection detectada (score {score:.2f}): {', '.join(hits)}",
        )

    # Que el usuario pegue una tarjeta en el prompt también es un incidente:
    # ese PAN termina en el contexto del modelo y en los logs del proveedor.
    pci = [f for f in findings if f.clase == "PCI" and f.entity not in req.allow_entities]
    if pci:
        return InputScanResponse(
            allow=False, injection_score=score, injection_hits=hits, findings=findings,
            reason=f"dato PCI en el prompt: {', '.join(sorted({f.entity for f in pci}))}",
        )

    return InputScanResponse(
        allow=True, injection_score=score, injection_hits=hits, findings=findings
    )


@app.post("/scan/context", response_model=InputScanResponse)
async def scan_context(req: ScanRequest):
    """Lo que trajo el RAG, antes de meterlo en el contexto.

    Mismo scanner que /scan/input, con el umbral más bajo: un documento
    corporativo no tiene ningún motivo para decirle al modelo qué hacer.
    Si lo hace, alguien lo plantó.

    Pero descartar el documento entero es un remedio peor que la enfermedad.
    El documento envenenado de la POC es el único que tiene el tope de
    viáticos: si lo tirás, el guardrail te salva de la inyección y te deja
    sin la respuesta legítima. El usuario ve "no tengo el dato", nadie
    entiende por qué, y a la semana alguien baja el umbral.

    Así que primero SANEAMOS: se cae el párrafo que contiene la inyección y
    el resto del documento sigue sirviendo. Sólo si lo que queda todavía
    dispara, se descarta entero.
    """
    threshold = req.threshold if req.threshold is not None else 0.30
    score, hits = score_injection(req.text, req.engine)

    if score < threshold:
        return InputScanResponse(allow=True, injection_score=score,
                                 injection_hits=hits, findings=[], sanitized=req.text)

    # Párrafo por párrafo... salvo que no haya párrafos.
    #
    # Dividir por "\n\n" funciona perfecto en Markdown y falla en PDF: el
    # texto que extraés de un PDF viene como un bloque con saltos de línea
    # simples. Ahí el saneo no encuentra dónde cortar, se queda con un solo
    # bloque que dispara, y descarta el documento entero — que es el mismo
    # daño que queríamos evitar, con otra cara.
    def dividir(texto: str) -> list[str]:
        for sep in ("\n\n", "\n"):
            partes = [x for x in texto.split(sep) if x.strip()]
            if len(partes) > 1:
                return partes
        # Último recurso: por frases.
        return [x for x in re.findall(r"[^.!?]+[.!?]?\s*", texto) if x.strip()]

    parrafos = dividir(req.text)
    limpios = [p for p in parrafos if score_injection(p)[0] < threshold]
    removidos = len(parrafos) - len(limpios)
    # Un título que se quedó sin su párrafo es ruido en el contexto.
    def solo_titulo(parrafo: str) -> bool:
        lineas = parrafo.strip().splitlines()
        return len(lineas) == 1 and lineas[0].lstrip().startswith("#")

    while limpios and solo_titulo(limpios[-1]):
        limpios.pop()
    union = "\n\n" if "\n\n" in req.text else ("\n" if "\n" in req.text else " ")
    saneado = union.join(limpios).strip()

    score_final, hits_final = score_injection(saneado) if saneado else (1.0, hits)

    if not saneado or score_final >= threshold:
        return InputScanResponse(
            allow=False, injection_score=score, injection_hits=hits, findings=[],
            bloques_removidos=removidos,
            reason=(f"inyección indirecta no saneable, documento descartado "
                    f"(score {score:.2f}): {', '.join(hits)}"),
        )

    return InputScanResponse(
        allow=True, injection_score=score, injection_hits=hits, findings=[],
        sanitized=saneado, bloques_removidos=removidos, score_saneado=score_final,
        reason=(f"inyección indirecta saneada: {removidos} bloque(s) removido(s) "
                f"(score original {score:.2f}): {', '.join(hits)}"),
    )


@app.post("/scan/output", response_model=OutputScanResponse)
async def scan_output(req: ScanRequest):
    """La última red. Lo que el rol no puede ver, no sale.

    Recibe en `forzar` los valores que el sistema YA SABE que son PII —los
    que la re-hidratación acaba de restituir— para no depender de volver a
    detectarlos. Lo declarado no se vuelve a adivinar.
    """
    findings = await detect_entities(req.text)
    for valor, entidad in req.forzar:
        valor = (valor or "").strip()
        if len(valor) < 3:
            continue
        for m in re.finditer(re.escape(valor), req.text):
            findings.append(Finding(entity=entidad, start=m.start(), end=m.end(),
                                    score=1.0, clase=_clase(entidad), text=valor))
    findings = _dedupe(findings)
    texto, tapados = redact(req.text, findings, set(req.allow_entities))
    return OutputScanResponse(text=texto, redacted=bool(tapados), findings=tapados)


# ---------------------------------------------------------------------------
# 4 — Pseudonimización reversible: cómo mandarle contexto de la empresa a un
#     modelo de frontera sin que el dato cruce el borde.
# ---------------------------------------------------------------------------
# La pregunta real de cualquier empresa no es "¿uso IA o no?". Es "¿puedo usar
# el modelo bueno sobre MIS datos?". Decir "lo sensible se queda on-prem"
# resuelve el compliance y no resuelve el problema: el equipo quiere GPT sobre
# los datos del negocio, y si no se lo das, lo pegan a mano en el chat personal.
#
# La salida es que el dato sensible se reemplace por un token ANTES de salir,
# y se restituya DESPUÉS de volver. El proveedor ve:
#
#     "¿Cuánto debe <<PERSONA_1>>?"  →  "<<PERSONA_1>> debe $152.340,75"
#
# y el usuario ve "María García debe $152.340,75". El modelo razona igual: no
# necesita saber el nombre para comparar saldos o resumir un caso.
#
# PAN y CBU NO entran acá. Se reemplazan por un token irreversible que nunca
# se restituye. Mandar un PAN tokenizado seguiría metiendo al proveedor en el
# alcance de PCI-DSS, y no hay caso de uso que lo justifique.

VAULT: dict[str, dict[str, str]] = {}
VAULT_TTL_SEG = 900
_vault_ts: dict[str, float] = {}

# Lo que se tokeniza de forma IRREVERSIBLE: sale como marca y no vuelve nunca.
PCI_IRREVERSIBLE = {"CREDIT_CARD", "CBU_AR", "IBAN_CODE"}
TOKEN_PCI = "<<DATO_PCI_REMOVIDO>>"

# Qué se tokeniza al salir a la nube. La lista es corta a propósito.
#
# Tokenizar TODO lo que el NER detecta suena más seguro y es peor: spaCy
# etiqueta "Zero Trust" como organización, y entonces la consulta que sale es
# "explicame qué es <<ORGANIZACION_1>>", que el modelo no puede responder.
# El usuario ve un asistente inútil y se va a ChatGPT por su cuenta — que es
# exactamente el riesgo que este stack venía a evitar.
#
# Tokenizamos lo que IDENTIFICA a una persona o una cuenta. Ubicaciones y
# organizaciones quedan afuera: no identifican por sí solas, y el domicilio
# de un cliente ya lo enmascara el ABAC en el borde del dato, que es donde
# corresponde.
PSEUDO_ENTIDADES = set(
    os.getenv("PSEUDO_ENTIDADES",
              "PERSONA,EMAIL_ADDRESS,PHONE_NUMBER,DNI_AR,CUIT_AR").split(",")
)


def _purgar_vault() -> None:
    import time
    ahora = time.time()
    for sid in [s for s, t in _vault_ts.items() if ahora - t > VAULT_TTL_SEG]:
        VAULT.pop(sid, None)
        _vault_ts.pop(sid, None)


class PseudoRequest(BaseModel):
    text: str
    session_id: str
    # Valores que el llamador SABE que son PII, con su tipo. Vienen de las
    # columnas de la base: el NER no tiene que adivinar lo que el esquema
    # ya declara.
    forzar: list[tuple[str, str]] = Field(default_factory=list)


class PseudoResponse(BaseModel):
    text: str
    session_id: str
    tokens: dict[str, str] = Field(default_factory=dict)   # token -> entidad
    pci_removido: int = 0


class RehidratarRequest(BaseModel):
    text: str
    session_id: str


class RehidratarResponse(BaseModel):
    text: str
    restituidos: int = 0
    # (valor, entidad) de todo lo que se volvió a poner en el texto.
    #
    # Sin esto, el guardrail de salida tiene que RE-DETECTAR lo que el
    # sistema ya sabía a la ida. Y la detección falla donde la declaración
    # no: Presidio no reconoce el formato de teléfono argentino, así que un
    # número que salió tokenizado porque la columna se llamaba `telefono`
    # volvía re-hidratado y pasaba derecho el filtro de salida.
    detalle: list[tuple[str, str]] = Field(default_factory=list)


@app.post("/pseudonimizar", response_model=PseudoResponse)
async def pseudonimizar(req: PseudoRequest):
    """Reemplaza entidades por tokens antes de mandar el texto afuera."""
    import time
    _purgar_vault()

    findings = [f for f in await detect_entities(req.text) if f.end > f.start]

    # Los valores declarados se buscan literalmente. Esto no es un refuerzo
    # del NER: es lo que lo reemplaza para todo lo que viene de un esquema.
    #
    # El NER en texto libre es best-effort y se equivoca de maneras que no
    # podés prever: es_core_news_md etiqueta "El cliente María García" como
    # MISC y no como persona, así que el nombre sale en claro. Para un dato
    # que salió de la columna `nombre` de una tabla, confiar en un modelo
    # probabilístico es una decisión difícil de defender.
    for valor, entidad in req.forzar:
        valor = (valor or "").strip()
        if len(valor) < 3:
            continue
        for m in re.finditer(re.escape(valor), req.text):
            findings.append(Finding(entity=entidad, start=m.start(), end=m.end(),
                                    score=1.0, clase=_clase(entidad), text=valor))

    findings = _dedupe(findings)
    findings.sort(key=lambda f: f.start, reverse=True)

    mapa = VAULT.setdefault(req.session_id, {})
    _vault_ts[req.session_id] = time.time()
    # Mismo valor → mismo token dentro de la sesión. Si "María García" aparece
    # tres veces, el modelo tiene que poder ver que son la misma persona.
    valor_a_token = {v: k for k, v in mapa.items()}
    contadores: dict[str, int] = {}
    for token in mapa:
        ent = token.strip("<>").rsplit("_", 1)[0]
        contadores[ent] = max(contadores.get(ent, 0), int(token.strip("<>").rsplit("_", 1)[1]))

    texto = req.text
    tokens: dict[str, str] = {}
    pci = 0

    # Los reemplazos se hacen de atrás para adelante (para no correr los
    # offsets), pero la NUMERACIÓN se asigna en orden de lectura: si no,
    # <<UBICACION_2>> aparece antes que <<UBICACION_1>> y el texto que recibe
    # el modelo se lee como si faltara algo.
    def token_relacionado(valor: str) -> str | None:
        """Busca un token ya asignado a un valor que contenga a éste (o al revés)."""
        v = valor.strip().lower()
        if len(v) < 3:
            return None
        for conocido, tok in valor_a_token.items():
            c = conocido.strip().lower()
            if v == c:
                return tok
            # Coincidencia por palabra completa en cualquiera de los dos sentidos.
            if re.search(rf"\b{re.escape(v)}\b", c) or re.search(rf"\b{re.escape(c)}\b", v):
                return tok
        return None

    for f in sorted(findings, key=lambda f: f.start):
        if f.entity in PCI_IRREVERSIBLE or f.entity not in PSEUDO_ENTIDADES:
            continue
        original = req.text[f.start:f.end]
        if original not in valor_a_token:
            emparentado = token_relacionado(original)
            if emparentado:
                valor_a_token[original] = emparentado
                continue
            contadores[f.entity] = contadores.get(f.entity, 0) + 1
            t = f"<<{f.entity}_{contadores[f.entity]}>>"
            mapa[t] = original
            valor_a_token[original] = t

    for f in findings:
        original = texto[f.start:f.end]
        if f.entity in PCI_IRREVERSIBLE:
            texto = texto[:f.start] + TOKEN_PCI + texto[f.end:]
            pci += 1
            continue
        if f.entity not in PSEUDO_ENTIDADES:
            continue   # no identifica por sí solo: viaja tal cual
        token = valor_a_token.get(original)
        if token is None:
            contadores[f.entity] = contadores.get(f.entity, 0) + 1
            token = f"<<{f.entity}_{contadores[f.entity]}>>"
            mapa[token] = original
            valor_a_token[original] = token
        tokens[token] = f.entity
        texto = texto[:f.start] + token + texto[f.end:]

    return PseudoResponse(text=texto, session_id=req.session_id, tokens=tokens, pci_removido=pci)


@app.post("/rehidratar", response_model=RehidratarResponse)
async def rehidratar(req: RehidratarRequest):
    """Restituye los valores reales en la respuesta que volvió del proveedor."""
    _purgar_vault()
    mapa = VAULT.get(req.session_id, {})
    texto = req.text
    n, detalle = 0, []
    # De token más largo a más corto: <<PERSONA_10>> antes que <<PERSONA_1>>,
    # si no el reemplazo del corto deja un "0" colgado.
    for token in sorted(mapa, key=len, reverse=True):
        if token in texto:
            texto = texto.replace(token, mapa[token])
            entidad = token.strip("<>").rsplit("_", 1)[0]
            detalle.append((mapa[token], entidad))
            n += 1
    return RehidratarResponse(text=texto, restituidos=n, detalle=detalle)


@app.delete("/vault/{session_id}")
async def borrar_vault(session_id: str):
    """El mapa se borra cuando termina la conversación. En producción esto va
    a Redis con TTL y cifrado en reposo, no en memoria del proceso."""
    VAULT.pop(session_id, None)
    _vault_ts.pop(session_id, None)
    return {"ok": True}



# ---------------------------------------------------------------------------
# 5 — Embeddings multilingües para el RAG
# ---------------------------------------------------------------------------
# El embedding por defecto de Chroma es all-MiniLM-L6-v2, entrenado en INGLÉS.
# Sobre un corpus en castellano las distancias quedan casi indiferenciadas:
# en la POC, la consulta "¿cuál es el tope de viáticos en el exterior?" dejaba
# fuera del top 8 al único chunk que decía "USD 120 en el exterior", con todas
# las distancias apretadas entre 1.08 y 1.26.
#
# Lo peor es que no se nota: el LLM responde razonable con casi cualquier
# contexto de un corpus chico, así que un RAG roto parece un RAG que anda.
# Hasta que la base crece y empieza a citar el documento equivocado.
EMBED_MODEL = os.getenv("EMBED_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
_embedder = None


def embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer

        _embedder = SentenceTransformer(EMBED_MODEL)
    return _embedder


class EmbedRequest(BaseModel):
    textos: list[str]


class EmbedResponse(BaseModel):
    modelo: str
    dimension: int
    vectores: list[list[float]]


@app.post("/embed", response_model=EmbedResponse)
async def embed(req: EmbedRequest):
    vs = embedder().encode(req.textos, normalize_embeddings=True).tolist()
    return EmbedResponse(modelo=EMBED_MODEL, dimension=len(vs[0]) if vs else 0, vectores=vs)



# ---------------------------------------------------------------------------
# 6 — Reranking: el bi-encoder recupera grueso, el cross-encoder ordena
# ---------------------------------------------------------------------------
# El embedding compara la pregunta y el documento por separado y después mide
# la distancia entre los dos vectores. Es rápido y sirve para traer candidatos,
# pero es tosco: en la POC, "¿qué dice el onboarding sobre datos productivos?"
# traía primero tres chunks de la política de viajes, y el que respondía
# quedaba cuarto.
#
# Un cross-encoder lee la pregunta Y el documento juntos y devuelve una
# puntuación de relevancia real. Es más caro, por eso se usa en dos etapas:
# el bi-encoder trae 10 candidatos, el cross-encoder los ordena y se quedan 3.
#
# Para seguridad esto no es sólo calidad de respuesta: cada chunk irrelevante
# que entra al contexto es superficie de ataque. Un documento envenenado que
# no tiene nada que ver con la pregunta no debería llegar al prompt.
RERANK_MODEL = os.getenv("RERANK_MODEL", "cross-encoder/mmarco-mMiniLMv2-L12-H384-v1")
_reranker = None


def reranker():
    global _reranker
    if _reranker is None:
        from sentence_transformers import CrossEncoder

        _reranker = CrossEncoder(RERANK_MODEL, max_length=512)
    return _reranker


class RerankRequest(BaseModel):
    pregunta: str
    documentos: list[str]
    top_k: int = 3
    # Fracción del MEJOR puntaje que un candidato tiene que alcanzar para
    # entrar al contexto.
    #
    # Relativo y no absoluto a propósito: los puntajes del cross-encoder se
    # mueven mucho según la pregunta. En la POC, "viáticos en el exterior"
    # da 0.444 al mejor chunk y "onboarding sobre datos productivos" da
    # 0.0415 — y los dos aciertan. Un corte fijo en 0.05 habría dejado la
    # segunda consulta sin ningún contexto, con el reranker funcionando bien.
    #
    # Lo que importa no es cuán alto puntúa el mejor, sino cuánto se despega
    # del resto.
    umbral_relativo: float = 0.25


class RerankItem(BaseModel):
    indice: int
    score: float


class RerankResponse(BaseModel):
    modelo: str
    elegidos: list[RerankItem]
    descartados: list[RerankItem]


@app.post("/rerank", response_model=RerankResponse)
async def rerank(req: RerankRequest):
    if not req.documentos:
        return RerankResponse(modelo=RERANK_MODEL, elegidos=[], descartados=[])

    import math

    pares = [(req.pregunta, d) for d in req.documentos]
    # El cross-encoder devuelve logits, que pueden ser negativos. Sin la
    # sigmoide, cualquier umbral "razonable" como 0.0 descarta todo y el
    # contexto llega vacío — con el modelo funcionando perfecto.
    puntajes = [1 / (1 + math.exp(-float(x))) for x in reranker().predict(pares)]

    ordenados = sorted(enumerate(puntajes), key=lambda x: float(x[1]), reverse=True)
    mejor = float(ordenados[0][1])
    corte = mejor * req.umbral_relativo

    elegidos, descartados = [], []
    for i, sc in ordenados:
        item = RerankItem(indice=i, score=float(sc))
        # El mejor siempre entra: si no, una consulta sin buenos candidatos
        # se queda sin contexto y el asistente dice "no tengo el dato" sin
        # que nadie pueda saber por qué.
        if not elegidos or (len(elegidos) < req.top_k and float(sc) >= corte):
            elegidos.append(item)
        else:
            descartados.append(item)
    return RerankResponse(modelo=RERANK_MODEL, elegidos=elegidos, descartados=descartados)
