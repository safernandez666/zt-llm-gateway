"""
Business API con ABAC + field masking.

La idea que vale la pena del diagrama: el enmascarado pasa ACÁ, en el borde
del dato, no después en la respuesta del modelo.

Si el PAN nunca entra al contexto del LLM, entonces no importa cuán buena sea
la inyección de prompt: no hay nada para filtrar. El guardrail de salida es la
segunda red, no la primera. Casi todos los stacks que uno ve en demos tienen
sólo la segunda.

  GET /clientes?q=García
     X-Role:  soporte | finanzas | auditoria
     X-ABAC:  1 (default) | 0  -> el modo "ANTES" de la POC
"""
import os
from decimal import Decimal

import pymysql
from fastapi import FastAPI, Header, HTTPException, Query

app = FastAPI(title="Business API (ABAC)", version="1.0")

DB = dict(
    host=os.getenv("MYSQL_HOST", "mysql"),
    user=os.getenv("MYSQL_USER", "app"),
    password=os.getenv("MYSQL_PASSWORD", "apppass"),
    database=os.getenv("MYSQL_DB", "negocio"),
    # Sin esto PyMySQL decodifica como latin1 y "María García" sale
    # "MarÃ­a GarcÃ­a". Con datos en español no es un detalle estético:
    # rompe la detección de entidades aguas abajo.
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor,
    autocommit=True,
)

TODOS_LOS_CAMPOS = [
    "id", "nombre", "email", "dni", "cuit", "telefono",
    "direccion", "tarjeta", "cbu", "saldo", "segmento", "estado", "alta",
]

# ABAC: qué atributos ve cada rol. Esto es una tabla, no un if.
CAMPOS_POR_ROL: dict[str, set[str]] = {
    "soporte":   {"id", "nombre", "email", "telefono", "segmento", "estado", "alta"},
    "finanzas":  {"id", "nombre", "email", "cuit", "saldo", "segmento", "estado", "alta"},
    "auditoria": set(TODOS_LOS_CAMPOS),
}

# Cómo se tapa cada campo cuando el rol no lo puede ver.
#   "last4"  -> deja los últimos 4 (lo que PCI-DSS permite mostrar de un PAN)
#   "drop"   -> el campo no viaja
MASCARA = {
    "tarjeta": "last4",
    "cbu": "last4",
    "dni": "drop",
    "cuit": "drop",
    "saldo": "drop",
    "email": "drop",
    "telefono": "drop",
    "direccion": "drop",
}


def conectar():
    return pymysql.connect(**DB)


def enmascarar(fila: dict, rol: str) -> dict:
    permitidos = CAMPOS_POR_ROL.get(rol, CAMPOS_POR_ROL["soporte"])
    out = {}
    for campo, valor in fila.items():
        if campo in permitidos:
            out[campo] = valor
            continue
        modo = MASCARA.get(campo, "drop")
        if modo == "last4" and valor:
            out[campo] = "*" * max(len(str(valor)) - 4, 0) + str(valor)[-4:]
        # "drop": el campo simplemente no aparece en la respuesta
    return out


def serializable(fila: dict) -> dict:
    return {
        k: (float(v) if isinstance(v, Decimal) else str(v) if hasattr(v, "isoformat") else v)
        for k, v in fila.items()
    }


@app.get("/health")
def health():
    # Tiene que devolver 503 si MySQL no responde. Si devolviera 200 con un
    # {"status": "degraded"} adentro, el healthcheck de compose lo daría por
    # sano y el resto del stack arrancaría contra una API que no sirve datos.
    try:
        with conectar() as c, c.cursor() as cur:
            cur.execute("SELECT 1")
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=503, detail={"status": "degraded", "error": str(e)})


@app.get("/clientes")
def clientes(
    q: str = Query("", description="Búsqueda por nombre o email"),
    limit: int = Query(5, ge=1, le=50),
    x_role: str = Header("soporte"),
    x_abac: str = Header("1"),
):
    sql = "SELECT * FROM clientes"
    params: list = []
    if q:
        sql += " WHERE nombre LIKE %s OR email LIKE %s"
        params = [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY id LIMIT %s"
    params.append(limit)

    with conectar() as c, c.cursor() as cur:
        cur.execute(sql, params)
        filas = [serializable(f) for f in cur.fetchall()]

    abac_activo = x_abac != "0"
    if abac_activo:
        filas = [enmascarar(f, x_role) for f in filas]

    return {
        "rol": x_role,
        "abac": abac_activo,
        "campos_visibles": sorted(CAMPOS_POR_ROL.get(x_role, set())) if abac_activo else TODOS_LOS_CAMPOS,
        "resultados": filas,
    }
