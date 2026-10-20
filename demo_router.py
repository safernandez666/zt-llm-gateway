#!/usr/bin/env python3
"""
Muestra cómo el Router clasifica cada consulta y a dónde la manda.

    python3 demo_router.py
    python3 demo_router.py --md ruteo.md

Las tres rutas del stack, con la misma identidad, para que se vea que lo que
cambia es la PREGUNTA y no quién pregunta:

  documental -> RAG sobre los documentos ingestados
  negocio    -> Business API con ABAC sobre MySQL
  general    -> directo al modelo, sin tocar datos de la empresa
"""
import argparse
import sys

try:
    import requests
except ImportError:
    sys.exit("Falta 'requests'. Instalá con:  pip install requests")

CONSULTAS = [
    "¿Cuál es el tope de viáticos en el exterior?",
    "¿Cuántos días de vacaciones me corresponden con 6 años de antigüedad?",
    "¿Cuál es el saldo del cliente García y en qué segmento está?",
    "Mostrame los datos de contacto del cliente Fernández",
    "Explicame qué es Zero Trust en dos frases",
    "¿Qué dice el onboarding sobre datos productivos?",
]


def token(base: str, usuario: str, password: str) -> str:
    r = requests.post(f"{base}/realms/zt-llm/protocol/openid-connect/token",
                      data={"grant_type": "password", "client_id": "zt-poc",
                            "username": usuario, "password": password}, timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8001")
    ap.add_argument("--keycloak", default="http://localhost:8085")
    ap.add_argument("--usuario", default="finanzas1")
    ap.add_argument("--password", default="finanzas123")
    ap.add_argument("--md", metavar="ARCHIVO")
    args = ap.parse_args()

    jwt = token(args.keycloak, args.usuario, args.password)
    filas = []

    for pregunta in CONSULTAS:
        r = requests.post(f"{args.url}/ask", json={"pregunta": pregunta},
                          headers={"Authorization": f"Bearer {jwt}"}, timeout=400)
        d = r.json()
        fuentes = ", ".join(d.get("docs_usados") or []) or "—"
        descartes = len(d.get("docs_descartados") or [])
        filas.append((pregunta, d.get("ruta", "?"), fuentes, d.get("modelo", "—"),
                      d.get("pseudonimizado"), descartes, d.get("respuesta", "")))

        print(f"\n▶ {pregunta}")
        print(f"    ruta    : {d.get('ruta')}")
        print(f"    fuentes : {fuentes}")
        print(f"    modelo  : {d.get('modelo')}"
              + ("  (pseudonimizado)" if d.get("pseudonimizado") else ""))
        if descartes:
            print(f"    descartó: {descartes} chunk(s) del RAG")
        print(f"    → {(d.get('respuesta') or d.get('motivo'))[:150]}")

    print("\n" + "=" * 92)
    print(f"{'consulta':<48}{'ruta':<12}{'modelo':<16}fuentes")
    print("-" * 92)
    for p, ruta, fuentes, modelo, pseudo, _, _ in filas:
        print(f"{p[:46]:<48}{ruta:<12}{modelo[:14]:<16}{fuentes[:34]}")

    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write("| Consulta | Ruta | Fuentes usadas | Modelo |\n")
            f.write("|---|---|---|---|\n")
            for p, ruta, fuentes, modelo, pseudo, _, _ in filas:
                sufijo = " · pseudonimizado" if pseudo else ""
                f.write(f"| {p} | `{ruta}` | {fuentes} | `{modelo}`{sufijo} |\n")
        print(f"\nTabla escrita en {args.md}")


if __name__ == "__main__":
    main()
