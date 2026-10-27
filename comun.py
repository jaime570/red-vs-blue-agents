"""
comun.py
==================================================================
Utilidades compartidas por las dos versiones del duelo:
  - duelo_seguridad.py      (API de Anthropic en crudo)
  - duelo_seguridad_sdk.py  (Claude Agent SDK, agentes con herramientas)

Aquí vive todo lo que no depende de cómo se llama al modelo:
severidades, puntuación, parseo del JSON y salida por consola.
==================================================================
"""

import re
import json
import textwrap
import unicodedata

# OJO: las claves van SIN tilde y en MAYÚSCULAS porque comparamos
# siempre con normalizar_sev(), que quita acentos y pasa a mayúsculas.
# Así "Crítica", "CRITICA" y "CRÍTICA" cuentan todas igual.
SEVERIDADES_BLOQUEANTES = {"CRITICA", "ALTA"}  # si quedan de estas, no hay victoria azul

# Puntos por severidad (para el marcador del "duelo")
PESOS = {"CRITICA": 10, "ALTA": 6, "MEDIA": 3, "BAJA": 1}


class C:
    """Colores ANSI para la consola (puramente cosmético)."""
    ROJO = "\033[91m"
    AZUL = "\033[94m"
    VERDE = "\033[92m"
    AMAR = "\033[93m"
    GRIS = "\033[90m"
    NEG = "\033[1m"
    OFF = "\033[0m"


class InformeInvalido(Exception):
    """El agente rojo no devolvió un informe JSON utilizable.

    Se lanza en lugar de devolver una lista vacía: una lista vacía
    significaría "código limpio" y daría la victoria al azul por error."""


def normalizar_sev(sev) -> str:
    """Pasa una severidad a forma canónica: mayúsculas y sin tildes.
    'Crítica' -> 'CRITICA', 'alta' -> 'ALTA'. Así no dependemos de
    cómo escriba exactamente el modelo la palabra."""
    s = str(sev or "").strip().upper()
    # NFD descompone 'Í' en 'I' + tilde; quitamos los acentos (categoría Mn).
    return "".join(c for c in unicodedata.normalize("NFD", s)
                   if unicodedata.category(c) != "Mn")


def parsear_json(texto: str):
    """Extrae el JSON aunque venga con texto antes/después o envuelto en
    vallas ```json ... ```. Tolerante porque el modelo suele añadir alguna frase."""
    limpio = (texto or "").strip()
    # 1) Si hay un bloque ```...```, quédate con su interior.
    m = re.search(r"```(?:json)?\s*(.*?)```", limpio, re.DOTALL)
    if m:
        limpio = m.group(1).strip()
    # 2) Recorta desde el primer { o [ hasta el último } o ] (quita prosa sobrante).
    inicio = min(
        (i for i in (limpio.find("{"), limpio.find("[")) if i != -1),
        default=0,
    )
    fin = max(limpio.rfind("}"), limpio.rfind("]"))
    limpio = limpio[inicio:fin + 1] if fin != -1 else limpio[inicio:]
    return json.loads(limpio)


def extraer_vulnerabilidades(texto: str) -> list:
    """Valida la respuesta del rojo y devuelve la lista de vulnerabilidades.

    Lanza InformeInvalido si la respuesta no es un JSON con la clave
    'vulnerabilidades' de tipo lista. Un {"vulnerabilidades": []} explícito
    SÍ es válido (significa que el rojo no encontró nada)."""
    try:
        data = parsear_json(texto)
    except (json.JSONDecodeError, ValueError) as e:
        raise InformeInvalido(f"JSON no válido: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilidades"), list):
        raise InformeInvalido("falta la clave 'vulnerabilidades' (lista)")
    return data["vulnerabilidades"]


# ------------------------------------------------------------------
# IMPRESIÓN Y PUNTUACIÓN
# ------------------------------------------------------------------
def color_sev(sev) -> str:
    color = {
        "CRITICA": C.ROJO + C.NEG,
        "ALTA": C.ROJO,
        "MEDIA": C.AMAR,
        "BAJA": C.GRIS,
    }.get(normalizar_sev(sev), "")
    return color + str(sev) + C.OFF


def imprimir_vulns(vulns: list, con_descripcion: bool = True):
    if not vulns:
        print(C.VERDE + "    Sin vulnerabilidades detectadas." + C.OFF)
        return
    for v in vulns:
        print(f"  {C.NEG}[{v.get('id', '?')}] {v.get('titulo', '')}{C.OFF}  "
              f"({color_sev(v.get('severidad', '?'))})")
        print(f"      {C.GRIS}{v.get('categoria', '')} · {v.get('ubicacion', '')}{C.OFF}")
        if con_descripcion and v.get("descripcion"):
            print(textwrap.fill(v["descripcion"], width=78,
                                initial_indent="      ", subsequent_indent="      "))


def puntuar(vulns: list) -> int:
    return sum(PESOS.get(normalizar_sev(v.get("severidad")), 1) for v in vulns)


def bloqueantes(vulns: list) -> list:
    """Vulnerabilidades CRÍTICAS/ALTAS (comparadas ya normalizadas)."""
    return [v for v in vulns
            if normalizar_sev(v.get("severidad")) in SEVERIDADES_BLOQUEANTES]


def imprimir_marcador(historial: list):
    print(f"\n{C.NEG}── MARCADOR (fallos encontrados por ronda) ──{C.OFF}")
    for h in historial:
        print(f"  Ronda {h['ronda']}: {C.ROJO}{'█' * h['puntos']}{C.OFF} "
              f"{h['puntos']} pts · {h['n_vulns']} vulns")
