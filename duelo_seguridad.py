"""
duelo_seguridad.py
==================================================================
Red Team vs Blue Team con Claude
------------------------------------------------------------------
Dos agentes compiten por rondas para endurecer un trozo de código:

  - AGENTE ROJO (pentester ético / red team):
        audita el código y devuelve un informe ESTRUCTURADO de
        vulnerabilidades (severidad, categoría OWASP, vector de
        ataque y recomendación).

  - AGENTE AZUL (defensor / blue team):
        recibe ese informe y devuelve el código PARCHEADO,
        explicando cada cambio.

  - ORQUESTADOR:
        repite ROJO -> AZUL durante N rondas.
        * Gana AZUL si ROJO ya no encuentra fallos CRÍTICOS/ALTOS.
        * Gana ROJO si se agotan las rondas con agujeros pendientes.
        Cada ronda se puntúa según la severidad encontrada.

IMPORTANTE: esto es seguridad DEFENSIVA. El rojo audita TU propio
código para que el azul lo arregle. No genera exploits funcionales
ni malware: produce informes de vulnerabilidad y remediaciones.

------------------------------------------------------------------
Requisitos:
    pip install anthropic
    export ANTHROPIC_API_KEY="tu-api-key"   # (en Windows: set ...)

Uso:
    python duelo_seguridad.py
==================================================================
"""

import os
import json
import argparse
import textwrap
import unicodedata
from pathlib import Path
from anthropic import Anthropic
from dotenv import load_dotenv

# ------------------------------------------------------------------
# CONFIGURACIÓN
# ------------------------------------------------------------------
# El cliente coge la clave de la variable de entorno ANTHROPIC_API_KEY
load_dotenv()
client = Anthropic()

# Modelo a usar. claude-sonnet-4-6 da un buen equilibrio
# calidad/precio para auditar y parchear código.
# Para casos muy difíciles puedes subir a "claude-opus-4-8".
MODELO = "claude-sonnet-4-6"

MAX_RONDAS = 4          # nº máximo de iteraciones rojo<->azul
# OJO: las claves van SIN tilde y en MAYÚSCULAS porque comparamos
# siempre con normalizar_sev(), que quita acentos y pasa a mayúsculas.
# Así "Crítica", "CRITICA" y "CRÍTICA" cuentan todas igual.
SEVERIDADES_BLOQUEANTES = {"CRITICA", "ALTA"}  # si quedan de estas, no hay victoria azul

# Puntos por severidad (para el marcador del "duelo")
PESOS = {"CRITICA": 10, "ALTA": 6, "MEDIA": 3, "BAJA": 1}


def normalizar_sev(sev: str) -> str:
    """Pasa una severidad a forma canónica: mayúsculas y sin tildes.
    'Crítica' -> 'CRITICA', 'alta' -> 'ALTA'. Así no dependemos de
    cómo escriba exactamente el modelo la palabra."""
    s = (sev or "").strip().upper()
    # NFD descompone 'Í' en 'I' + tilde; quitamos los acentos (categoría Mn).
    return "".join(c for c in unicodedata.normalize("NFD", s)
                   if unicodedata.category(c) != "Mn")

# Colores ANSI para la consola (puramente cosmético)
class C:
    ROJO = "\033[91m"
    AZUL = "\033[94m"
    VERDE = "\033[92m"
    AMAR = "\033[93m"
    GRIS = "\033[90m"
    NEG = "\033[1m"
    OFF = "\033[0m"


# ------------------------------------------------------------------
# UTILIDAD: llamada a Claude
# ------------------------------------------------------------------
def llamar_claude(system: str, prompt: str, max_tokens: int = 4000) -> str:
    """Una llamada simple al endpoint de mensajes. Devuelve el texto."""
    resp = client.messages.create(
        model=MODELO,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    # Si la respuesta se cortó por llegar al tope de tokens, el JSON
    # vendrá incompleto y reventará el parser. Avisamos en pantalla.
    if resp.stop_reason == "max_tokens":
        print(C.AMAR + f"[!] Respuesta cortada por max_tokens ({max_tokens}). "
                       f"El JSON puede venir incompleto." + C.OFF)
    # La respuesta puede venir en varios bloques; concatenamos el texto.
    return "".join(b.text for b in resp.content if b.type == "text")


def parsear_json(texto: str):
    """Extrae el JSON de la respuesta aunque venga envuelto en ```json ... ```."""
    limpio = texto.strip()
    if limpio.startswith("```"):
        # quitamos la primera y última línea de las vallas de código
        limpio = "\n".join(limpio.split("\n")[1:])
        if limpio.rstrip().endswith("```"):
            limpio = limpio.rstrip()[:-3]
    # por si quedara algún prefijo, buscamos el primer { o [
    inicio = min(
        (i for i in (limpio.find("{"), limpio.find("[")) if i != -1),
        default=0,
    )
    return json.loads(limpio[inicio:])


# ------------------------------------------------------------------
# AGENTE ROJO  (pentester ético)
# ------------------------------------------------------------------
SYSTEM_ROJO = """Eres un auditor de seguridad ofensiva (red team) profesional y ético.
Tu trabajo es revisar código que TE ENTREGA su propietario para encontrar
vulnerabilidades antes de que lo haga un atacante real.

Analiza el código en busca de fallos como (no exhaustivo):
- Inyección (SQL, comandos, LDAP, etc.)
- Cross-Site Scripting (XSS) y deserialización insegura
- Autenticación/autorización débil o ausente
- Secretos hardcodeados (claves, contraseñas, tokens)
- Criptografía débil o mal usada
- Gestión de errores que filtra información
- Validación de entrada insuficiente / path traversal
- Condiciones de carrera, SSRF, configuración insegura

Devuelve EXCLUSIVAMENTE un JSON válido, sin texto adicional ni vallas de código,
con esta forma:

{
  "vulnerabilidades": [
    {
      "id": "V1",
      "titulo": "Inyección SQL en login",
      "severidad": "CRÍTICA",      // CRÍTICA | ALTA | MEDIA | BAJA
      "categoria": "A03:2021 Injection",
      "ubicacion": "función login(), línea ~12",
      "descripcion": "Explicación clara del fallo.",
      "vector_ataque": "Descripción conceptual de cómo se explotaría (sin payloads funcionales).",
      "recomendacion": "Cómo corregirlo."
    }
  ]
}

Si el código está limpio, devuelve {"vulnerabilidades": []}.
NO inventes vulnerabilidades que no existan. Sé riguroso pero honesto."""


def agente_rojo(codigo: str) -> list:
    prompt = f"""Audita el siguiente código y reporta sus vulnerabilidades en el JSON indicado:

```
{codigo}
```"""
    salida = llamar_claude(SYSTEM_ROJO, prompt)
    try:
        data = parsear_json(salida)
        return data.get("vulnerabilidades", [])
    except (json.JSONDecodeError, ValueError):
        print(C.AMAR + "[!] El rojo no devolvió JSON válido. Respuesta cruda:" + C.OFF)
        print(salida)
        return []


# ------------------------------------------------------------------
# AGENTE AZUL  (defensor)
# ------------------------------------------------------------------
SYSTEM_AZUL = """Eres un ingeniero de seguridad defensiva (blue team) senior.
Recibes un trozo de código y un informe de vulnerabilidades hecho por el red team.
Tu trabajo es entregar una versión PARCHEADA del código que cierre esos fallos,
aplicando buenas prácticas (consultas parametrizadas, validación de entrada,
hashing seguro de contraseñas, gestión de secretos por entorno, principio de
mínimo privilegio, manejo de errores sin fugas de info, etc.).

No cambies la funcionalidad legítima del programa. Mantén la lógica de negocio.

Devuelve EXCLUSIVAMENTE un JSON válido, sin texto adicional ni vallas externas,
con esta forma:

{
  "codigo_corregido": "EL CÓDIGO COMPLETO YA PARCHEADO COMO STRING",
  "cambios": [
    {"id": "V1", "cambio": "Qué hiciste para cerrar esta vulnerabilidad."}
  ],
  "notas": "Observaciones de defensa en profundidad (opcional)."
}"""


def agente_azul(codigo: str, vulnerabilidades: list) -> dict:
    informe = json.dumps({"vulnerabilidades": vulnerabilidades},
                         ensure_ascii=False, indent=2)
    prompt = f"""Código actual:

```
{codigo}
```

Informe del red team:
{informe}

Devuelve el código parcheado en el JSON indicado."""
    # El azul devuelve TODO el código parcheado dentro del JSON, así que
    # necesita espacio de sobra: el código de salida pesa parecido al de
    # entrada + el informe de cambios. Estimamos ~1 token por cada 3-4
    # caracteres y dejamos margen, con un suelo de 6000 y un techo de 16000.
    estimado = (len(codigo) + len(informe)) // 3 + 2000
    tokens_salida = max(6000, min(estimado, 16000))
    salida = llamar_claude(SYSTEM_AZUL, prompt, max_tokens=tokens_salida)
    try:
        return parsear_json(salida)
    except (json.JSONDecodeError, ValueError):
        print(C.AMAR + "[!] El azul no devolvió JSON válido. Respuesta cruda:" + C.OFF)
        print(salida)
        return {"codigo_corregido": codigo, "cambios": [], "notas": "(parseo fallido)"}


# ------------------------------------------------------------------
# IMPRESIÓN
# ------------------------------------------------------------------
def color_sev(sev: str) -> str:
    color = {
        "CRITICA": C.ROJO + C.NEG,
        "ALTA": C.ROJO,
        "MEDIA": C.AMAR,
        "BAJA": C.GRIS,
    }.get(normalizar_sev(sev), "")
    return color + sev + C.OFF


def imprimir_vulns(vulns: list):
    if not vulns:
        print(C.VERDE + "    Sin vulnerabilidades detectadas. " + C.OFF)
        return
    for v in vulns:
        print(f"  {C.NEG}[{v.get('id','?')}] {v.get('titulo','')}{C.OFF}  "
              f"({color_sev(v.get('severidad','?'))})")
        print(f"      {C.GRIS}{v.get('categoria','')} · {v.get('ubicacion','')}{C.OFF}")
        print(textwrap.fill(v.get("descripcion", ""), width=78,
                            initial_indent="      ", subsequent_indent="      "))


def puntuar(vulns: list) -> int:
    return sum(PESOS.get(normalizar_sev(v.get("severidad")), 1) for v in vulns)


# ------------------------------------------------------------------
# ORQUESTADOR DEL DUELO
# ------------------------------------------------------------------
def duelo(codigo_inicial: str, max_rondas: int = MAX_RONDAS):
    codigo = codigo_inicial
    historial = []

    print(C.NEG + "\n" + "=" * 70)
    print("  DUELO DE SEGURIDAD: ROJO (ataque) vs AZUL (defensa)")
    print("=" * 70 + C.OFF)

    for ronda in range(1, max_rondas + 1):
        print(f"\n{C.NEG}── RONDA {ronda} ──{C.OFF}")

        # 1) El rojo ataca
        print(f"{C.ROJO}🔴 ROJO auditando...{C.OFF}")
        vulns = agente_rojo(codigo)
        imprimir_vulns(vulns)
        puntos_rojo = puntuar(vulns)
        historial.append({"ronda": ronda, "puntos_rojo": puntos_rojo, "n_vulns": len(vulns)})

        # ¿Quedan fallos bloqueantes? (comparamos normalizado para no
        # fallar por tildes o mayúsculas/minúsculas)
        bloqueantes = [v for v in vulns
                       if normalizar_sev(v.get("severidad")) in SEVERIDADES_BLOQUEANTES]
        if not bloqueantes:
            print(f"\n{C.AZUL}{C.NEG}🏆 ¡Gana AZUL!{C.OFF} "
                  f"El rojo ya no encuentra fallos críticos ni altos.")
            print(f"{C.GRIS}(Pueden quedar avisos menores; revisa el informe.){C.OFF}")
            break

        # 2) El azul defiende
        print(f"\n{C.AZUL}🔵 AZUL parcheando ({len(bloqueantes)} fallos bloqueantes)...{C.OFF}")
        resultado = agente_azul(codigo, vulns)
        codigo = resultado.get("codigo_corregido", codigo)
        for c in resultado.get("cambios", []):
            print(f"  {C.VERDE}✓{C.OFF} [{c.get('id','?')}] {c.get('cambio','')}")
        if resultado.get("notas"):
            print(f"  {C.GRIS}Nota: {resultado['notas']}{C.OFF}")

    else:
        # se agotaron las rondas sin victoria azul
        print(f"\n{C.ROJO}{C.NEG}🏆 ¡Gana ROJO!{C.OFF} "
              f"Tras {max_rondas} rondas siguen quedando agujeros sin cerrar.")

    # Resumen del marcador
    print(f"\n{C.NEG}── MARCADOR (fallos encontrados por ronda) ──{C.OFF}")
    for h in historial:
        barra = "█" * h["puntos_rojo"]
        print(f"  Ronda {h['ronda']}: {C.ROJO}{barra}{C.OFF} "
              f"{h['puntos_rojo']} pts · {h['n_vulns']} vulns")

    print(f"\n{C.NEG}── CÓDIGO FINAL ──{C.OFF}")
    print(codigo)
    return codigo


# ------------------------------------------------------------------
# DEMO: código vulnerable de ejemplo
# ------------------------------------------------------------------
CODIGO_VULNERABLE = '''\
import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "admin123"          # secreto hardcodeado

@app.route("/login")
def login():
    user = request.args.get("user")
    pw = request.args.get("pw")
    conn = sqlite3.connect("app.db")
    # consulta construida por concatenación -> inyección SQL
    query = "SELECT * FROM users WHERE name = '" + user + "' AND pw = '" + pw + "'"
    row = conn.execute(query).fetchone()
    if row:
        return "Bienvenido " + user
    return "Login incorrecto"

@app.route("/file")
def read_file():
    name = request.args.get("name")
    # path traversal: el usuario controla la ruta
    with open("/data/" + name) as f:
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)          # debug en producción filtra info
'''


if __name__ == "__main__":
    # --- Mejora 2: argparse para argumentos de línea de comandos ---
    parser = argparse.ArgumentParser(
        description="Duelo de seguridad: el agente ROJO audita y el AZUL parchea.",
        epilog="Ejemplos:  python duelo_seguridad.py pagina.html --rondas 3",
    )
    parser.add_argument("archivo", nargs="?",
                        help="ruta del código a auditar (si se omite, usa la demo)")
    parser.add_argument("--rondas", type=int, default=MAX_RONDAS,
                        help=f"número máximo de rondas (por defecto {MAX_RONDAS})")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Define la variable de entorno ANTHROPIC_API_KEY primero.")
        raise SystemExit(1)

    # --- Mejora 1: pathlib + control de errores ---
    if args.archivo:
        ruta = Path(args.archivo)
        if not ruta.exists():
            print(f"❌ No encuentro el archivo: {ruta}")
            raise SystemExit(1)
        codigo = ruta.read_text(encoding="utf-8")
        print(f"📄 Auditando: {ruta} ({len(codigo)} caracteres)")
    else:
        codigo = CODIGO_VULNERABLE
        print("ℹ️  Sin archivo indicado: usando la demo CODIGO_VULNERABLE.")

    duelo(codigo, max_rondas=args.rondas)
