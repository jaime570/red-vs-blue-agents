"""
duelo_seguridad_sdk.py
==================================================================
Red Team vs Blue Team con el CLAUDE AGENT SDK  (agentes que ACTÚAN)
------------------------------------------------------------------
Versión hermana de `duelo_seguridad.py`, pero ahora los agentes no
solo razonan sobre un string: usan HERRAMIENTAS reales sobre una
copia de tu código.

  - AGENTE ROJO (red team): lee los ficheros, lanza un SAST real
        (bandit para Python) y devuelve un informe JSON de
        vulnerabilidades. Herramientas: Read, Grep, Glob, Bash.
        (NO edita código: es solo auditoría defensiva.)

  - AGENTE AZUL (blue team): edita los ficheros EN SITIO para cerrar
        los fallos del informe y, si hay tests, los ejecuta para
        comprobar que no rompe nada. Herramientas: Read, Edit, Write,
        Grep, Glob, Bash.

  - ORQUESTADOR (este script, en Python): repite ROJO -> AZUL por
        rondas, puntúa la severidad y decide quién gana. Mantiene el
        control determinista de las rondas igual que la versión vieja.

Por qué esta versión arregla "de gratis" el problema del JSON truncado:
el código parcheado YA NO viaja dentro de un JSON; el azul lo escribe
directamente en disco con la herramienta Edit. El JSON del azul solo
lleva el resumen de cambios.

==================================================================
REQUISITOS
------------------------------------------------------------------
1) SDK y CLI:
       pip install claude-agent-sdk
   El SDK lanza por debajo el CLI de Claude Code, así que necesitas
   tenerlo instalado (Node.js + `npm i -g @anthropic-ai/claude-code`).

2) SAST opcional (recomendado para Python):
       pip install bandit
   Si no está instalado, el rojo hace la auditoría igual, solo que
   sin el analizador automático.

3) AUTENTICACIÓN CON TU PLAN PRO (para no gastar API aparte):
   - Haz login una vez con el CLI:  `claude`  ->  /login
   - Y MUY IMPORTANTE: NO tengas definida la variable ANTHROPIC_API_KEY,
     porque si existe, el SDK la usa y factura como API de pago.
   Por eso aquí NO llamamos a load_dotenv(): queremos que coja la
   sesión del plan Pro, no la clave del .env.

USO
       python duelo_seguridad_sdk.py mi_app.py --rondas 3
       python duelo_seguridad_sdk.py            # usa la demo
==================================================================
"""

import os
import json
import shutil
import asyncio
import argparse
import unicodedata
from pathlib import Path

from claude_agent_sdk import query, ClaudeAgentOptions


# ------------------------------------------------------------------
# CONFIGURACIÓN
# ------------------------------------------------------------------
# Modelo de los agentes. El SDK acepta alias: "sonnet", "opus", "haiku".
MODELO = "sonnet"               # sube a "opus" para casos difíciles
MAX_RONDAS = 4
SEVERIDADES_BLOQUEANTES = {"CRITICA", "ALTA"}   # sin tilde: ver normalizar_sev
PESOS = {"CRITICA": 10, "ALTA": 6, "MEDIA": 3, "BAJA": 1}


class C:
    ROJO = "\033[91m"; AZUL = "\033[94m"; VERDE = "\033[92m"
    AMAR = "\033[93m"; GRIS = "\033[90m"; NEG = "\033[1m"; OFF = "\033[0m"


def normalizar_sev(sev: str) -> str:
    """'Crítica'/'CRITICA'/'CRÍTICA' -> 'CRITICA'. Quita tildes y sube a mayúsculas."""
    s = (sev or "").strip().upper()
    return "".join(c for c in unicodedata.normalize("NFD", s)
                   if unicodedata.category(c) != "Mn")


# ------------------------------------------------------------------
# SYSTEM PROMPTS DE LOS AGENTES
# ------------------------------------------------------------------
SYSTEM_ROJO = """Eres un auditor de seguridad ofensiva (red team) profesional y ético.
El propietario te ENTREGA su propio código (está en tu directorio de trabajo) para
que encuentres vulnerabilidades antes que un atacante. Es auditoría DEFENSIVA: NO
escribes exploits funcionales ni malware, solo informas y recomiendas.

Procedimiento:
1. Explora y lee los ficheros de código del directorio (usa Glob/Grep/Read).
2. Si hay código Python, ejecuta un análisis estático con Bash:
       bandit -r . -f json
   Si 'bandit' no está instalado o falla, continúa con tu revisión manual.
3. Busca, como mínimo: inyección (SQL/comandos), XSS, deserialización insegura,
   auth/permisos débiles, secretos hardcodeados, criptografía mal usada, fugas de
   info en errores, validación insuficiente / path traversal, SSRF, configuración
   insegura (p.ej. debug en producción).

NO edites ningún fichero. NO inventes fallos que no existan.

Tu MENSAJE FINAL debe ser EXCLUSIVAMENTE un JSON válido (sin texto alrededor ni
vallas de código) con esta forma:
{
  "vulnerabilidades": [
    {
      "id": "V1",
      "titulo": "Inyección SQL en login",
      "severidad": "CRÍTICA",            // CRÍTICA | ALTA | MEDIA | BAJA
      "categoria": "A03:2021 Injection",
      "ubicacion": "app.py, función login()",
      "descripcion": "Explicación clara del fallo.",
      "vector_ataque": "Cómo se explotaría, conceptualmente (sin payloads funcionales).",
      "recomendacion": "Cómo corregirlo."
    }
  ]
}
Si el código está limpio, devuelve {"vulnerabilidades": []}."""


SYSTEM_AZUL = """Eres un ingeniero de seguridad defensiva (blue team) senior.
En tu directorio de trabajo está el código y recibirás un informe de
vulnerabilidades del red team. Tu trabajo:

1. EDITA los ficheros EN SITIO (herramientas Edit/Write) para cerrar cada fallo,
   aplicando buenas prácticas: consultas parametrizadas, validación de entrada,
   hashing seguro de contraseñas, secretos por variables de entorno, mínimo
   privilegio, manejo de errores sin fugas, desactivar debug en producción, etc.
2. NO cambies la funcionalidad legítima ni la lógica de negocio.
3. Si hay tests en el proyecto, ejecútalos con Bash (p.ej. `pytest -q`) para
   comprobar que no has roto nada. Si no hay, dilo en las notas.

Tu MENSAJE FINAL debe ser EXCLUSIVAMENTE un JSON válido (sin texto alrededor ni
vallas) con esta forma:
{
  "cambios": [
    {"id": "V1", "fichero": "app.py", "cambio": "Qué hiciste para cerrar el fallo."}
  ],
  "tests": "Resultado de los tests si los ejecutaste, o 'sin tests'.",
  "notas": "Observaciones de defensa en profundidad (opcional)."
}"""


# ------------------------------------------------------------------
# UTILIDAD: ejecutar un agente del SDK y recoger su mensaje final
# ------------------------------------------------------------------
async def correr_agente(prompt: str, system: str, tools: list, cwd: Path,
                        etiqueta: str, color: str) -> str:
    """Lanza un query() del Agent SDK con las herramientas dadas sobre `cwd`.
    Imprime en vivo qué herramienta usa y devuelve el texto del mensaje final."""
    opciones = ClaudeAgentOptions(
        system_prompt=system,
        model=MODELO,
        allowed_tools=tools,          # se auto-aprueban sin preguntar
        permission_mode="bypassPermissions",  # ejecución desatendida (es TU código)
        cwd=str(cwd),
        setting_sources=[],           # no cargamos settings del usuario/proyecto
        max_turns=40,
    )

    final = ""
    async for msg in query(prompt=prompt, options=opciones):
        # Mensajes del asistente: enseñamos las herramientas que va usando.
        for bloque in getattr(msg, "content", None) or []:
            tipo = getattr(bloque, "type", None)
            if tipo == "tool_use":
                detalle = ""
                if bloque.name == "Bash":
                    detalle = (bloque.input or {}).get("command", "")[:70]
                elif bloque.name in ("Read", "Edit", "Write"):
                    detalle = (bloque.input or {}).get("file_path", "")
                print(f"  {color}{etiqueta}{C.OFF} {C.GRIS}· {bloque.name} {detalle}{C.OFF}")
        # Mensaje final del agente (ResultMessage tiene .result)
        if hasattr(msg, "result") and msg.result:
            final = msg.result
    return final


def parsear_json(texto: str):
    """Extrae JSON aunque venga con vallas ```json o algún prefijo."""
    limpio = (texto or "").strip()
    if limpio.startswith("```"):
        limpio = "\n".join(limpio.split("\n")[1:])
        if limpio.rstrip().endswith("```"):
            limpio = limpio.rstrip()[:-3]
    inicio = min((i for i in (limpio.find("{"), limpio.find("[")) if i != -1), default=0)
    return json.loads(limpio[inicio:])


# ------------------------------------------------------------------
# IMPRESIÓN Y PUNTUACIÓN
# ------------------------------------------------------------------
def color_sev(sev: str) -> str:
    color = {"CRITICA": C.ROJO + C.NEG, "ALTA": C.ROJO,
             "MEDIA": C.AMAR, "BAJA": C.GRIS}.get(normalizar_sev(sev), "")
    return color + str(sev) + C.OFF


def imprimir_vulns(vulns: list):
    if not vulns:
        print(C.VERDE + "    Sin vulnerabilidades detectadas." + C.OFF)
        return
    for v in vulns:
        print(f"  {C.NEG}[{v.get('id','?')}] {v.get('titulo','')}{C.OFF}  "
              f"({color_sev(v.get('severidad','?'))})")
        print(f"      {C.GRIS}{v.get('categoria','')} · {v.get('ubicacion','')}{C.OFF}")


def puntuar(vulns: list) -> int:
    return sum(PESOS.get(normalizar_sev(v.get("severidad")), 1) for v in vulns)


# ------------------------------------------------------------------
# ORQUESTADOR DEL DUELO
# ------------------------------------------------------------------
async def duelo(dir_trabajo: Path, max_rondas: int = MAX_RONDAS):
    historial = []
    informes = dir_trabajo / "_informes"
    informes.mkdir(exist_ok=True)

    print(C.NEG + "\n" + "=" * 70)
    print("  DUELO DE SEGURIDAD (Agent SDK): ROJO (audita) vs AZUL (parchea)")
    print(f"  Directorio de trabajo: {dir_trabajo}")
    print("=" * 70 + C.OFF)

    for ronda in range(1, max_rondas + 1):
        print(f"\n{C.NEG}── RONDA {ronda} ──{C.OFF}")

        # 1) ROJO audita el directorio
        print(f"{C.ROJO}🔴 ROJO auditando con herramientas...{C.OFF}")
        salida_rojo = await correr_agente(
            prompt="Audita TODO el código de este directorio y entrega el informe JSON.",
            system=SYSTEM_ROJO,
            tools=["Read", "Grep", "Glob", "Bash"],
            cwd=dir_trabajo, etiqueta="🔴", color=C.ROJO,
        )
        try:
            vulns = parsear_json(salida_rojo).get("vulnerabilidades", [])
        except (json.JSONDecodeError, ValueError):
            print(C.AMAR + "[!] El rojo no devolvió JSON válido:" + C.OFF)
            print(salida_rojo)
            vulns = []

        imprimir_vulns(vulns)
        (informes / f"ronda{ronda}_rojo.json").write_text(
            json.dumps(vulns, ensure_ascii=False, indent=2), encoding="utf-8")
        historial.append({"ronda": ronda, "puntos": puntuar(vulns), "n": len(vulns)})

        # ¿Quedan fallos bloqueantes? (comparación normalizada)
        bloqueantes = [v for v in vulns
                       if normalizar_sev(v.get("severidad")) in SEVERIDADES_BLOQUEANTES]
        if not bloqueantes:
            print(f"\n{C.AZUL}{C.NEG}🏆 ¡Gana AZUL!{C.OFF} "
                  f"El rojo ya no encuentra fallos críticos ni altos.")
            break

        # 2) AZUL parchea los ficheros en sitio
        print(f"\n{C.AZUL}🔵 AZUL parcheando ({len(bloqueantes)} bloqueantes)...{C.OFF}")
        prompt_azul = ("Aquí tienes el informe del red team. Edita los ficheros del "
                       "directorio para cerrar cada fallo y entrega el JSON de cambios.\n\n"
                       + json.dumps({"vulnerabilidades": vulns}, ensure_ascii=False, indent=2))
        salida_azul = await correr_agente(
            prompt=prompt_azul, system=SYSTEM_AZUL,
            tools=["Read", "Edit", "Write", "Grep", "Glob", "Bash"],
            cwd=dir_trabajo, etiqueta="🔵", color=C.AZUL,
        )
        try:
            resultado = parsear_json(salida_azul)
        except (json.JSONDecodeError, ValueError):
            resultado = {"cambios": [], "tests": "?", "notas": "(parseo fallido)"}
        for c in resultado.get("cambios", []):
            print(f"  {C.VERDE}✓{C.OFF} [{c.get('id','?')}] "
                  f"{c.get('fichero','')}: {c.get('cambio','')}")
        if resultado.get("tests"):
            print(f"  {C.GRIS}Tests: {resultado['tests']}{C.OFF}")
        (informes / f"ronda{ronda}_azul.json").write_text(
            json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        print(f"\n{C.ROJO}{C.NEG}🏆 ¡Gana ROJO!{C.OFF} "
              f"Tras {max_rondas} rondas siguen quedando agujeros.")

    # Marcador
    print(f"\n{C.NEG}── MARCADOR (fallos por ronda) ──{C.OFF}")
    for h in historial:
        print(f"  Ronda {h['ronda']}: {C.ROJO}{'█' * h['puntos']}{C.OFF} "
              f"{h['puntos']} pts · {h['n']} vulns")
    print(f"\n{C.NEG}Código endurecido y informes en:{C.OFF} {dir_trabajo}")


# ------------------------------------------------------------------
# DEMO
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
    query = "SELECT * FROM users WHERE name = '" + user + "' AND pw = '" + pw + "'"
    row = conn.execute(query).fetchone()
    if row:
        return "Bienvenido " + user
    return "Login incorrecto"

@app.route("/file")
def read_file():
    name = request.args.get("name")
    with open("/data/" + name) as f:   # path traversal
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)               # debug en producción
'''


def preparar_directorio(args) -> Path:
    """Copia el objetivo a un directorio _work para no tocar el original."""
    base = Path(__file__).parent
    work = base / "_work_duelo"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    if args.archivo:
        origen = Path(args.archivo)
        if not origen.exists():
            print(f"❌ No encuentro: {origen}")
            raise SystemExit(1)
        if origen.is_dir():
            shutil.copytree(origen, work, dirs_exist_ok=True)
        else:
            shutil.copy(origen, work / origen.name)
        print(f"📄 Copiado a área de trabajo: {origen} -> {work}")
    else:
        (work / "app.py").write_text(CODIGO_VULNERABLE, encoding="utf-8")
        print("ℹ️  Sin objetivo: usando la demo (app.py vulnerable).")
    return work


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Duelo de seguridad con Agent SDK: ROJO audita, AZUL parchea (con herramientas).",
        epilog="Ejemplo:  python duelo_seguridad_sdk.py mi_app.py --rondas 3",
    )
    parser.add_argument("archivo", nargs="?",
                        help="fichero O carpeta a auditar (si se omite, usa la demo)")
    parser.add_argument("--rondas", type=int, default=MAX_RONDAS,
                        help=f"nº máximo de rondas (por defecto {MAX_RONDAS})")
    args = parser.parse_args()

    # Aviso de facturación: si hay API key, NO se usa el plan Pro.
    if os.environ.get("ANTHROPIC_API_KEY"):
        print(C.AMAR + "[aviso] ANTHROPIC_API_KEY está definida: el SDK facturará "
              "como API de pago, NO con tu plan Pro.\n"
              "        Para usar el Pro: quita esa variable y haz login con `claude` "
              "-> /login." + C.OFF)

    work = preparar_directorio(args)
    asyncio.run(duelo(work, max_rondas=args.rondas))
