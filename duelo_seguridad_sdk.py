"""
duelo_seguridad_sdk.py
==================================================================
Red Team vs Blue Team con el CLAUDE AGENT SDK  (agentes que ACTÚAN)
------------------------------------------------------------------
ROJO audita con herramientas (Read/Grep/Glob/Bash + bandit), AZUL
parchea editando los ficheros en sitio (Read/Edit/Write/Bash). El
ORQUESTADOR (este script) repite ROJO -> AZUL por rondas, puntúa la
severidad y decide quién gana.

Condición de victoria + PASADA FINAL DE LIMPIEZA:
  Gana AZUL cuando el rojo ya no encuentra fallos CRÍTICOS/ALTOS. Como
  el rojo casi siempre encuentra detalles menores (MEDIA/BAJA), al ganar
  el azul se hace UNA última pasada para cerrar esos restantes y se PARA
  (no se re-audita, para no entrar en bucle). Se desactiva con --sin-limpieza.

SEGURIDAD
  Los agentes corren con permission_mode="bypassPermissions" y acceso a Bash
  para poder trabajar desatendidos. Úsalo SOLO con código de confianza: se
  trabaja sobre una copia (_work_duelo/), pero Bash se ejecuta en tu máquina.

REQUISITOS
  1) pip install claude-agent-sdk   (+ CLI: npm i -g @anthropic-ai/claude-code)
  2) pip install bandit             (SAST opcional para Python)
  3) Plan Pro: login con `claude` -> /login y NO tener ANTHROPIC_API_KEY
     definida (si existe, el SDK factura como API). Por eso NO usamos .env aquí.

USO
  python duelo_seguridad_sdk.py mi_app.py --rondas 3
  python duelo_seguridad_sdk.py --sin-limpieza
  python duelo_seguridad_sdk.py
==================================================================
"""

import os
import json
import shutil
import asyncio
import argparse
from pathlib import Path

from claude_agent_sdk import query, ClaudeAgentOptions

from comun import (C, InformeInvalido, extraer_vulnerabilidades, parsear_json,
                   imprimir_vulns, imprimir_marcador, puntuar, bloqueantes)


# ------------------------------------------------------------------
# CONFIGURACIÓN
# ------------------------------------------------------------------
MODELO = "sonnet"               # alias del SDK; sube a "opus" para casos difíciles
MAX_RONDAS = 4


# ------------------------------------------------------------------
# SYSTEM PROMPTS
# ------------------------------------------------------------------
SYSTEM_ROJO = """Eres un auditor de seguridad ofensiva (red team) profesional y ético.
El propietario te ENTREGA su propio código (está en tu directorio de trabajo) para
que encuentres vulnerabilidades antes que un atacante. Es auditoría DEFENSIVA: NO
escribes exploits funcionales ni malware, solo informas y recomiendas.

Procedimiento:
1. Explora y lee los ficheros de código del directorio (Glob/Grep/Read).
2. Si hay Python, ejecuta SAST con Bash: bandit -r . -f json
   Si 'bandit' no está o falla, continúa con revisión manual.
3. Busca al menos: inyección (SQL/comandos), XSS, deserialización insegura,
   auth/permisos débiles, secretos hardcodeados, criptografía mal usada, fugas de
   info en errores, validación insuficiente / path traversal, SSRF, configuración
   insegura (p.ej. debug en producción).

NO edites ningún fichero. NO inventes fallos que no existan.

Tu MENSAJE FINAL debe ser EXCLUSIVAMENTE el JSON, sin frases antes ni después y
sin vallas de código, con esta forma:
{
  "vulnerabilidades": [
    {
      "id": "V1",
      "titulo": "Inyección SQL en login",
      "severidad": "CRÍTICA",
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
En tu directorio de trabajo está el código y recibirás un informe del red team.

1. EDITA los ficheros EN SITIO (Edit/Write) para cerrar cada fallo con buenas
   prácticas: consultas parametrizadas, validación de entrada, hashing seguro de
   contraseñas, secretos por entorno, mínimo privilegio, manejo de errores sin
   fugas, desactivar debug en producción, etc.
2. NO cambies la funcionalidad legítima ni la lógica de negocio.
3. Si hay tests, ejecútalos con Bash (p.ej. pytest -q) para comprobar que no rompes
   nada. Si no hay, dilo en las notas.

Tu MENSAJE FINAL debe ser EXCLUSIVAMENTE el JSON, sin frases antes ni después y
sin vallas, con esta forma:
{
  "cambios": [
    {"id": "V1", "fichero": "app.py", "cambio": "Qué hiciste para cerrar el fallo."}
  ],
  "tests": "Resultado de los tests si los ejecutaste, o 'sin tests'.",
  "notas": "Observaciones de defensa en profundidad (opcional)."
}"""


# ------------------------------------------------------------------
# UTILIDAD: ejecutar un agente del SDK
# ------------------------------------------------------------------
async def correr_agente(prompt: str, system: str, tools: list, cwd: Path,
                        etiqueta: str, color: str) -> str:
    """Lanza un query() del Agent SDK con esas herramientas sobre `cwd`.
    Imprime en vivo qué herramienta usa y devuelve el texto del mensaje final."""
    opciones = ClaudeAgentOptions(
        system_prompt=system,
        model=MODELO,
        allowed_tools=tools,
        permission_mode="bypassPermissions",  # desatendido (es TU código en una copia)
        cwd=str(cwd),
        setting_sources=[],
        max_turns=40,
    )
    final = ""
    async for msg in query(prompt=prompt, options=opciones):
        for bloque in getattr(msg, "content", None) or []:
            if getattr(bloque, "type", None) == "tool_use":
                detalle = ""
                if bloque.name == "Bash":
                    detalle = (bloque.input or {}).get("command", "")[:70]
                elif bloque.name in ("Read", "Edit", "Write"):
                    detalle = (bloque.input or {}).get("file_path", "")
                print(f"  {color}{etiqueta}{C.OFF} {C.GRIS}· {bloque.name} {detalle}{C.OFF}")
        if hasattr(msg, "result") and msg.result:
            final = msg.result
    return final


# ------------------------------------------------------------------
# TURNOS DE LOS AGENTES
# ------------------------------------------------------------------
async def turno_rojo(dir_trabajo: Path, reintentos: int = 1) -> list:
    """Lanza al agente rojo y devuelve las vulnerabilidades encontradas.

    Si el informe no es un JSON válido se reintenta; si sigue fallando se
    lanza InformeInvalido. NUNCA devolvemos [] por un error de parseo,
    porque [] significa "código limpio" y daría la victoria al azul."""
    prompt = "Audita TODO el código de este directorio y entrega el informe JSON."
    for intento in range(reintentos + 1):
        salida = await correr_agente(
            prompt=prompt, system=SYSTEM_ROJO,
            tools=["Read", "Grep", "Glob", "Bash"],
            cwd=dir_trabajo, etiqueta="🔴", color=C.ROJO,
        )
        try:
            return extraer_vulnerabilidades(salida)
        except InformeInvalido as e:
            print(C.AMAR + f"[!] El rojo no devolvió un informe válido ({e})." + C.OFF)
            if intento < reintentos:
                print(C.AMAR + "    Reintentando..." + C.OFF)
                prompt += (" IMPORTANTE: tu mensaje final debe ser SOLO el JSON "
                           "pedido, sin texto adicional.")
            else:
                print(C.GRIS + "Respuesta cruda:\n" + str(salida) + C.OFF)
    raise InformeInvalido("el rojo no devolvió un informe válido tras reintentar")


async def turno_azul(vulns: list, dir_trabajo: Path, intro: str) -> dict:
    """Lanza al agente azul para que parchee `vulns` y devuelve su resumen."""
    prompt = intro + "\n\n" + json.dumps({"vulnerabilidades": vulns},
                                         ensure_ascii=False, indent=2)
    salida = await correr_agente(
        prompt=prompt, system=SYSTEM_AZUL,
        tools=["Read", "Edit", "Write", "Grep", "Glob", "Bash"],
        cwd=dir_trabajo, etiqueta="🔵", color=C.AZUL,
    )
    try:
        resultado = parsear_json(salida)
    except (json.JSONDecodeError, ValueError):
        resultado = {"cambios": [], "tests": "?", "notas": "(parseo fallido)"}
    for c in resultado.get("cambios", []):
        print(f"  {C.VERDE}✓{C.OFF} [{c.get('id','?')}] "
              f"{c.get('fichero','')}: {c.get('cambio','')}")
    if resultado.get("tests"):
        print(f"  {C.GRIS}Tests: {resultado['tests']}{C.OFF}")
    return resultado


# ------------------------------------------------------------------
# ORQUESTADOR DEL DUELO
# ------------------------------------------------------------------
async def duelo(dir_trabajo: Path, max_rondas: int = MAX_RONDAS,
                limpieza_final: bool = True) -> bool:
    """Ejecuta el duelo. Devuelve False si se interrumpe por un informe inválido."""
    historial = []
    informes = dir_trabajo / "_informes"
    informes.mkdir(exist_ok=True)

    print(C.NEG + "\n" + "=" * 70)
    print("  DUELO DE SEGURIDAD (Agent SDK): ROJO (audita) vs AZUL (parchea)")
    print(f"  Directorio de trabajo: {dir_trabajo}")
    print("=" * 70 + C.OFF)

    for ronda in range(1, max_rondas + 1):
        print(f"\n{C.NEG}── RONDA {ronda} ──{C.OFF}")

        print(f"{C.ROJO}🔴 ROJO auditando con herramientas...{C.OFF}")
        try:
            vulns = await turno_rojo(dir_trabajo)
        except InformeInvalido as e:
            # Sin informe fiable no se puede decidir un ganador: paramos.
            print(f"\n{C.AMAR}{C.NEG}⚠ Duelo interrumpido:{C.OFF} {e}. "
                  f"No se declara ganador.")
            imprimir_marcador(historial)
            return False

        imprimir_vulns(vulns, con_descripcion=False)
        (informes / f"ronda{ronda}_rojo.json").write_text(
            json.dumps(vulns, ensure_ascii=False, indent=2), encoding="utf-8")
        historial.append({"ronda": ronda, "puntos": puntuar(vulns), "n_vulns": len(vulns)})

        pendientes = bloqueantes(vulns)
        if not pendientes:
            print(f"\n{C.AZUL}{C.NEG}🏆 ¡Gana AZUL!{C.OFF} "
                  f"El rojo ya no encuentra fallos críticos ni altos.")

            # --- PASADA FINAL DE LIMPIEZA (opción 2) ---
            # Si quedan MEDIA/BAJA, el azul los cierra UNA vez y paramos.
            # NO re-auditamos: así evitamos el bucle infinito de retoques.
            if limpieza_final and vulns:
                print(f"\n{C.AZUL}🧹 Pasada final: el azul cierra {len(vulns)} "
                      f"fallos menores (MEDIA/BAJA) restantes...{C.OFF}")
                limpieza = await turno_azul(
                    vulns, dir_trabajo,
                    intro=("El código ya no tiene fallos críticos ni altos. Cierra "
                           "estos fallos menores restantes (mejora / defensa en "
                           "profundidad) editando los ficheros, sin cambiar la "
                           "funcionalidad. Entrega el JSON de cambios."),
                )
                (informes / f"ronda{ronda}_limpieza_azul.json").write_text(
                    json.dumps(limpieza, ensure_ascii=False, indent=2), encoding="utf-8")
                print(f"{C.GRIS}(Limpieza final aplicada; no se vuelve a auditar.){C.OFF}")
            break

        print(f"\n{C.AZUL}🔵 AZUL parcheando ({len(pendientes)} bloqueantes)...{C.OFF}")
        resultado = await turno_azul(
            vulns, dir_trabajo,
            intro=("Aquí tienes el informe del red team. Edita los ficheros del "
                   "directorio para cerrar cada fallo y entrega el JSON de cambios."),
        )
        (informes / f"ronda{ronda}_azul.json").write_text(
            json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        print(f"\n{C.ROJO}{C.NEG}🏆 ¡Gana ROJO!{C.OFF} "
              f"Tras {max_rondas} rondas siguen quedando agujeros.")

    imprimir_marcador(historial)
    print(f"\n{C.NEG}Código endurecido y informes en:{C.OFF} {dir_trabajo}")
    return True


# ------------------------------------------------------------------
# DEMO
# ------------------------------------------------------------------
CODIGO_VULNERABLE = "\n".join([
    "import sqlite3",
    "from flask import Flask, request",
    "",
    "app = Flask(__name__)",
    'DB_PASSWORD = "admin123"          # secreto hardcodeado',
    "",
    '@app.route("/login")',
    "def login():",
    '    user = request.args.get("user")',
    '    pw = request.args.get("pw")',
    '    conn = sqlite3.connect("app.db")',
    '    query = "SELECT * FROM users WHERE name = \'" + user + "\' AND pw = \'" + pw + "\'"',
    "    row = conn.execute(query).fetchone()",
    "    if row:",
    '        return "Bienvenido " + user',
    '    return "Login incorrecto"',
    "",
    '@app.route("/file")',
    "def read_file():",
    '    name = request.args.get("name")',
    '    with open("/data/" + name) as f:   # path traversal',
    "        return f.read()",
    "",
    'if __name__ == "__main__":',
    "    app.run(debug=True)               # debug en producción",
    "",
])


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
    parser.add_argument("--sin-limpieza", action="store_true",
                        help="no hacer la pasada final que cierra los MEDIA/BAJA restantes")
    args = parser.parse_args()

    if os.environ.get("ANTHROPIC_API_KEY"):
        print(C.AMAR + "[aviso] ANTHROPIC_API_KEY está definida: el SDK facturará "
              "como API de pago, NO con tu plan Pro.\n"
              "        Para usar el Pro: quita esa variable y haz login con `claude` "
              "-> /login." + C.OFF)

    work = preparar_directorio(args)
    ok = asyncio.run(duelo(work, max_rondas=args.rondas,
                           limpieza_final=not args.sin_limpieza))
    raise SystemExit(0 if ok else 1)
