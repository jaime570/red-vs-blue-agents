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
    pip install -r requirements.txt     (anthropic + python-dotenv)
    Crea un fichero .env con:  ANTHROPIC_API_KEY=tu-api-key

Uso:
    python duelo_seguridad.py                        # demo
    python duelo_seguridad.py mi_app.py --rondas 3   # tu código
    python duelo_seguridad.py mi_app.py --salida app_segura.py
==================================================================
"""

import os
import json
import argparse
from pathlib import Path
from anthropic import Anthropic
from dotenv import load_dotenv

from comun import (C, InformeInvalido, extraer_vulnerabilidades, parsear_json,
                   imprimir_vulns, imprimir_marcador, puntuar, bloqueantes)

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


def agente_rojo(codigo: str, reintentos: int = 1) -> list:
    """Devuelve la lista de vulnerabilidades encontradas.

    Si la respuesta no es un JSON válido se reintenta; si sigue fallando se
    lanza InformeInvalido. NUNCA se devuelve [] por un error de parseo, porque
    [] significa "código limpio" y daría la victoria al azul sin merecerla."""
    prompt = f"""Audita el siguiente código y reporta sus vulnerabilidades en el JSON indicado:

```
{codigo}
```"""
    for intento in range(reintentos + 1):
        salida = llamar_claude(SYSTEM_ROJO, prompt)
        try:
            return extraer_vulnerabilidades(salida)
        except InformeInvalido as e:
            print(C.AMAR + f"[!] El rojo no devolvió un informe válido ({e})." + C.OFF)
            if intento < reintentos:
                print(C.AMAR + "    Reintentando..." + C.OFF)
                prompt += ("\n\nIMPORTANTE: responde SOLO con el JSON pedido, "
                           "sin texto adicional.")
            else:
                print(C.GRIS + "Respuesta cruda:\n" + salida + C.OFF)
    raise InformeInvalido("el rojo no devolvió un informe válido tras reintentar")


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
# ORQUESTADOR DEL DUELO
# ------------------------------------------------------------------
def duelo(codigo_inicial: str, max_rondas: int = MAX_RONDAS,
          salida: Path | None = None) -> str | None:
    """Ejecuta el duelo y devuelve el código final (o None si se interrumpe).
    Si se indica `salida`, guarda ahí el código endurecido."""
    codigo = codigo_inicial
    historial = []

    print(C.NEG + "\n" + "=" * 70)
    print("  DUELO DE SEGURIDAD: ROJO (ataque) vs AZUL (defensa)")
    print("=" * 70 + C.OFF)

    for ronda in range(1, max_rondas + 1):
        print(f"\n{C.NEG}── RONDA {ronda} ──{C.OFF}")

        # 1) El rojo ataca
        print(f"{C.ROJO}🔴 ROJO auditando...{C.OFF}")
        try:
            vulns = agente_rojo(codigo)
        except InformeInvalido as e:
            # Sin informe fiable no se puede decidir un ganador: paramos.
            print(f"\n{C.AMAR}{C.NEG}⚠ Duelo interrumpido:{C.OFF} {e}. "
                  f"No se declara ganador.")
            imprimir_marcador(historial)
            return None
        imprimir_vulns(vulns)
        historial.append({"ronda": ronda, "puntos": puntuar(vulns), "n_vulns": len(vulns)})

        # ¿Quedan fallos bloqueantes (CRÍTICA/ALTA)?
        pendientes = bloqueantes(vulns)
        if not pendientes:
            print(f"\n{C.AZUL}{C.NEG}🏆 ¡Gana AZUL!{C.OFF} "
                  f"El rojo ya no encuentra fallos críticos ni altos.")
            print(f"{C.GRIS}(Pueden quedar avisos menores; revisa el informe.){C.OFF}")
            break

        # 2) El azul defiende
        print(f"\n{C.AZUL}🔵 AZUL parcheando ({len(pendientes)} fallos bloqueantes)...{C.OFF}")
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

    imprimir_marcador(historial)

    print(f"\n{C.NEG}── CÓDIGO FINAL ──{C.OFF}")
    print(codigo)
    if salida:
        salida.write_text(codigo, encoding="utf-8")
        print(f"\n{C.VERDE}💾 Código endurecido guardado en: {salida}{C.OFF}")
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
    parser.add_argument("--salida",
                        help="dónde guardar el código endurecido "
                             "(por defecto: <archivo>_endurecido.<ext>)")
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
        salida = Path(args.salida) if args.salida else ruta.with_name(
            f"{ruta.stem}_endurecido{ruta.suffix}")
    else:
        codigo = CODIGO_VULNERABLE
        print("ℹ️  Sin archivo indicado: usando la demo CODIGO_VULNERABLE.")
        salida = Path(args.salida) if args.salida else Path("demo_endurecido.py")

    resultado = duelo(codigo, max_rondas=args.rondas, salida=salida)
    raise SystemExit(0 if resultado is not None else 1)
