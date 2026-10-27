import hmac
import os
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from functools import wraps

from flask import Flask, abort, jsonify, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import safe_join

app = Flask(__name__)

# Entorno de despliegue. Por defecto se asume "production" (postura segura
# por defecto): solo se permite generar una SECRET_KEY efímera si se declara
# explícitamente un entorno no productivo (APP_ENV=development, etc.).
APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "production")).lower()

# Secretos cargados desde variables de entorno, nunca hardcodeados en el código fuente.
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    if APP_ENV == "production":
        raise RuntimeError(
            "SECRET_KEY no está definida. En producción es obligatorio fijar "
            "esta variable de entorno (gestionada por un gestor de secretos); "
            "la aplicación no arrancará con una clave generada al vuelo."
        )
    # Solo en entornos explícitamente no productivos se genera una clave
    # efímera, válida únicamente para la vida del proceso actual.
    _secret_key = secrets.token_hex(32)
app.secret_key = _secret_key

DB_PASSWORD = os.environ.get("DB_PASSWORD")  # credencial externa, si se necesitara

DB_PATH = os.environ.get("APP_DB_PATH", "app.db")
DATA_DIR = os.path.realpath(os.environ.get("DATA_DIR", "data"))

# Cookies de sesión reforzadas: solo por HTTPS, inaccesibles desde JS y no
# enviadas en peticiones cross-site "no seguras" (mitiga robo de sesión y
# colabora en la defensa contra CSRF).
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Hash "señuelo" precalculado: se usa para que la verificación de contraseña
# tarde lo mismo exista o no el usuario, evitando un canal lateral de
# temporización que permitiría enumerar cuentas válidas.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(32))

# --- Limitación de intentos de login (mitigación de fuerza bruta) ---------
LOGIN_RATE_LIMIT = 5       # intentos permitidos
LOGIN_RATE_WINDOW = 60     # ventana deslizante, en segundos
_login_attempts = defaultdict(list)
_login_attempts_lock = threading.Lock()


def _login_rate_limited(key):
    """Devuelve True si 'key' (p.ej. IP+usuario) ha superado el límite de
    intentos de login en la ventana temporal configurada."""
    now = time.time()
    with _login_attempts_lock:
        attempts = _login_attempts[key]
        attempts[:] = [t for t in attempts if now - t < LOGIN_RATE_WINDOW]
        if len(attempts) >= LOGIN_RATE_LIMIT:
            return True
        attempts.append(now)
        return False


def _get_csrf_token():
    """Obtiene (generando si no existe) el token CSRF ligado a la sesión
    actual, usado para proteger el POST de /login frente a CSRF."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


def _extract_credentials():
    """Lee 'user'/'pw' del cuerpo de la petición (JSON o form-data), nunca
    de la query string, para no exponerlos en logs, historial o Referer."""
    if request.is_json:
        data = request.get_json(silent=True) or {}
        return data.get("user", ""), data.get("pw", "")
    return request.form.get("user", ""), request.form.get("pw", "")


def _extract_csrf_token():
    if request.is_json:
        data = request.get_json(silent=True) or {}
        token = data.get("csrf_token")
        if token:
            return token
    token = request.form.get("csrf_token")
    if token:
        return token
    return request.headers.get("X-CSRF-Token", "")


def login_required(view):
    """Exige una sesión autenticada para acceder al endpoint protegido."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            abort(401)
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET"])
def login_csrf_token():
    """Emite el token CSRF que el cliente debe incluir en el POST a /login.
    No realiza ninguna acción de autenticación ni acepta credenciales."""
    return jsonify({"csrf_token": _get_csrf_token()})


@app.route("/login", methods=["POST"])
def login():
    # Protección CSRF: el token debe haberse obtenido previamente vía GET y
    # viajar ligado a la sesión del cliente.
    expected_token = session.get("csrf_token")
    provided_token = _extract_csrf_token()
    if not expected_token or not provided_token or not hmac.compare_digest(
        expected_token, provided_token
    ):
        abort(400)

    # Credenciales leídas del cuerpo de la petición (JSON o form-data), no
    # de parámetros de query string en una URL.
    user, pw = _extract_credentials()

    if not user or not pw:
        return "Login incorrecto", 400

    # Limitación de intentos por IP + usuario para mitigar fuerza bruta.
    rate_key = f"{request.remote_addr}:{user}"
    if _login_rate_limited(rate_key):
        return "Demasiados intentos, inténtalo más tarde", 429

    conn = sqlite3.connect(DB_PATH)
    try:
        # Consulta parametrizada: evita inyección SQL.
        row = conn.execute(
            "SELECT pw FROM users WHERE name = ?", (user,)
        ).fetchone()
    finally:
        conn.close()

    # La columna 'pw' almacena un hash (bcrypt/pbkdf2/scrypt) generado con
    # werkzeug.security.generate_password_hash, nunca texto plano.
    #
    # Se ejecuta SIEMPRE la verificación de hash (contra un hash señuelo si
    # el usuario no existe) para que el tiempo de respuesta no revele si la
    # cuenta existe (mitiga canal lateral de temporización).
    stored_hash = row[0] if row and row[0] else _DUMMY_PASSWORD_HASH
    password_ok = check_password_hash(stored_hash, pw)

    if row and password_ok:
        session.clear()
        session["user"] = user
        # La entrada se escapa antes de reflejarla para evitar XSS reflejado.
        return f"Bienvenido {escape(user)}"

    # Mensaje genérico e idéntico para usuario inexistente o contraseña
    # incorrecta, para no facilitar la enumeración de cuentas.
    return "Login incorrecto", 401


@app.route("/file")
@login_required
def read_file():
    name = request.args.get("name", "")

    # Solo se permite un nombre de fichero simple, sin separadores de ruta
    # ni secuencias de traversal ('..', rutas absolutas, etc.).
    if not name or os.path.basename(name) != name:
        abort(400)

    safe_path = safe_join(DATA_DIR, name)
    if safe_path is None:
        abort(400)

    real_path = os.path.realpath(safe_path)
    # Verificación adicional de que la ruta resuelta sigue dentro del
    # directorio base permitido (defensa en profundidad).
    if real_path != DATA_DIR and not real_path.startswith(DATA_DIR + os.sep):
        abort(403)

    if not os.path.isfile(real_path):
        abort(404)

    try:
        with open(real_path) as f:
            return f.read()
    except OSError:
        abort(404)


if __name__ == "__main__":
    # El modo debug solo se activa explícitamente vía variable de entorno,
    # nunca por defecto, para no exponer la consola interactiva de Werkzeug.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)
