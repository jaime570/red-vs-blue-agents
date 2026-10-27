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
