"""
Sistema de reservas de canchas - Backend (Flask)
Ejecutar local:  python app.py
Produccion:      gunicorn -w 2 -b 0.0.0.0:8000 app:app

Variables de entorno:
  SECRET_KEY      clave para firmar sesiones (OBLIGATORIA en la nube; igual en todas las instancias)
  DATABASE_URL    ej. postgresql+psycopg2://usuario:clave@host:5432/reservas  (por defecto SQLite local)
  COOKIE_SECURE   "1" cuando el sitio se sirve por HTTPS
  ENABLE_STRESS   "1" habilita /api/stress para disparar el autoescalado en la demo
"""
import os
import re
import socket
import time
import hashlib
from collections import defaultdict
from datetime import date, datetime

from flask import Flask, jsonify, request, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "cambia-esto-en-produccion"),
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///reservas.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,  # limita el tamano de las peticiones
)
db = SQLAlchemy(app)

RECURSOS = ["Cancha 1", "Cancha 2", "Cancha 3"]
HORAS = list(range(8, 22))  # 8:00 a 21:00
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ----------------------------- Modelos -----------------------------
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    acepta_datos = db.Column(db.Boolean, nullable=False, default=False)  # Ley 1581 de 2012
    creado = db.Column(db.DateTime, default=datetime.utcnow)


class Reserva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False, index=True)
    recurso = db.Column(db.String(40), nullable=False)
    fecha = db.Column(db.Date, nullable=False)
    hora = db.Column(db.Integer, nullable=False)
    creado = db.Column(db.DateTime, default=datetime.utcnow)
    # Evita doble reserva del mismo recurso a la misma hora
    __table_args__ = (db.UniqueConstraint("recurso", "fecha", "hora", name="uq_reserva_slot"),)


with app.app_context():
    db.create_all()


# ----------------------------- Utilidades -----------------------------
def error(msg, code=400):
    return jsonify({"error": msg}), code


def usuario_actual():
    uid = session.get("uid")
    return db.session.get(Usuario, uid) if uid else None


def log(evento, **datos):
    """Registro simple de eventos de seguridad (va a stdout -> CloudWatch/Logging)."""
    extra = " ".join(f"{k}={v}" for k, v in datos.items())
    print(f"[{datetime.utcnow().isoformat()}] {evento} ip={ip_cliente()} {extra}", flush=True)


def ip_cliente():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()


# Limitador de intentos de login (en memoria, por instancia)
_fallos = defaultdict(list)
VENTANA, MAX_FALLOS = 300, 5


def bloqueado(ip):
    ahora = time.time()
    _fallos[ip] = [t for t in _fallos[ip] if ahora - t < VENTANA]
    return len(_fallos[ip]) >= MAX_FALLOS


# ----------------------------- Seguridad -----------------------------
@app.before_request
def proteger_api():
    # Mitigacion CSRF: las peticiones que modifican datos deben traer este
    # encabezado personalizado, que un formulario de otro sitio no puede enviar.
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "DELETE"):
        if request.headers.get("X-Requested-With") != "fetch":
            return error("Peticion no permitida", 403)


@app.after_request
def cabeceras(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    )
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ----------------------------- Frontend y salud -----------------------------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/health")
def health():
    """Usado por el balanceador de carga. Muestra que instancia respondio."""
    return jsonify({"status": "ok", "instancia": socket.gethostname()})


# ----------------------------- Autenticacion -----------------------------
@app.post("/api/registro")
def registro():
    d = request.get_json(silent=True) or {}
    nombre = str(d.get("nombre", "")).strip()
    email = str(d.get("email", "")).strip().lower()
    clave = str(d.get("password", ""))

    if not (2 <= len(nombre) <= 80):
        return error("El nombre debe tener entre 2 y 80 caracteres")
    if not EMAIL_RE.match(email) or len(email) > 120:
        return error("Correo no valido")
    if len(clave) < 8:
        return error("La contrasena debe tener al menos 8 caracteres")
    if d.get("acepta_datos") is not True:
        return error("Debes aceptar el tratamiento de datos personales")

    u = Usuario(
        nombre=nombre,
        email=email,
        password_hash=generate_password_hash(clave),  # hash con sal (nunca texto plano)
        acepta_datos=True,
    )
    db.session.add(u)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return error("Ese correo ya esta registrado", 409)

    session.clear()
    session["uid"] = u.id
    log("REGISTRO", usuario=u.id)
    return jsonify({"id": u.id, "nombre": u.nombre, "email": u.email}), 201


@app.post("/api/login")
def login():
    ip = ip_cliente()
    if bloqueado(ip):
        log("LOGIN_BLOQUEADO")
        return error("Demasiados intentos. Espera unos minutos.", 429)

    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    u = Usuario.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash, str(d.get("password", ""))):
        _fallos[ip].append(time.time())
        log("LOGIN_FALLIDO", email=email)
        return error("Correo o contrasena incorrectos", 401)

    session.clear()
    session["uid"] = u.id
    log("LOGIN_OK", usuario=u.id)
    return jsonify({"id": u.id, "nombre": u.nombre, "email": u.email})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    u = usuario_actual()
    if not u:
        return error("No autenticado", 401)
    return jsonify({"id": u.id, "nombre": u.nombre, "email": u.email})


# ----------------------------- Reservas -----------------------------
@app.get("/api/config")
def config():
    return jsonify({"recursos": RECURSOS, "horas": HORAS})


@app.get("/api/disponibilidad")
def disponibilidad():
    if not usuario_actual():
        return error("No autenticado", 401)
    recurso = request.args.get("recurso", "")
    try:
        f = date.fromisoformat(request.args.get("fecha", ""))
    except ValueError:
        return error("Fecha no valida")
    ocupadas = [r.hora for r in Reserva.query.filter_by(recurso=recurso, fecha=f).all()]
    return jsonify({"ocupadas": ocupadas})


@app.get("/api/reservas")
def listar():
    u = usuario_actual()
    if not u:
        return error("No autenticado", 401)
    rs = (Reserva.query.filter_by(usuario_id=u.id)
          .order_by(Reserva.fecha, Reserva.hora).all())
    return jsonify([{"id": r.id, "recurso": r.recurso, "fecha": r.fecha.isoformat(), "hora": r.hora}
                    for r in rs])


@app.post("/api/reservas")
def crear():
    u = usuario_actual()
    if not u:
        return error("No autenticado", 401)
    d = request.get_json(silent=True) or {}
    recurso = d.get("recurso")
    try:
        f = date.fromisoformat(str(d.get("fecha", "")))
        hora = int(d.get("hora"))
    except (ValueError, TypeError):
        return error("Datos no validos")

    if recurso not in RECURSOS or hora not in HORAS:
        return error("Recurso u hora no validos")
    if f < date.today():
        return error("No puedes reservar en fechas pasadas")

    r = Reserva(usuario_id=u.id, recurso=recurso, fecha=f, hora=hora)
    db.session.add(r)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return error("Ese horario ya esta reservado", 409)
    log("RESERVA_CREADA", usuario=u.id, reserva=r.id)
    return jsonify({"id": r.id}), 201


@app.delete("/api/reservas/<int:rid>")
def cancelar(rid):
    u = usuario_actual()
    if not u:
        return error("No autenticado", 401)
    r = Reserva.query.filter_by(id=rid, usuario_id=u.id).first()  # solo puede borrar las suyas
    if not r:
        return error("Reserva no encontrada", 404)
    db.session.delete(r)
    db.session.commit()
    log("RESERVA_CANCELADA", usuario=u.id, reserva=rid)
    return jsonify({"ok": True})


# ----------------------------- Prueba de autoescalado -----------------------------
if os.getenv("ENABLE_STRESS") == "1":
    @app.get("/api/stress")
    def stress():
        """Consume CPU ~0.3 s por peticion para forzar el autoescalado. Desactivar despues de la demo."""
        fin = time.time() + 0.3
        h = b"x"
        while time.time() < fin:
            h = hashlib.sha256(h).digest()
        return jsonify({"instancia": socket.gethostname()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)), debug=False)
