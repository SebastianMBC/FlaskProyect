from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from functools import wraps
from db import get_connection
import jwt
import datetime
import os

app = Flask(__name__)

app.secret_key = "clave_secreta_segura"
JWT_SECRET    = "jwt_clave_super_secreta"
JWT_ALGORITHM = "HS256"

bcrypt = Bcrypt(app)

# ═════════════════════════════════════════════════════════════
#  HELPERS JWT
# ═════════════════════════════════════════════════════════════

def generar_token(usuario_id, rol):
    payload = {
        "usuario_id": usuario_id,
        "rol": rol,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verificar_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ")[1]
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except:
        return None

# ═════════════════════════════════════════════════════════════
#  DECORADORES
# ═════════════════════════════════════════════════════════════

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = verificar_token()
        if payload is None:
            return jsonify({"status": "error", "message": "Token inválido o expirado"}), 401
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "administrador":
            return "Acceso denegado", 403
        return f(*args, **kwargs)
    return decorated_function

# ═════════════════════════════════════════════════════════════
#  AUTENTICACIÓN
# ═════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form["correo"]
        clave  = request.form["clave"]
        conn   = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios_sistema WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        conn.close()
        if usuario and bcrypt.check_password_hash(usuario["clave"], clave):
            session["usuario_id"] = usuario["id"]
            session["rol"]        = usuario["rol"]
            session["nombre"]     = usuario["nombres"]
            session["jwt_token"]  = generar_token(usuario["id"], usuario["rol"])
            return redirect(url_for("usuarios"))
        flash("Credenciales incorrectas", "error")
        return render_template("login.html")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – USUARIOS
# ═════════════════════════════════════════════════════════════

@app.route('/usuarios')
@login_required
def usuarios():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email FROM usuarios")
    lista_usuarios = cursor.fetchall()
    conn.close()
    return render_template('usuarios.html', usuarios=lista_usuarios)

@app.route('/usuarios/guardar', methods=['POST'])
@login_required
def guardar_usuario():
    nombre = request.form['nombre']
    email  = request.form['email']
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO usuarios (nombre, email) VALUES (%s, %s)",
        (nombre, email)
    )
    conn.commit()
    conn.close()
    return redirect('/usuarios')

@app.route('/usuarios/actualizar/<int:id>', methods=['POST'])
@login_required
def actualizar_usuario(id):
    nombre = request.form['nombre']
    email  = request.form['email']
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET nombre=%s, email=%s WHERE id=%s",
        (nombre, email, id)
    )
    conn.commit()
    conn.close()
    return redirect('/usuarios')

@app.route('/usuarios/eliminar/<int:id>')
@login_required
def eliminar_usuario(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return redirect('/usuarios')

# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – CURSOS  ← NUEVO
# ═════════════════════════════════════════════════════════════

@app.route('/cursos')
@login_required
def cursos():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, descripcion, estado FROM cursos")
    lista_cursos = cursor.fetchall()
    conn.close()
    return render_template('cursos/index.html', cursos=lista_cursos)

@app.route('/cursos/nuevo')
@login_required
def nuevo_curso():
    return render_template('cursos/nuevo.html')

@app.route('/cursos/guardar', methods=['POST'])
@login_required
def guardar_curso():
    nombre      = request.form['nombre']
    descripcion = request.form.get('descripcion', '')
    estado      = int(request.form.get('estado', 1))
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cursos (nombre, descripcion, estado) VALUES (%s, %s, %s)",
        (nombre, descripcion, estado)
    )
    conn.commit()
    conn.close()
    return redirect('/cursos')

@app.route('/cursos/actualizar/<int:id>', methods=['POST'])
@login_required
def actualizar_curso(id):
    nombre      = request.form['nombre']
    descripcion = request.form.get('descripcion', '')
    estado      = int(request.form.get('estado', 1))
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cursos SET nombre=%s, descripcion=%s, estado=%s WHERE id=%s",
        (nombre, descripcion, estado, id)
    )
    conn.commit()
    conn.close()
    return redirect('/cursos')

@app.route('/cursos/eliminar/<int:id>')
@login_required
def eliminar_curso(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cursos WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return redirect('/cursos')

# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – INSCRIPCIONES
# ═════════════════════════════════════════════════════════════

@app.route('/inscripciones')
@login_required
def inscripciones():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id, u.nombre AS usuario, c.nombre AS curso, i.fecha_inscripcion
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos   c ON i.curso_id   = c.id
    """)
    data = cursor.fetchall()

    # Listas para el formulario de nueva inscripción
    cursor.execute("SELECT id, nombre FROM usuarios")
    lista_usuarios = cursor.fetchall()
    cursor.execute("SELECT id, nombre FROM cursos")
    lista_cursos = cursor.fetchall()
    conn.close()
    return render_template(
        'inscripciones.html',
        inscripciones=data,
        usuarios=lista_usuarios,
        cursos=lista_cursos
    )

@app.route('/inscripciones/guardar', methods=['POST'])
@login_required
def guardar_inscripcion():
    usuario_id = request.form['usuario_id']
    curso_id   = request.form['curso_id']
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO inscripciones (usuario_id, curso_id) VALUES (%s, %s)",
        (usuario_id, curso_id)
    )
    conn.commit()
    conn.close()
    return redirect('/inscripciones')

@app.route('/inscripciones/eliminar/<int:id>')
@login_required
def eliminar_inscripcion(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inscripciones WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return redirect('/inscripciones')

# ═════════════════════════════════════════════════════════════
#  PANEL API  ← NUEVO
# ═════════════════════════════════════════════════════════════

# ═════════════════════════════════════════════════════════════
#  API REST – AUTH
# ═════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data   = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Se esperaba JSON"}), 400
    correo = data.get("correo")
    clave  = data.get("clave")
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios_sistema WHERE correo = %s", (correo,))
    usuario = cursor.fetchone()
    conn.close()
    if not usuario or not bcrypt.check_password_hash(usuario["clave"], clave):
        return jsonify({"status": "error", "message": "Credenciales incorrectas"}), 401
    token = generar_token(usuario["id"], usuario["rol"])
    return jsonify({
        "status":  "ok",
        "message": f"Bienvenido {usuario['nombres']}",
        "token":   token,
        "rol":     usuario["rol"]
    })

# ═════════════════════════════════════════════════════════════
#  API REST – USUARIOS
# ═════════════════════════════════════════════════════════════

@app.route("/api/usuarios", methods=["GET"])
def api_listar_usuarios():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email FROM usuarios")
    data = cursor.fetchall()
    conn.close()
    return jsonify({"status": "ok", "data": data})

@app.route("/api/usuarios/<int:id>", methods=["GET"])
def api_obtener_usuario(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, email FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    conn.close()
    if usuario is None:
        return jsonify({"status": "error", "message": "No encontrado"}), 404
    return jsonify({"status": "ok", "data": usuario})

@app.route("/api/usuarios", methods=["POST"])
@jwt_required
def api_crear_usuario():
    data   = request.get_json()
    nombre = data.get("nombre")
    email  = data.get("email")
    if not nombre or not email:
        return jsonify({"status": "error", "message": "nombre y email son requeridos"}), 400
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO usuarios (nombre, email) VALUES (%s, %s)",
        (nombre, email)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Usuario creado"}), 201

@app.route("/api/usuarios/<int:id>", methods=["PUT"])
@jwt_required
def api_actualizar_usuario(id):
    data   = request.get_json()
    nombre = data.get("nombre")
    email  = data.get("email")
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET nombre=%s, email=%s WHERE id=%s",
        (nombre, email, id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Usuario actualizado"})

@app.route("/api/usuarios/<int:id>", methods=["DELETE"])
@jwt_required
def api_eliminar_usuario(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Usuario eliminado"})

# ═════════════════════════════════════════════════════════════
#  API REST – CURSOS
# ═════════════════════════════════════════════════════════════

@app.route("/api/cursos", methods=["GET"])
def api_listar_cursos():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, descripcion, estado FROM cursos")
    data = cursor.fetchall()
    conn.close()
    return jsonify({"status": "ok", "data": data})

@app.route("/api/cursos/<int:id>", methods=["GET"])
def api_obtener_curso(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, descripcion, estado FROM cursos WHERE id = %s", (id,))
    curso = cursor.fetchone()
    conn.close()
    if curso is None:
        return jsonify({"status": "error", "message": "No encontrado"}), 404
    return jsonify({"status": "ok", "data": curso})

@app.route("/api/cursos", methods=["POST"])
@jwt_required
def api_crear_curso():
    data        = request.get_json()
    nombre      = data.get("nombre")
    descripcion = data.get("descripcion", "")
    estado      = data.get("estado", 1)
    if not nombre:
        return jsonify({"status": "error", "message": "nombre es requerido"}), 400
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cursos (nombre, descripcion, estado) VALUES (%s, %s, %s)",
        (nombre, descripcion, estado)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Curso creado"}), 201

@app.route("/api/cursos/<int:id>", methods=["PUT"])
@jwt_required
def api_actualizar_curso(id):
    data        = request.get_json()
    nombre      = data.get("nombre")
    descripcion = data.get("descripcion", "")
    estado      = data.get("estado", 1)
    conn        = get_connection()
    cursor      = conn.cursor()
    cursor.execute(
        "UPDATE cursos SET nombre=%s, descripcion=%s, estado=%s WHERE id=%s",
        (nombre, descripcion, estado, id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Curso actualizado"})

@app.route("/api/cursos/<int:id>", methods=["DELETE"])
@jwt_required
def api_eliminar_curso(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cursos WHERE id=%s", (id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Curso eliminado"})

# ═════════════════════════════════════════════════════════════
#  API REST – INSCRIPCIONES
# ═════════════════════════════════════════════════════════════

@app.route("/api/inscripciones", methods=["GET"])
def api_listar_inscripciones():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id, u.nombre AS usuario, c.nombre AS curso, i.fecha_inscripcion
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos   c ON i.curso_id   = c.id
    """)
    data = cursor.fetchall()
    conn.close()
    return jsonify({"status": "ok", "data": data})

@app.route("/api/inscripciones/<int:id>", methods=["GET"])
def api_obtener_inscripcion(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id, u.nombre AS usuario, c.nombre AS curso, i.fecha_inscripcion
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos   c ON i.curso_id   = c.id
        WHERE i.id = %s
    """, (id,))
    inscripcion = cursor.fetchone()
    conn.close()
    if inscripcion is None:
        return jsonify({"status": "error", "message": "No encontrada"}), 404
    return jsonify({"status": "ok", "data": inscripcion})

@app.route("/api/inscripciones", methods=["POST"])
@jwt_required
def api_crear_inscripcion():
    data       = request.get_json()
    usuario_id = data.get("usuario_id")
    curso_id   = data.get("curso_id")
    if not usuario_id or not curso_id:
        return jsonify({"status": "error", "message": "usuario_id y curso_id son requeridos"}), 400
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO inscripciones (usuario_id, curso_id) VALUES (%s, %s)",
        (usuario_id, curso_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Inscripción creada"}), 201

@app.route("/api/inscripciones/<int:id>", methods=["DELETE"])
@jwt_required
def api_eliminar_inscripcion(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inscripciones WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Inscripción eliminada"})

# ═════════════════════════════════════════════════════════════
#  INICIO
# ═════════════════════════════════════════════════════════════

@app.route('/')
def inicio():
    if "usuario_id" in session:
        return redirect(url_for("usuarios"))
    return redirect(url_for("login"))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)