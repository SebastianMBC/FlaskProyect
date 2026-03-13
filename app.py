from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from functools import wraps
from db import get_connection
import jwt
import datetime

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
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ═════════════════════════════════════════════════════════════
#  DECORADORES JWT (API)
# ═════════════════════════════════════════════════════════════

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = verificar_token()
        if payload is None:
            return jsonify({
                "status": "error",
                "message": "Token inválido o no proporcionado. Inicia sesión en /api/auth/login"
            }), 401
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated


def jwt_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = verificar_token()
        if payload is None:
            return jsonify({"status": "error", "message": "Token inválido o no proporcionado"}), 401
        if payload.get("rol") != "administrador":
            return jsonify({"status": "error", "message": "Acceso denegado: se requiere rol administrador"}), 403
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated


# ═════════════════════════════════════════════════════════════
#  DECORADORES SESIÓN (vistas HTML)
# ═════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "administrador":
            return "Acceso denegado", 403
        return f(*args, **kwargs)
    return decorated_function


# ═════════════════════════════════════════════════════════════
#  API – AUTENTICACIÓN JWT
# ═════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json()
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
        return jsonify({"status": "error", "message": "Usuario no encontrado"}), 404
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
    cursor.execute("INSERT INTO usuarios (nombre, email) VALUES (%s, %s)", (nombre, email))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Usuario creado correctamente"}), 201


@app.route("/api/usuarios/<int:id>", methods=["PUT"])
@jwt_required
def api_actualizar_usuario(id):
    data   = request.get_json()
    nombre = data.get("nombre")
    email  = data.get("email")
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET nombre=%s, email=%s WHERE id=%s", (nombre, email, id))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Usuario actualizado correctamente"})


@app.route("/api/usuarios/<int:id>", methods=["DELETE"])
@jwt_admin_required
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
    cursor.execute("SELECT * FROM cursos")
    data = cursor.fetchall()
    conn.close()
    return jsonify({"status": "ok", "data": data})


@app.route("/api/cursos/<int:id>", methods=["GET"])
def api_obtener_curso(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos WHERE id = %s", (id,))
    curso = cursor.fetchone()
    conn.close()
    if curso is None:
        return jsonify({"status": "error", "message": "Curso no encontrado"}), 404
    return jsonify({"status": "ok", "data": curso})


@app.route("/api/cursos", methods=["POST"])
@jwt_admin_required
def api_crear_curso():
    data        = request.get_json()
    nombre      = data.get("nombre")
    descripcion = data.get("descripcion")
    if not nombre:
        return jsonify({"status": "error", "message": "El nombre es requerido"}), 400
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO cursos (nombre, descripcion) VALUES (%s, %s)", (nombre, descripcion))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Curso creado correctamente"}), 201


@app.route("/api/cursos/<int:id>", methods=["PUT"])
@jwt_admin_required
def api_actualizar_curso(id):
    data        = request.get_json()
    nombre      = data.get("nombre")
    descripcion = data.get("descripcion")
    conn        = get_connection()
    cursor      = conn.cursor()
    cursor.execute("UPDATE cursos SET nombre=%s, descripcion=%s WHERE id=%s", (nombre, descripcion, id))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Curso actualizado correctamente"})


@app.route("/api/cursos/<int:id>", methods=["DELETE"])
@jwt_admin_required
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
        JOIN cursos  c ON i.curso_id  = c.id
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
        JOIN cursos  c ON i.curso_id  = c.id
        WHERE i.id = %s
    """, (id,))
    inscripcion = cursor.fetchone()
    conn.close()
    if inscripcion is None:
        return jsonify({"status": "error", "message": "Inscripción no encontrada"}), 404
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
    cursor.execute("INSERT INTO inscripciones (usuario_id, curso_id) VALUES (%s, %s)",
                   (usuario_id, curso_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Inscripción creada correctamente"}), 201


@app.route("/api/inscripciones/<int:id>", methods=["DELETE"])
@jwt_admin_required
def api_eliminar_inscripcion(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inscripciones WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Inscripción eliminada"})


# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – INICIO / AUTH
# ═════════════════════════════════════════════════════════════

@app.route('/', methods=['GET', 'POST'])
def inicio():
    nombre = None
    if request.method == 'POST':
        nombre = request.form['nombre']
    return render_template('index.html', nombre=nombre)


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
            return redirect(url_for("usuarios"))
        return "Credenciales incorrectas"
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/cambiar_clave", methods=["GET", "POST"])
@login_required
def cambiar_clave():
    if request.method == "POST":
        nueva      = request.form["nueva"]
        clave_hash = bcrypt.generate_password_hash(nueva).decode("utf-8")
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE usuarios_sistema SET clave = %s WHERE id = %s",
                       (clave_hash, session["usuario_id"]))
        conn.commit()
        conn.close()
        return redirect(url_for("usuarios"))
    return render_template("cambiar_clave.html")


# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – USUARIOS (alumnos)
# ═════════════════════════════════════════════════════════════

@app.route('/usuarios')
def usuarios():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
    return render_template('usuarios.html', usuarios=usuarios)


@app.route('/usuarios/nuevo')
def nuevo_usuario():
    return render_template('usuarios_form.html')


@app.route('/usuarios/editar/<int:id>')
def editar_usuario(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    return render_template('usuarios_form.html', usuario=usuario)


@app.route('/usuarios/actualizar/<int:id>', methods=['POST'])
def actualizar_usuario(id):
    nombre = request.form['nombre']
    email  = request.form['email']
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET nombre=%s, email=%s WHERE id=%s", (nombre, email, id))
    conn.commit()
    return redirect('/usuarios')


@app.route('/usuarios/eliminar/<int:id>')
def eliminar_usuario(id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    return redirect('/usuarios')


@app.route('/usuarios/guardar', methods=['POST'])
def guardar_usuario():
    nombre = request.form['nombre']
    email  = request.form['email']
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO usuarios (nombre, email) VALUES (%s, %s)", (nombre, email))
    conn.commit()
    return redirect('/usuarios')


# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – USUARIOS SISTEMA
# ═════════════════════════════════════════════════════════════

@app.route('/sistema/usuarios')
@login_required
@admin_required
def sistema_usuarios():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, correo, nombres, apellidos, rol FROM usuarios_sistema")
    usuarios = cursor.fetchall()
    conn.close()
    return render_template('sistema_usuarios.html', usuarios=usuarios)


@app.route("/sistema/usuarios/nuevo", methods=["GET", "POST"])
@login_required
@admin_required
def usuarios_sistema_nuevo():
    if request.method == "POST":
        correo    = request.form["correo"]
        nombres   = request.form["nombres"]
        apellidos = request.form["apellidos"]
        rol       = request.form["rol"]
        clave_hash = bcrypt.generate_password_hash("123456").decode("utf-8")
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO usuarios_sistema (correo, nombres, apellidos, clave, rol)
            VALUES (%s, %s, %s, %s, %s)
        """, (correo, nombres, apellidos, clave_hash, rol))
        conn.commit()
        conn.close()
        flash('Usuario creado correctamente. Clave por defecto: 123456', 'success')
        return redirect(url_for("sistema_usuarios"))
    return render_template("usuarios_sistema_form.html")


@app.route('/sistema/usuarios/restaurar/<int:id>', methods=['POST'])
@login_required
@admin_required
def sistema_usuarios_restaurar(id):
    nuevo_hash = bcrypt.generate_password_hash("123456").decode('utf-8')
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios_sistema SET clave = %s WHERE id = %s", (nuevo_hash, id))
    conn.commit()
    conn.close()
    flash('Contraseña restaurada a 123456 correctamente', 'success')
    return redirect(url_for('sistema_usuarios'))


@app.route('/sistema/usuarios/eliminar/<int:id>', methods=['POST'])
@login_required
@admin_required
def sistema_usuarios_eliminar(id):
    # Evitar que el admin se elimine a sí mismo
    if id == session.get("usuario_id"):
        flash('No puedes eliminarte a ti mismo', 'danger')
        return redirect(url_for('sistema_usuarios'))
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios_sistema WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    flash('Usuario eliminado correctamente', 'danger')
    return redirect(url_for('sistema_usuarios'))


# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – INSCRIPCIONES
# ═════════════════════════════════════════════════════════════

@app.route('/inscripciones')
def inscripciones():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id, u.nombre AS usuario, c.nombre AS curso, i.fecha_inscripcion
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos  c ON i.curso_id  = c.id
    """)
    data = cursor.fetchall()
    return render_template('inscripciones.html', inscripciones=data)


@app.route("/inscripciones/nueva", methods=["GET", "POST"])
@login_required
def inscripcion_nueva():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre FROM usuarios")
    alumnos = cursor.fetchall()
    cursor.execute("SELECT id, nombre FROM cursos")
    cursos = cursor.fetchall()
    if request.method == "POST":
        alumno_id = request.form["alumno_id"]
        curso_id  = request.form["curso_id"]
        cursor.execute("INSERT INTO inscripciones (usuario_id, curso_id) VALUES (%s, %s)",
                       (alumno_id, curso_id))
        conn.commit()
        conn.close()
        return redirect(url_for("inscripciones"))
    conn.close()
    return render_template("inscripcion_form.html", alumnos=alumnos, cursos=cursos)


# ═════════════════════════════════════════════════════════════
#  VISTAS HTML – CURSOS
# ═════════════════════════════════════════════════════════════

@app.route('/cursos')
@login_required
def cursos():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos")
    cursos = cursor.fetchall()
    cursor.close()
    return render_template('cursos/index.html', cursos=cursos)


@app.route('/cursos/nuevo')
@login_required
@admin_required
def nuevo_curso():
    return render_template('cursos/nuevo.html')


@app.route('/login_test')
def login_test():
    return render_template('Login_Test.html')


@app.route('/cursos/guardar', methods=['POST'])
@login_required
@admin_required
def guardar_curso():
    nombre      = request.form['nombre']
    descripcion = request.form['descripcion']
    conn        = get_connection()
    cursor      = conn.cursor(dictionary=True)
    cursor.execute("INSERT INTO cursos (nombre, descripcion) VALUES (%s, %s)", (nombre, descripcion))
    conn.commit()
    cursor.close()
    flash('Curso registrado correctamente', 'success')
    return redirect(url_for('cursos'))


# ─────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)