from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import hashlib
import re
import random
import time
from functools import wraps
from datetime import datetime
from flask import jsonify

app = Flask(__name__)
app.secret_key = 'ecoruta_secret_2026'

uri = "mongodb://localhost:27017"
client = MongoClient(uri, server_api=ServerApi("1"))

db = client["Eco-ruta"]

# Colecciones correctas
rutas_col       = db["rutas"]
conductores_col = db["conductores"]
vehiculos_col   = db["camiones"]
usuarios_col    = db["usuarios"]
viajes_col      = db["viajes"]
incidencias_col = db["incidencias"]


# ══════════════════════════════════════════════════════
#  DECORADORES RBAC
# ══════════════════════════════════════════════════════

def requiere_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'rol' not in session:
            return jsonify({'error': 'No autenticado'}), 401
        return f(*args, **kwargs)
    return decorated

def requiere_rol(*roles):
    """Permite solo a los roles indicados. Uso: @requiere_rol('admin','conductor')"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'rol' not in session:
                return jsonify({'error': 'No autenticado'}), 401
            if session['rol'] not in roles:
                return jsonify({'error': f'Acceso denegado. Rol requerido: {", ".join(roles)}'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ══════════════════════════════════════════════════════
#  CAPTCHA MATEMÁTICO + RATE LIMITING DE LOGIN
# ══════════════════════════════════════════════════════

# Registro de intentos fallidos: {ip: {'count': n, 'locked_until': timestamp}}
_login_attempts: dict = {}

MAX_INTENTOS   = 5      # intentos antes de bloquear
BLOQUEO_SEG    = 300    # segundos de bloqueo (5 min)


def _get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()


def _registrar_fallo():
    ip = _get_ip()
    ahora = time.time()
    rec = _login_attempts.setdefault(ip, {'count': 0, 'locked_until': 0})
    rec['count'] += 1
    if rec['count'] >= MAX_INTENTOS:
        rec['locked_until'] = ahora + BLOQUEO_SEG
        rec['count'] = 0  # resetea contador para el siguiente ciclo


def _esta_bloqueado():
    ip = _get_ip()
    rec = _login_attempts.get(ip)
    if rec and rec['locked_until'] > time.time():
        restante = int(rec['locked_until'] - time.time())
        return True, restante
    return False, 0


def _limpiar_intentos():
    ip = _get_ip()
    _login_attempts.pop(ip, None)


def _generar_captcha():
    """Genera una operación aritmética simple y devuelve (pregunta, respuesta)."""
    ops = [
        ('+', lambda a, b: a + b),
        ('-', lambda a, b: a - b),
        ('×', lambda a, b: a * b),
    ]
    simbolo, fn = random.choice(ops)
    if simbolo == '×':
        a, b = random.randint(2, 9), random.randint(2, 9)
    elif simbolo == '-':
        a, b = random.randint(5, 20), random.randint(1, 5)
    else:
        a, b = random.randint(1, 20), random.randint(1, 20)
    return f'{a} {simbolo} {b}', fn(a, b)


@app.route('/api/captcha', methods=['GET'])
def api_captcha():
    """Genera un nuevo CAPTCHA y lo guarda en sesión. Devuelve solo la pregunta."""
    bloqueado, restante = _esta_bloqueado()
    if bloqueado:
        return jsonify({'error': f'Demasiados intentos fallidos. Espera {restante} segundos.', 'bloqueado': True, 'restante': restante}), 429

    pregunta, respuesta = _generar_captcha()
    session['captcha_respuesta'] = respuesta
    session['captcha_ts']        = time.time()          # expira en 5 min
    return jsonify({'pregunta': pregunta})

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ══════════════════════════════════════════════════════
#  VALIDACIONES — expresiones regulares por campo
# ══════════════════════════════════════════════════════

# Nombre completo: letras (incluye acentos), espacios, mín 3 chars
RE_NOMBRE    = re.compile(r'^[A-Za-záéíóúÁÉÍÓÚüÜñÑ\s]{3,80}$')
# Usuario de sistema: letras, números, guión bajo, 3–20 chars
RE_USERNAME  = re.compile(r'^[A-Za-z0-9_]{3,20}$')
# Contraseña: mín 8 chars, al menos 1 letra y 1 dígito
RE_PASSWORD  = re.compile(r'^(?=.*[A-Za-z])(?=.*\d).{8,}$')
# Teléfono: dígitos, espacios, guiones y +, entre 7 y 15 dígitos en total
RE_TELEFONO  = re.compile(r'^\+?[\d\s\-]{7,20}$')
# Licencia: LIC- seguido de 3-10 alfanuméricos, o solo alfanumérico 4-12
RE_LICENCIA  = re.compile(r'^(LIC-[A-Za-z0-9]{2,10}|[A-Za-z0-9\-]{4,15})$', re.IGNORECASE)
# Placa: 2-4 letras, guión, 3-4 alfanuméricos  (ECO-001, ABC-1234)
RE_PLACA     = re.compile(r'^[A-Za-z]{2,4}-[A-Za-z0-9]{3,4}$')
# Capacidad: número entero o decimal puro (sin unidad — se guarda en toneladas)
RE_CAPACIDAD = re.compile(r'^\d+(\.\d+)?$')
# Nombre de ruta: alfanumérico con espacios, guiones, mín 3 chars
RE_RUTA_NOMBRE = re.compile(r'^[\w\s\-áéíóúÁÉÍÓÚüÜñÑ]{3,80}$')


def _err(msg, code=400):
    """Respuesta de error JSON estandarizada."""
    return jsonify({'error': msg}), code


def validar_usuario(data, es_edicion=False):
    """Valida campos de un documento usuario. Retorna lista de errores."""
    errores = []
    nombre   = data.get('nombre', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    rol      = data.get('rol', '').strip()

    if nombre and not RE_NOMBRE.match(nombre):
        errores.append('El nombre solo puede contener letras y espacios (mín 3 caracteres).')
    elif not nombre:
        errores.append('El nombre es obligatorio.')

    if not es_edicion:
        if not username:
            errores.append('El nombre de usuario es obligatorio.')
        elif not RE_USERNAME.match(username):
            errores.append('El usuario solo puede tener letras, números y _ (3-20 caracteres).')

        if not password:
            errores.append('La contraseña es obligatoria.')
        elif not RE_PASSWORD.match(password):
            errores.append('La contraseña debe tener mínimo 8 caracteres, al menos una letra y un número.')

    if rol and rol not in ('admin', 'conductor', 'usuario'):
        errores.append('Rol no válido.')

    return errores


def validar_conductor(data):
    """Valida campos operativos de un conductor. Retorna lista de errores."""
    errores = []
    licencia = data.get('licencia', '').strip()
    telefono = data.get('telefono', '').strip()
    estado   = data.get('estado', '').strip()

    if not licencia:
        errores.append('La licencia es obligatoria.')
    elif not RE_LICENCIA.match(licencia):
        errores.append('Formato de licencia inválido. Ejemplo válido: LIC-001 o A12345.')

    if telefono and not RE_TELEFONO.match(telefono):
        errores.append('Formato de teléfono inválido. Usa entre 7 y 15 dígitos (puede incluir +, -, espacios).')

    if estado and estado not in ('Activo', 'Inactivo', 'Suspendido'):
        errores.append('Estado de conductor no válido.')

    return errores


def validar_camion(data):
    """Valida campos de un camión/vehículo. Retorna lista de errores.
    Convierte capacidad a float en el dict para que se guarde como número."""
    errores = []
    placa     = data.get('placa', '').strip()
    capacidad = str(data.get('capacidad', '')).strip()
    estado    = data.get('estado', '').strip()

    if not placa:
        errores.append('La placa es obligatoria.')
    elif not RE_PLACA.match(placa):
        errores.append('Formato de placa inválido. Ejemplo válido: ECO-001 o ABC-1234.')

    if capacidad:
        if not RE_CAPACIDAD.match(capacidad):
            errores.append('La capacidad debe ser un número (ej: 12 o 8.5). La unidad se gestiona en la interfaz.')
        else:
            # Normalizar a float directamente en el dict
            data['capacidad'] = float(capacidad)

    if estado and estado not in ('Operativo', 'Mantenimiento', 'Fuera de servicio'):
        errores.append('Estado de vehículo no válido.')

    return errores


def validar_ruta(data):
    """Valida campos de una ruta. Retorna lista de errores."""
    errores = []
    nombre = data.get('nombre', '').strip()
    estado = data.get('estado', '').strip()

    if not nombre:
        errores.append('El nombre de la ruta es obligatorio.')
    elif not RE_RUTA_NOMBRE.match(nombre):
        errores.append('El nombre de la ruta contiene caracteres no permitidos (mín 3 chars).')

    if estado and estado not in ('Activa', 'Inactiva', 'Suspendida'):
        errores.append('Estado de ruta no válido.')

    return errores

def init_db():
    """Inserta datos de prueba si las colecciones están vacías."""
    # Índice único en placa de camiones — garantía a nivel de base de datos
    vehiculos_col.create_index('placa', unique=True, sparse=True)

    if usuarios_col.count_documents({}) == 0:
        usuarios_col.insert_many([
            {'nombre': 'Administrador', 'username': 'admin',     'password': hash_pw('admin123'),     'rol': 'admin'},
            {'nombre': 'Juan Pérez',    'username': 'conductor', 'password': hash_pw('conductor123'), 'rol': 'conductor'},
            {'nombre': 'Ana López',     'username': 'usuario',   'password': hash_pw('usuario123'),   'rol': 'usuario'},
        ])
    if rutas_col.count_documents({}) == 0:
        rutas_col.insert_many([
            {'nombre': 'Ruta Norte',   'origen': 'Colonia Norte', 'destino': 'Centro',  'estado': 'Activa'},
            {'nombre': 'Ruta Sur',     'origen': 'Colonia Sur',   'destino': 'Mercado', 'estado': 'Activa'},
        ])
    if vehiculos_col.count_documents({}) == 0:
        vehiculos_col.insert_many([
            {'placa': 'ECO-001', 'modelo': 'Mercedes Econic', 'capacidad': 12.0, 'combustible': 'Diesel', 'estado': 'Operativo'},
            {'placa': 'ECO-002', 'modelo': 'Volvo FE',        'capacidad': 10.0, 'combustible': 'Diesel', 'estado': 'Operativo'},
        ])
    if conductores_col.count_documents({}) == 0:
        conductores_col.insert_many([
            {'nombre': 'Juan Pérez',   'licencia': 'LIC-001', 'telefono': '555-0001', 'estado': 'Activo'},
            {'nombre': 'María García', 'licencia': 'LIC-002', 'telefono': '555-0002', 'estado': 'Activo'},
        ])


# ══════════════════════════════════════════════════════
#  LOGIN / LOGOUT
# ══════════════════════════════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        rol_sel  = request.form.get('rol', '').strip()

        user = usuarios_col.find_one({
            'username': username,
            'password': hash_pw(password),
            'rol':      rol_sel
        })
        if user:
            session['user_id']  = str(user['_id'])
            session['nombre']   = user['nombre']
            session['username'] = user['username']
            session['rol']      = user['rol']
            return redirect(url_for('menu'))
        else:
            flash('Credenciales incorrectas o rol no coincide.', 'error')
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ══════════════════════════════════════════════════════
#  MENÚ PRINCIPAL
# ══════════════════════════════════════════════════════

@app.route('/menu')
def menu():
    if 'rol' not in session:
        return redirect(url_for('login'))
    return render_template('menu.html')


# ══════════════════════════════════════════════════════
#  MÓDULO: RUTAS
# ══════════════════════════════════════════════════════

@app.route('/rutas')
def rutas():
    if 'rol' not in session:
        return redirect(url_for('login'))
    registros = list(rutas_col.find())
    return render_template('rutas.html', registros=registros)

@app.route('/rutas/crear', methods=['POST'])
def rutas_crear():
    if session.get('rol') == 'usuario':
        flash('Sin permiso.', 'error')
        return redirect(url_for('rutas'))
    rutas_col.insert_one({
        'nombre':   request.form['nombre'],
        'origen':   request.form['origen'],
        'destino':  request.form['destino'],
        'estado':   request.form['estado'],
    })
    flash('Ruta creada correctamente.', 'success')
    return redirect(url_for('rutas'))

@app.route('/rutas/editar', methods=['POST'])
def rutas_editar():
    if session.get('rol') == 'usuario':
        flash('Sin permiso.', 'error')
        return redirect(url_for('rutas'))
    rutas_col.update_one(
        {'_id': ObjectId(request.form['id'])},
        {'$set': {
            'nombre':   request.form['nombre'],
            'origen':   request.form['origen'],
            'destino':  request.form['destino'],
            'estado':   request.form['estado'],
        }}
    )
    flash('Ruta actualizada.', 'success')
    return redirect(url_for('rutas'))

@app.route('/rutas/eliminar/<id>', methods=['POST'])
def rutas_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Solo el administrador puede eliminar.', 'error')
        return redirect(url_for('rutas'))
    rutas_col.delete_one({'_id': ObjectId(id)})
    flash('Ruta eliminada.', 'success')
    return redirect(url_for('rutas'))


# ══════════════════════════════════════════════════════
#  MÓDULO: CONDUCTORES
# ══════════════════════════════════════════════════════

@app.route('/conductores')
def conductores():
    if 'rol' not in session:
        return redirect(url_for('login'))
    registros = list(conductores_col.find())
    return render_template('conductores.html', registros=registros)

@app.route('/conductores/crear', methods=['POST'])
def conductores_crear():
    if session.get('rol') == 'usuario':
        flash('Sin permiso.', 'error')
        return redirect(url_for('conductores'))
    conductores_col.insert_one({
        'nombre':   request.form['nombre'],
        'licencia': request.form['licencia'],
        'telefono': request.form['telefono'],
        'estado':   request.form['estado'],
    })
    flash('Conductor registrado.', 'success')
    return redirect(url_for('conductores'))

@app.route('/conductores/editar', methods=['POST'])
def conductores_editar():
    if session.get('rol') == 'usuario':
        flash('Sin permiso.', 'error')
        return redirect(url_for('conductores'))
    conductores_col.update_one(
        {'_id': ObjectId(request.form['id'])},
        {'$set': {
            'nombre':   request.form['nombre'],
            'licencia': request.form['licencia'],
            'telefono': request.form['telefono'],
            'estado':   request.form['estado'],
        }}
    )
    flash('Conductor actualizado.', 'success')
    return redirect(url_for('conductores'))

@app.route('/conductores/eliminar/<id>', methods=['POST'])
def conductores_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Solo el administrador puede eliminar.', 'error')
        return redirect(url_for('conductores'))
    conductores_col.delete_one({'_id': ObjectId(id)})
    flash('Conductor eliminado.', 'success')
    return redirect(url_for('conductores'))


# ══════════════════════════════════════════════════════
#  MÓDULO: VEHÍCULOS
# ══════════════════════════════════════════════════════

@app.route('/vehiculos')
def vehiculos():
    if 'rol' not in session:
        return redirect(url_for('login'))
    registros = list(vehiculos_col.find())
    return render_template('vehiculos.html', registros=registros)

@app.route('/vehiculos/crear', methods=['POST'])
def vehiculos_crear():
    if session.get('rol') == 'usuario':
        flash('Sin permiso.', 'error')
        return redirect(url_for('vehiculos'))
    vehiculos_col.insert_one({
        'placa':      request.form['placa'],
        'modelo':     request.form['modelo'],
        'capacidad':  request.form['capacidad'],
        'combustible':request.form['combustible'],
        'estado':     request.form['estado'],
    })
    flash('Vehículo registrado.', 'success')
    return redirect(url_for('vehiculos'))

@app.route('/vehiculos/editar', methods=['POST'])
def vehiculos_editar():
    if session.get('rol') == 'usuario':
        flash('Sin permiso.', 'error')
        return redirect(url_for('vehiculos'))
    vehiculos_col.update_one(
        {'_id': ObjectId(request.form['id'])},
        {'$set': {
            'placa':       request.form['placa'],
            'modelo':      request.form['modelo'],
            'capacidad':   request.form['capacidad'],
            'combustible': request.form['combustible'],
            'estado':      request.form['estado'],
        }}
    )
    flash('Vehículo actualizado.', 'success')
    return redirect(url_for('vehiculos'))

@app.route('/vehiculos/eliminar/<id>', methods=['POST'])
def vehiculos_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Solo el administrador puede eliminar.', 'error')
        return redirect(url_for('vehiculos'))
    vehiculos_col.delete_one({'_id': ObjectId(id)})
    flash('Vehículo eliminado.', 'success')
    return redirect(url_for('vehiculos'))


# ══════════════════════════════════════════════════════
#  MÓDULO: USUARIOS  (solo admin)
# ══════════════════════════════════════════════════════

@app.route('/usuarios')
def usuarios():
    if session.get('rol') != 'admin':
        flash('Acceso solo para administrador.', 'error')
        return redirect(url_for('menu'))
    registros = list(usuarios_col.find({}, {'password': 0}))
    return render_template('usuarios.html', registros=registros)

@app.route('/usuarios/crear', methods=['POST'])
def usuarios_crear():
    if session.get('rol') != 'admin':
        flash('Sin permiso.', 'error')
        return redirect(url_for('menu'))
    usuarios_col.insert_one({
        'nombre':   request.form['nombre'],
        'username': request.form['username'],
        'password': hash_pw(request.form['password']),
        'rol':      request.form['rol'],
    })
    flash('Usuario creado.', 'success')
    return redirect(url_for('usuarios'))

@app.route('/usuarios/eliminar/<id>', methods=['POST'])
def usuarios_eliminar(id):
    if session.get('rol') != 'admin':
        flash('Sin permiso.', 'error')
        return redirect(url_for('menu'))
    usuarios_col.delete_one({'_id': ObjectId(id)})
    flash('Usuario eliminado.', 'success')
    return redirect(url_for('usuarios'))


# ══════════════════════════════════════════════════════
#  API JSON — agregar en app.py antes del bloque de arranque
# ══════════════════════════════════════════════════════
from flask import jsonify

COLECCIONES = {
    'rutas':       'rutas',
    'usuarios':    'usuarios',
    'camiones':    'camiones',
    'conductores': 'conductores',
}

def col(key):
    return db[COLECCIONES[key]]

def serialize(doc):
    """Convierte ObjectId a string para poder enviar como JSON."""
    doc['_id'] = str(doc['_id'])
    # Convertir cualquier ObjectId anidado (ej: usuario_id)
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            doc[k] = str(v)
    return doc


@app.route('/api/<coleccion>', methods=['GET'])
@requiere_login
def api_listar(coleccion):
    if coleccion not in COLECCIONES:
        return jsonify({'error': 'Colección no válida'}), 404
    # Usuarios y conductores solo visibles para admin y conductor
    if coleccion in ('usuarios', 'conductores') and session['rol'] == 'usuario':
        return jsonify({'error': 'Acceso denegado'}), 403
    docs = [serialize(d) for d in col(coleccion).find()]
    return jsonify(docs)


@app.route('/api/<coleccion>', methods=['POST'])
def api_crear(coleccion):
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    if session['rol'] == 'usuario':
        return jsonify({'error': 'Sin permiso'}), 403
    if coleccion not in COLECCIONES:
        return jsonify({'error': 'Colección no válida'}), 404
    if coleccion == 'conductores':
        return jsonify({'error': 'Usa el endpoint específico para conductores'}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Cuerpo de solicitud vacío'}), 400
    data.pop('_id', None)

    # Validaciones por colección
    if coleccion == 'usuarios':
        errores = validar_usuario(data, es_edicion=False)
        if errores:
            return jsonify({'error': errores[0], 'errores': errores}), 422
        # Hashear contraseña antes de guardar
        if data.get('password'):
            data['password'] = hash_pw(data['password'])

    elif coleccion == 'camiones':
        errores = validar_camion(data)
        if errores:
            return jsonify({'error': errores[0], 'errores': errores}), 422
        # Unicidad de placa al crear — case-insensitive
        placa = data.get('placa', '').strip()
        if vehiculos_col.find_one({'placa': {'$regex': f'^{re.escape(placa)}$', '$options': 'i'}}):
            return jsonify({'error': f'La placa "{placa}" ya está registrada.'}), 409

    elif coleccion == 'rutas':
        errores = validar_ruta(data)
        if errores:
            return jsonify({'error': errores[0], 'errores': errores}), 422

    result = col(coleccion).insert_one(data)
    return jsonify({'_id': str(result.inserted_id)}), 201


@app.route('/api/<coleccion>/<id>', methods=['PUT'])
def api_editar(coleccion, id):
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    if session['rol'] == 'usuario':
        return jsonify({'error': 'Sin permiso'}), 403
    if coleccion not in COLECCIONES:
        return jsonify({'error': 'Colección no válida'}), 404
    if coleccion == 'conductores':
        return jsonify({'error': 'Usa el endpoint específico para conductores'}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Cuerpo de solicitud vacío'}), 400
    data.pop('_id', None)

    # Validaciones por colección
    if coleccion == 'usuarios':
        errores = validar_usuario(data, es_edicion=True)
        if errores:
            return jsonify({'error': errores[0], 'errores': errores}), 422
        if data.get('password'):
            data['password'] = hash_pw(data['password'])

    elif coleccion == 'camiones':
        errores = validar_camion(data)
        if errores:
            return jsonify({'error': errores[0], 'errores': errores}), 422
        # Unicidad de placa al editar — excluir el propio documento
        placa = data.get('placa', '').strip()
        if placa:
            duplicado = vehiculos_col.find_one({
                'placa': {'$regex': f'^{re.escape(placa)}$', '$options': 'i'},
                '_id':   {'$ne': ObjectId(id)}
            })
            if duplicado:
                return jsonify({'error': f'La placa "{placa}" ya está registrada en otro vehículo.'}), 409

    elif coleccion == 'rutas':
        errores = validar_ruta(data)
        if errores:
            return jsonify({'error': errores[0], 'errores': errores}), 422

    col(coleccion).update_one({'_id': ObjectId(id)}, {'$set': data})
    return jsonify({'ok': True})


@app.route('/api/<coleccion>/<id>', methods=['DELETE'])
def api_eliminar(coleccion, id):
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    if session['rol'] != 'admin':
        return jsonify({'error': 'Solo el administrador puede eliminar'}), 403
    if coleccion not in COLECCIONES:
        return jsonify({'error': 'Colección no válida'}), 404
    # conductores y usuarios tienen sus propios endpoints con lógica relacional
    if coleccion in ('conductores', 'usuarios'):
        return jsonify({'error': 'Usa el endpoint específico para esta colección'}), 400
    col(coleccion).delete_one({'_id': ObjectId(id)})
    return jsonify({'ok': True})


@app.route('/api/login', methods=['POST'])
def api_login():
    # ── Rate limiting ──────────────────────────────────
    bloqueado, restante = _esta_bloqueado()
    if bloqueado:
        return jsonify({'error': f'Cuenta bloqueada temporalmente. Intenta de nuevo en {restante} segundos.'}), 429

    data     = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    rol      = data.get('rol', '').strip()

    # ── Validar CAPTCHA ────────────────────────────────
    captcha_input    = str(data.get('captcha', '')).strip()
    captcha_correcta = session.get('captcha_respuesta')
    captcha_ts       = session.get('captcha_ts', 0)

    if captcha_correcta is None:
        _registrar_fallo()
        return jsonify({'error': 'CAPTCHA no generado. Recarga la página.'}), 400

    # CAPTCHA caduca en 5 minutos
    if time.time() - captcha_ts > 300:
        session.pop('captcha_respuesta', None)
        _registrar_fallo()
        return jsonify({'error': 'El CAPTCHA ha expirado. Genera uno nuevo.', 'captcha_expirado': True}), 400

    if not captcha_input or not captcha_input.lstrip('-').isdigit():
        _registrar_fallo()
        return jsonify({'error': 'Responde el CAPTCHA con un número entero.'}), 400

    if int(captcha_input) != captcha_correcta:
        session.pop('captcha_respuesta', None)
        _registrar_fallo()
        return jsonify({'error': 'Respuesta del CAPTCHA incorrecta.', 'captcha_incorrecto': True}), 400

    # CAPTCHA correcto — invalidarlo de inmediato (uso único)
    session.pop('captcha_respuesta', None)

    # ── Autenticación ──────────────────────────────────
    user = usuarios_col.find_one({
        'username': username,
        'password': hash_pw(password),
        'rol':      rol
    })
    if not user:
        _registrar_fallo()
        return jsonify({'error': 'Credenciales incorrectas o rol no coincide'}), 401

    # Login exitoso — limpiar contador de intentos
    _limpiar_intentos()
    session['user_id']  = str(user['_id'])
    session['nombre']   = user['nombre']
    session['username'] = user['username']
    session['rol']      = user['rol']
    return jsonify({
        'nombre':   user['nombre'],
        'username': user['username'],
        'rol':      user['rol'],
    })


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/me')
def api_me():
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    return jsonify({
        'nombre':   session['nombre'],
        'username': session['username'],
        'rol':      session['rol'],
    })


# ══════════════════════════════════════════════════════
#  API ESPECIALIZADA: CONDUCTORES (con JOIN a usuarios)
# ══════════════════════════════════════════════════════

@app.route('/api/conductores', methods=['GET'])
def api_conductores_listar():
    """Devuelve conductores con el nombre resuelto desde la colección usuarios."""
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401

    conductores = list(conductores_col.find())
    resultado = []
    for c in conductores:
        c['_id'] = str(c['_id'])
        if isinstance(c.get('usuario_id'), ObjectId):
            c['usuario_id'] = str(c['usuario_id'])

        # Resolver nombre desde usuarios si existe FK
        nombre = '–'
        username = ''
        if c.get('usuario_id'):
            try:
                u = usuarios_col.find_one(
                    {'_id': ObjectId(c['usuario_id'])},
                    {'nombre': 1, 'username': 1}
                )
                if u:
                    nombre   = u.get('nombre', '–')
                    username = u.get('username', '')
            except Exception:
                pass
        c['nombre']   = nombre
        c['username'] = username
        resultado.append(c)
    return jsonify(resultado)


@app.route('/api/conductores', methods=['POST'])
def api_conductores_crear():
    """Crea un perfil de conductor vinculado a un usuario existente."""
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    if session['rol'] == 'usuario':
        return jsonify({'error': 'Sin permiso'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Cuerpo de solicitud vacío'}), 400
    data.pop('_id', None)

    usuario_id_str = data.get('usuario_id', '').strip()
    if not usuario_id_str:
        return jsonify({'error': 'Debes seleccionar un usuario conductor'}), 400

    # Validar campos operativos
    errores = validar_conductor(data)
    if errores:
        return jsonify({'error': errores[0], 'errores': errores}), 422

    try:
        uid = ObjectId(usuario_id_str)
    except Exception:
        return jsonify({'error': 'usuario_id inválido'}), 400

    # Verificar que el usuario exista y tenga rol conductor
    u = usuarios_col.find_one({'_id': uid, 'rol': 'conductor'})
    if not u:
        return jsonify({'error': 'El usuario no existe o no tiene rol conductor'}), 404

    # Evitar duplicado de FK
    if conductores_col.find_one({'usuario_id': uid}):
        return jsonify({'error': 'Este usuario ya tiene un perfil de conductor'}), 409

    data['usuario_id'] = uid
    result = conductores_col.insert_one(data)
    return jsonify({'_id': str(result.inserted_id)}), 201


@app.route('/api/conductores/<id>', methods=['PUT'])
def api_conductores_editar(id):
    """Actualiza datos operativos del conductor (no cambia el vínculo de usuario)."""
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    if session['rol'] == 'usuario':
        return jsonify({'error': 'Sin permiso'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Cuerpo de solicitud vacío'}), 400
    data.pop('_id', None)
    data.pop('nombre', None)    # el nombre vive en usuarios, no aquí
    data.pop('username', None)

    # Validar campos operativos
    errores = validar_conductor(data)
    if errores:
        return jsonify({'error': errores[0], 'errores': errores}), 422

    # Si se envía usuario_id, convertir a ObjectId y verificar unicidad
    if 'usuario_id' in data:
        try:
            new_uid = ObjectId(data['usuario_id'])
            existing = conductores_col.find_one(
                {'usuario_id': new_uid, '_id': {'$ne': ObjectId(id)}}
            )
            if existing:
                return jsonify({'error': 'Ese usuario ya tiene otro perfil de conductor'}), 409
            data['usuario_id'] = new_uid
        except Exception:
            return jsonify({'error': 'usuario_id inválido'}), 400

    conductores_col.update_one({'_id': ObjectId(id)}, {'$set': data})
    return jsonify({'ok': True})


@app.route('/api/conductores/<id>', methods=['DELETE'])
def api_conductores_eliminar(id):
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    if session['rol'] != 'admin':
        return jsonify({'error': 'Solo el administrador puede eliminar'}), 403
    conductores_col.delete_one({'_id': ObjectId(id)})
    return jsonify({'ok': True})


@app.route('/api/usuarios_conductores_disponibles', methods=['GET'])
def api_usuarios_conductores_disponibles():
    """Usuarios con rol=conductor que aún no tienen perfil de conductor asignado.
       Usado para poblar el selector al crear un nuevo conductor."""
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401

    # IDs ya vinculados
    vinculados = {
        c['usuario_id']
        for c in conductores_col.find({'usuario_id': {'$exists': True}}, {'usuario_id': 1})
        if c.get('usuario_id')
    }

    disponibles = []
    for u in usuarios_col.find({'rol': 'conductor'}):
        if u['_id'] not in vinculados:
            disponibles.append({
                '_id':      str(u['_id']),
                'nombre':   u.get('nombre', ''),
                'username': u.get('username', ''),
            })
    return jsonify(disponibles)


@app.route('/api/usuarios/<id>', methods=['DELETE'])
def api_usuarios_eliminar(id):
    """Elimina un usuario y, si era conductor, elimina también su perfil de conductor."""
    if 'rol' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    if session['rol'] != 'admin':
        return jsonify({'error': 'Solo el administrador puede eliminar'}), 403
    try:
        uid = ObjectId(id)
    except Exception:
        return jsonify({'error': 'ID inválido'}), 400

    # Cascade: eliminar perfil de conductor si existía
    conductores_col.delete_many({'usuario_id': uid})
    usuarios_col.delete_one({'_id': uid})
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════
#  API CONDUCTOR: VIAJES
# ══════════════════════════════════════════════════════

@app.route('/api/conductor/viajes', methods=['GET'])
@requiere_rol('conductor', 'admin')
def api_conductor_mis_viajes():
    """Lista los viajes del conductor autenticado."""
    filtro = {} if session['rol'] == 'admin' else {'conductor_username': session['username']}
    viajes = [serialize(v) for v in viajes_col.find(filtro).sort('inicio', -1)]
    return jsonify(viajes)


@app.route('/api/conductor/viajes/iniciar', methods=['POST'])
@requiere_rol('conductor')
def api_conductor_iniciar_viaje():
    """Inicia un nuevo viaje para el conductor autenticado."""
    data = request.get_json() or {}
    ruta_id = data.get('ruta_id', '').strip()
    camion_id = data.get('camion_id', '').strip()

    if not ruta_id:
        return jsonify({'error': 'Debes seleccionar una ruta'}), 400
    if not camion_id:
        return jsonify({'error': 'Debes seleccionar un camión'}), 400

    try:
        ruta = rutas_col.find_one({'_id': ObjectId(ruta_id)})
        camion = vehiculos_col.find_one({'_id': ObjectId(camion_id)})
    except Exception:
        return jsonify({'error': 'ID de ruta o camión inválido'}), 400

    if not ruta:
        return jsonify({'error': 'Ruta no encontrada'}), 404
    if ruta.get('estado') != 'Activa':
        return jsonify({'error': 'Solo se pueden iniciar viajes en rutas activas'}), 422
    if not camion:
        return jsonify({'error': 'Camión no encontrado'}), 404
    if camion.get('estado') != 'Operativo':
        return jsonify({'error': 'El camión no está operativo'}), 422

    # Verificar que el conductor no tenga ya un viaje en curso
    en_curso = viajes_col.find_one({
        'conductor_username': session['username'],
        'estado': 'En curso'
    })
    if en_curso:
        return jsonify({'error': 'Ya tienes un viaje en curso. Finalízalo antes de iniciar otro.'}), 409

    viaje = {
        'conductor_username': session['username'],
        'conductor_nombre':   session['nombre'],
        'ruta_id':   ruta_id,
        'ruta_nombre': ruta.get('nombre', ''),
        'camion_id': camion_id,
        'camion_placa': camion.get('placa', ''),
        'estado':  'En curso',
        'inicio':  datetime.utcnow().isoformat(),
        'fin':     None,
        'notas':   data.get('notas', ''),
    }
    result = viajes_col.insert_one(viaje)
    return jsonify({'_id': str(result.inserted_id), 'mensaje': 'Viaje iniciado'}), 201


@app.route('/api/conductor/viajes/<viaje_id>/finalizar', methods=['POST'])
@requiere_rol('conductor')
def api_conductor_finalizar_viaje(viaje_id):
    """Finaliza un viaje en curso del conductor autenticado."""
    try:
        viaje = viajes_col.find_one({
            '_id': ObjectId(viaje_id),
            'conductor_username': session['username'],
            'estado': 'En curso'
        })
    except Exception:
        return jsonify({'error': 'ID de viaje inválido'}), 400

    if not viaje:
        return jsonify({'error': 'Viaje no encontrado o ya finalizado'}), 404

    data = request.get_json() or {}
    viajes_col.update_one(
        {'_id': ObjectId(viaje_id)},
        {'$set': {
            'estado': 'Finalizado',
            'fin':    datetime.utcnow().isoformat(),
            'notas_fin': data.get('notas', ''),
        }}
    )
    return jsonify({'ok': True, 'mensaje': 'Viaje finalizado'})


# ══════════════════════════════════════════════════════
#  API CONDUCTOR: INCIDENCIAS
# ══════════════════════════════════════════════════════

@app.route('/api/conductor/incidencias', methods=['GET'])
@requiere_rol('conductor', 'admin')
def api_conductor_incidencias():
    """Lista incidencias. Conductor ve las suyas; admin ve todas."""
    filtro = {} if session['rol'] == 'admin' else {'conductor_username': session['username']}
    incs = [serialize(i) for i in incidencias_col.find(filtro).sort('fecha', -1)]
    return jsonify(incs)


@app.route('/api/conductor/incidencias', methods=['POST'])
@requiere_rol('conductor')
def api_conductor_reportar_incidencia():
    """Registra una incidencia reportada por el conductor."""
    data = request.get_json() or {}
    tipo        = data.get('tipo', '').strip()
    descripcion = data.get('descripcion', '').strip()
    ruta_id     = data.get('ruta_id', '').strip()

    TIPOS_VALIDOS = ('Mecánica', 'Accidente', 'Obstrucción vial', 'Clima', 'Otro')
    if not tipo or tipo not in TIPOS_VALIDOS:
        return jsonify({'error': f'Tipo de incidencia inválido. Opciones: {", ".join(TIPOS_VALIDOS)}'}), 422
    if not descripcion or len(descripcion) < 10:
        return jsonify({'error': 'La descripción debe tener al menos 10 caracteres'}), 422

    incidencia = {
        'conductor_username': session['username'],
        'conductor_nombre':   session['nombre'],
        'tipo':        tipo,
        'descripcion': descripcion,
        'ruta_id':     ruta_id,
        'fecha':       datetime.utcnow().isoformat(),
        'estado':      'Abierta',
    }
    result = incidencias_col.insert_one(incidencia)
    return jsonify({'_id': str(result.inserted_id), 'mensaje': 'Incidencia reportada'}), 201


# ══════════════════════════════════════════════════════
#  API USUARIO: RUTAS PÚBLICAS (solo activas)
# ══════════════════════════════════════════════════════

@app.route('/api/publico/rutas', methods=['GET'])
@requiere_login
def api_rutas_publicas():
    """Devuelve solo rutas activas. Accesible para todos los roles."""
    rutas = [serialize(r) for r in rutas_col.find({'estado': 'Activa'})]
    return jsonify(rutas)


# ══════════════════════════════════════════════════════
#  ARRANQUE
# ══════════════════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    app.run(debug=True)