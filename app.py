import os
import logging
import sys
import io
from smtplib import SMTP_SSL
from unittest import result

from dotenv import load_dotenv
from flask import Flask, current_app, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from email.mime.text import MIMEText
import smtplib

from bson.objectid import ObjectId  # Import ObjectId si tu _id en MongoDB es un ObjectId

# Asegurar codificación UTF-8 para stdout y stderr
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Importaciones de módulos locales
from forms import MovieForm
from utils.log_handler import log_error
from error_handler import recibir_correos_error  # Importar la función

# Definir las credenciales del correo
EMAIL_USER = os.getenv('EMAIL_USER', '23300031@uttt.edu.mx')  # Usar .env o un valor por defecto
EMAIL_PASS = os.getenv('EMAIL_PASS', 'Dormilon00')  # Usar .env o un valor por defecto
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', '23300031@uttt.edu.mx')  # Usar .env o un valor por defecto

# Rutas del proyecto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'app', 'templates')
UPLOAD_FOLDER = 'static/uploads'

# Configuración de la aplicación Flask
def crear_app():
    app = Flask(__name__, template_folder=TEMPLATE_DIR)
    app.secret_key = os.getenv('FLASK_SECRET_KEY', 'tu_clave_secreta')  # ¡Cambia esto por una clave segura!
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, UPLOAD_FOLDER)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', True)
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', EMAIL_USER)
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', EMAIL_PASS)
    app.config['MAIL_ASCII_ATTACHMENTS'] = False

    # Inicializar Flask-Mail
    mail = Mail(app)

    # Configuración de logging
    logging.basicConfig(filename='errores.log', level=logging.ERROR)
    app.logger.setLevel(logging.ERROR)

    # Configuración de Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # Funciones auxiliares
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    # Cargar las variables de entorno desde el archivo .env
    load_dotenv()

    # Obtener la URI de conexión y el nombre de la base de datos desde las variables de entorno
    MONGO_URI = os.getenv('MONGO_URI')
    MONGO_DATABASE = os.getenv('MONGO_DATABASE')

    # Inicializar el cliente de MongoDB y la base de datos
    client = MongoClient(MONGO_URI)
    db = client[MONGO_DATABASE]

    # Ejemplo de cómo podrías tener una función para obtener la base de datos (opcional):
    def get_mongo_db():
        client = MongoClient(MONGO_URI)
        return client[MONGO_DATABASE]

    def format_datetime(value, format='%Y'):
        if value is None:
            return ''
        return value.strftime(format)

    app.jinja_env.filters['strftime'] = format_datetime

    # Función para enviar correos electrónicos (usando smtplib directamente)
    def send_email(subject, body, sender, recipients, password):
        msg = MIMEText(body, 'plain', 'utf-8')  # Especificamos UTF-8 para el cuerpo
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)

        # Forzar la codificación a UTF-8
        msg.set_charset('utf-8')

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
                smtp_server.login(sender, password)
                smtp_server.sendmail(sender, recipients, msg.as_string())
            return "¡Mensaje enviado!"
        except Exception as e:
            return f"Error al enviar el correo: {e}"

    def send_error_email(error_message):
        subject = "Error en la Aplicación Cartelera"
        body = f"Se ha producido el siguiente error en la aplicación:\n\n{error_message}"
        current_app.logger.info("Correo de error enviado al administrador.")
        logging.info("Correo de error enviado exitosamente.")
        sender = EMAIL_USER
        recipients = [ADMIN_EMAIL]  # Asegúrate de usar ADMIN_EMAIL para el administrador
        password = EMAIL_PASS
        result = send_email(subject, body, sender, recipients, password)
        return result

    def manejar_error_y_notificar(error_message, exception=None):
        logging.error(error_message, exc_info=True)
        app.logger.error(error_message, exc_info=True)
        log_error(error_message)  # Usar log_error de log_handler
        send_error_email(error_message)

    @app.route('/test_log_error')
    def test_log_error():
        test_message = "Este es un mensaje de error de prueba con caracteres como óéíúáñ."
        log_error(test_message)
        return f"Resultado del envío de correo de error: {test_message}"

    @app.route('/test_send_error_email')
    def test_send_error_email():
        test_message = "Este es un mensaje de error de prueba con caracteres como óéíúáñ."
        result = send_error_email(test_message)
        return f"Resultado del envío de correo de error: {result}"

    # Clases
    class User(UserMixin):
        def __init__(self, id, username, password, role):
            self.id = id
            self.username = username
            self.password = password
            self.role = role

    @login_manager.user_loader
    def load_user(user_id):
            usuarios_collection = db['usuarios']
            try:
                user_data = usuarios_collection.find_one({'_id': ObjectId(user_id)})  # Try ObjectId first
            except:
                try:
                    user_data = usuarios_collection.find_one({'_id': int(user_id)}) # Fallback to int
                except:
                    user_data = usuarios_collection.find_one({'_id': user_id}) # Fallback to string
            if user_data:
                return User(
                    id=str(user_data['_id']),  # Convert ObjectId to string
                    username=user_data.get('username'),
                    password=user_data.get('password'),
                    role=user_data.get('role')
                )
            return None
    # Rutas
    @app.route('/')
    def index():
        try:
            peliculas_collection = db['peliculas']
            fecha_param = request.args.get('fecha')
            busqueda_param = request.args.get('busqueda')
            genero_busqueda_param = request.args.get('genero')
            peliculas = []

            if fecha_param:
                peliculas = list(peliculas_collection.find({'fecha': fecha_param}))
            elif busqueda_param:
                peliculas = list(peliculas_collection.find(
                    {'titulo': {'$regex': busqueda_param, '$options': 'i'}}))
            elif genero_busqueda_param:
                peliculas = list(peliculas_collection.find(
                    {'genero': {'$regex': genero_busqueda_param, '$options': 'i'}}))
            else:
                peliculas = list(peliculas_collection.find({}))

            # Limpiar el _id de los documentos para que sean serializables a JSON si es necesario
            peliculas_sin_id = [{**pelicula, '_id': str(pelicula['_id'])} for pelicula in peliculas]

            return render_template('index.html', peliculas=peliculas_sin_id, now=datetime.now())

        except Exception as e:
            error_message = f"Error al interactuar con la base de datos en '/': {repr(e)}"
            log_error(error_message)
            return "Error interno del servidor", 500

    @app.route('/registro', methods=['GET', 'POST'], endpoint='registro')
    def registro():
        try:
            usuarios_collection = db['usuarios']
            if request.method == 'POST':
                username = request.form['nombre']
                password = generate_password_hash(request.form['contraseña'])  # ¡Hashear la contraseña!
                email = request.form['email']
                role = 'user'

                try:
                    # Insertar el nuevo usuario en MongoDB
                    result = usuarios_collection.insert_one({
                        'username': username,
                        'password': password,
                        'email': email,
                        'role': role
                    })

                    if result.inserted_id:
                        flash('Registro exitoso. Por favor, inicia sesión.')
                        return redirect(url_for('login'))
                    else:
                        flash('Error al registrar el usuario.', 'danger')
                        return render_template('registro.html', now=datetime.now())

                except Exception as db_e:
                    log_error(f"Error al insertar usuario en /registro: {db_e}")
                    flash('Error al registrar el usuario.', 'danger')
                    return render_template('registro.html', now=datetime.now())

            return render_template('registro.html', now=datetime.now())

        except Exception as e:
            log_error(f"Error inesperado en la ruta '/registro': {repr(e)}")
            flash('Error interno del servidor durante el registro.', 'danger')
            return "Error interno del servidor", 500

    @app.route('/login', methods=['GET', 'POST'], endpoint='login')
    def login():
        try:
            usuarios_collection = db['usuarios']
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']

                try:
                    user_data = usuarios_collection.find_one({'username': username})

                    if user_data and check_password_hash(user_data.get('password'), password):  # Usar check_password_hash
                        user_obj = User(
                            id=str(user_data['_id']),  # Convertir ObjectId a string
                            username=user_data.get('username'),
                            password=user_data.get('password'),
                            role=user_data.get('role')
                        )
                        login_user(user_obj)
                        return redirect(url_for('admin' if user_data.get('role') == 'admin' else 'index'))
                    else:
                        flash('Usuario o contraseña incorrectos')

                except Exception as db_e:
                    log_error(f"Error al consultar usuario en /login: {db_e}")
                    flash('Error al iniciar sesión. Inténtalo de nuevo.', 'danger')
                    return render_template('login.html', now=datetime.now())

            return render_template('login.html', now=datetime.now())

        except Exception as e:
            log_error(f"Error inesperado en la ruta '/login': {repr(e)}")
            flash('Error interno del servidor durante el inicio de sesión.', 'danger')
            return "Error interno del servidor", 500

    @app.route('/logout', endpoint='logout')
    def logout():
        try:
            logout_user()
            return redirect(url_for('index'))
        except Exception as e:
            log_error(f"Error inesperado en la ruta '/logout': {repr(e)}")
            flash('Error al cerrar sesión.', 'danger')
            return "Error interno del servidor", 500

    @app.route('/admin', endpoint='admin')
    @login_required
    def admin():
        if current_user.role != 'admin':
            flash('No tienes permisos para acceder a esta página.', 'danger')
            return redirect(url_for('index'))

        try:
            peliculas_collection = db['peliculas']
            peliculas = list(peliculas_collection.find({}))  # Obtener todas las películas

            # Limpiar el _id para serialización (opcional, depende de tu plantilla)
            peliculas_sin_id = [{**pelicula, '_id': str(pelicula['_id'])} for pelicula in peliculas]

            return render_template('admin.html', peliculas=peliculas_sin_id, now=datetime.now())

        except Exception as e:
            error_message = f"Error al interactuar con la base de datos en /admin: {repr(e)}"
            log_error(error_message)
            return "Error interno del servidor", 500

    @app.route('/admin/add_movie', methods=['GET', 'POST'], endpoint='add_movie')
    @login_required
    def add_movie():
        if current_user.role != 'admin':
            return redirect(url_for('index'))
        form = MovieForm()
        try:
            peliculas_collection = db['peliculas']
            if form.validate_on_submit():
                titulo = form.titulo.data
                genero = form.genero.data
                sinopsis = form.sinopsis.data
                imagen_file = form.imagen.data
                estado = form.estado.data
                fecha = form.fecha.data
                trailer_url = form.trailer_url.data
                imagen_ruta_db = None

                if imagen_file and allowed_file(imagen_file.filename):
                    filename = secure_filename(imagen_file.filename)
                    local_filepath = os.path.join(
                        app.config['UPLOAD_FOLDER'], filename)
                    try:
                        imagen_file.save(local_filepath)
                        imagen_ruta_db = os.path.join('/uploads', filename).replace('\\', '/')

                        # Insertar la película en MongoDB
                        fecha = datetime.combine(form.fecha.data, datetime.min.time())
                        result = peliculas_collection.insert_one({
                            'titulo': titulo,
                            'genero': genero,
                            'sinopsis': sinopsis,
                            'imagen': imagen_ruta_db,
                            'estado': estado,
                            'fecha': fecha,
                            'trailer_url': trailer_url
                        })

                        if result.inserted_id:
                            flash('Película añadida con éxito.', 'success')
                            return redirect(url_for('admin'))
                        else:
                            flash('Error al añadir película (base de datos).', 'danger')
                            return redirect(url_for('add_movie'))

                    except Exception as local_file_err:
                        log_error(f"Error al guardar archivo local en /admin/add_movie: {repr(local_file_err)}")
                        flash('Error al guardar archivo local.', 'danger')
                        return redirect(url_for('add_movie'))

                else:
                    flash('Por favor, selecciona un archivo de imagen válido.', 'warning')

            return render_template('add_movie.html', form=form, now=datetime.now())

        except Exception as e:
            log_error(f"Error inesperado en la ruta '/admin/add_movie': {repr(e)}")
            flash('Error interno del servidor al añadir película.', 'danger')
            return "Error interno del servidor", 500

    @app.route('/admin/edit_movie/<string:id>', methods=['GET', 'POST'], endpoint='edit_movie')
    def edit_movie(id):
        # El resto de tu código de la función edit_movie permanece igual
        if current_user.role != 'admin':
            return redirect(url_for('index'))

        peliculas_collection = db['peliculas']

        try:
            # Buscar la película por su _id, convirtiendo el id de la URL a ObjectId
            pelicula_data = peliculas_collection.find_one({'_id': ObjectId(id)})
            if pelicula_data is None:
                flash('Película no encontrada.', 'danger')
                return redirect(url_for('admin'))

            # Inicializar el formulario con los datos de la película
            form = MovieForm(data=pelicula_data)

            if form.validate_on_submit():
                titulo = form.titulo.data
                genero = form.genero.data
                sinopsis = form.sinopsis.data
                imagen_file = form.imagen.data
                estado = form.estado.data
                fecha = form.fecha.data
                trailer_url = form.trailer_url.data
                imagen_ruta_db = pelicula_data.get('imagen')  # Mantener la imagen existente por defecto

                if imagen_file and allowed_file(imagen_file.filename):
                    filename = secure_filename(imagen_file.filename)
                    local_filepath = os.path.join(
                        app.config['UPLOAD_FOLDER'], filename)
                    try:
                        imagen_file.save(local_filepath)
                        imagen_ruta_db = os.path.join('/uploads', filename).replace('\\', '/')
                    except Exception as local_file_err:
                        log_error(f"Error al guardar archivo local en /admin/edit_movie: {repr(local_file_err)}")
                        flash('Error al guardar archivo local.', 'danger')
                        return redirect(url_for('edit_movie', id=id))

                # Actualizar la película en MongoDB
                fecha = datetime.combine(form.fecha.data, datetime.min.time())
                update_result = peliculas_collection.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': {
                        'titulo': titulo,
                        'genero': genero,
                        'sinopsis': sinopsis,
                        'imagen': imagen_ruta_db,
                        'estado': estado,
                        'fecha': fecha,  # Aquí está el problema
                        'trailer_url': trailer_url
                    }}
                )
                if update_result.modified_count > 0:
                    flash('Película actualizada con éxito.', 'success')
                    return redirect(url_for('admin'))
                else:
                    flash('No se realizaron cambios en la película.', 'info')
                    return redirect(url_for('edit_movie', id=id))

            return render_template('edit_movie.html', form=form, pelicula_id=id, pelicula=pelicula_data, now=datetime.now())

        except Exception as e:
            log_error(f"Error inesperado en la ruta '/admin/edit_movie/{id}': {repr(e)}")
            flash('Error interno del servidor al editar la película.', 'danger')
            return "Error interno del servidor", 500    
        
    @app.route('/admin/delete_movie/<string:id>', endpoint='delete_movie')
    def delete_movie(id):
        if current_user.role != 'admin':
            return redirect(url_for('index'))

        peliculas_collection = db['peliculas']

        try:
            # Eliminar la película por su _id, convirtiendo el id de la URL a ObjectId
            delete_result = peliculas_collection.delete_one({'_id': ObjectId(id)})

            if delete_result.deleted_count > 0:
                flash('Película eliminada con éxito.', 'success')
            else:
                flash('Película no encontrada.', 'info')

        except Exception as e:
            log_error(f"Error inesperado en la ruta '/admin/delete_movie/{id}': {repr(e)}")
            flash('Error al eliminar la película.', 'danger')

        return redirect(url_for('admin'))

    @app.route('/cartelera', endpoint='cartelera')
    def cartelera():
        try:
            peliculas_collection = db['peliculas']
            peliculas = list(peliculas_collection.find({}))

            # Limpiar el _id para serialización (opcional, depende de tu plantilla)
            peliculas_sin_id = [{**pelicula, '_id': str(pelicula['_id'])} for pelicula in peliculas]

            return render_template('cartelera.html', peliculas=peliculas_sin_id, now=datetime.now())

        except Exception as e:
            log_error(f"Error inesperado en la ruta '/cartelera': {repr(e)}")
            return "Error interno del servidor", 500

    @app.route('/pelicula/<string:id>', endpoint='pelicula_detalles')
    def pelicula_detalles(id):
        peliculas_collection = db['peliculas']
        try:
            # Ahora 'id' es una cadena, conviértela a ObjectId
            pelicula = peliculas_collection.find_one({'_id': ObjectId(id)})

            if pelicula:
                print(f"Estructura de pelicula: {pelicula}")
                # Limpiar el _id para la plantilla (opcional)
                pelicula_sin_id = {**pelicula, '_id': str(pelicula['_id'])}
                return render_template('pelicula_detalles.html', pelicula=pelicula_sin_id, now=datetime.now())
            else:
                return "Película no encontrada", 404

        except Exception as e:
            log_error(f"Error inesperado al obtener detalles de la película con ID {id}: {repr(e)}")
            return "Error interno del servidor", 500

    @app.route('/compra_boletos', endpoint='compra_boletos')
    def compra_boletos():
        try:
            return "Página de Compra de Boletos"
        except Exception as e:
            log_error(f"Error inesperado en la ruta '/compra_boletos': {repr(e)}")
            return "Error interno del servidor", 500


    @app.route('/contacto', endpoint='contacto')
    @login_required
    def contacto():
        try:
            return render_template('contacto.html', now=datetime.now())
        except Exception as e:
            log_error(f"Error inesperado en la ruta '/contacto': {repr(e)}")
            return "Error interno del servidor", 500

    @app.route('/procesar_errores', endpoint='procesar_errores')
    def procesar_errores():
        recibir_correos_error()
        return 'Errores procesados'


    # Ruta de prueba para el envío de correos
    @app.route('/test_email')
    def test_email():
        try:
            msg = Message(
                subject="Correo de prueba",
                sender=app.config['MAIL_USERNAME'],
                recipients=[ADMIN_EMAIL],
                body="Este es un correo electrónico de prueba.",
                charset='utf-8'  # Asegurar codificación UTF-8 también en pruebas
            )
            mail.send(msg)
            return "Correo de prueba enviado"
        except Exception as e:
            manejar_error_y_notificar(f"Error al enviar correo de prueba: {repr(e)}", e)
            return "Error al enviar correo de prueba"


    @app.route('/probar_envio_error')
    def probar_envio_error():
        try:
            raise Exception("Simulando un error de prueba para envío de correo")
        except Exception as e:
            send_error_email(f"Error simulado: {e}")
            return "Correo de error enviado (si todo salió bien)"

    return app

app = crear_app()

# Ejecutar la aplicación
if __name__ == '__main__':
    print("Iniciando aplicación Flask...")
    app.run(debug=True, use_reloader=False)