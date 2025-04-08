from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, TextAreaField, SelectField, DateField, FileField, BooleanField
from wtforms.validators import DataRequired, Length, Optional
from werkzeug.utils import secure_filename

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class MovieForm(FlaskForm):
    titulo = StringField('Título', validators=[DataRequired(), Length(max=255)])
    genero = StringField('Género', validators=[DataRequired(), Length(max=100)])
    sinopsis = TextAreaField('Sinopsis', validators=[DataRequired()])
    imagen = FileField('Imagen', validators=[Optional()])
    estado = SelectField('Estado', choices=[('Próximamente', 'Próximamente'), ('En Cartelera', 'En Cartelera'), ('Fuera de Cartelera', 'Fuera de Cartelera')], validators=[DataRequired()])
    fecha = DateField('Fecha de Estreno', validators=[DataRequired()], format='%Y-%m-%d')
    trailer_url = StringField('URL del Trailer', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Guardar') # Asegúrate de tener un campo submit si estás usando Flask-WTF
 