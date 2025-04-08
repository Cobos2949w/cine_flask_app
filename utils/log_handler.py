# log_handler.py
import logging
import smtplib
from email.mime.text import MIMEText

EMAIL_USER = '23300031@uttt.edu.mx'  # Reemplaza con tu dirección de Gmail
EMAIL_PASS = 'Dormilon00'  # Reemplaza con tu contraseña de aplicación
EMAIL_TO = '23300031@uttt.edu.mx'  # Reemplaza con la dirección del administrador

def log_error(error):
    logging.error(str(error))
    send_error_email(str(error))

def send_error_email(error_message):
    msg = MIMEText(error_message, 'plain', 'utf-8')
    msg['Subject'] = 'Error en la aplicación de cine'
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        logging.info("Correo de error enviado.")
    except Exception as e:
        logging.error(f"Error al enviar correo electrónico: {e}")