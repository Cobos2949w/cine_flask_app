# error_handler.py
import imaplib
import email
from flask import current_app

# Definir las credenciales del correo (Asegúrate de que sean accesibles aquí)
EMAIL_USER = '23300031@uttt.edu.mx'
EMAIL_PASS = 'Dormilon00'  # Tu contraseña de aplicación

def recibir_correos_error():
    IMAP_SERVER = 'imap.gmail.com'
    IMAP_USERNAME = EMAIL_USER
    IMAP_PASSWORD = EMAIL_PASS
    try:
        mail_imap = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail_imap.login(IMAP_USERNAME, IMAP_PASSWORD)
        mail_imap.select('inbox')

        _, data = mail_imap.search(None, 'ALL')
        mail_ids = data[0]
        id_list = mail_ids.split()

        for num in id_list:
            _, data = mail_imap.fetch(num, '(RFC822)')
            for response_part in data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    email_subject = msg['subject']
                    email_from = msg['from']

                    if 'Error' in email_subject:
                        for part in msg.walk():
                            if part.get_content_type() == 'text/plain':
                                body = part.get_payload(decode=True).decode('utf-8', 'ignore') # Decodificar a UTF-8 ignorando errores
                                current_app.logger.info(f'Correo de error de {email_from}: {body}')
                                # Aquí puedes procesar el error, guardarlo en una base de datos, etc.

        mail_imap.close()
        mail_imap.logout()

    except Exception as e:
        current_app.logger.error(f'Error al recibir correos: {e}', exc_info=True)