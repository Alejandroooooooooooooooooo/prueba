from odoo import http
from odoo.http import request, Response
import json
import uuid
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from odoo.fields import Date
from passlib.hash import bcrypt
from passlib.context import CryptContext
import logging
import re

_logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UsersAPI(http.Controller):


    @staticmethod
    def validate_password(password):

        if len(password) < 8:
            return False, "La contraseña debe tener al menos 8 caracteres."
        
        if not re.search(r'[A-Z]', password):
            return False, "La contraseña debe contener al menos una letra mayúscula."
        
        if not re.search(r'[a-z]', password):
            return False, "La contraseña debe contener al menos una letra minúscula "

        if not re.search(r'[0-9]', password):
            return False, "La contraseña debe contener al menos un número."
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "La contraseña debe contener al menos un carácter especial."
        
        return True, ""
    
    #Endpoint para login
    @http.route('/api/login', type= 'http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def login(self, **kwargs):

        if request.httprequest.method == 'OPTIONS':
            response = Response(status=204)
            return self.add_cors_headers(response)
        
        if request.httprequest.method == 'POST':
        
            try:

                data = json.loads(request.httprequest.get_data(as_text=True))  
                email = data.get('email')  
                password = data.get('password')  


                if not email or not password:
                    _logger.warning('Faltan email o contraseña en la solicitud')
                    return self.error_response("El correo y la contraseña son obligatorios.")
        
                user = request.env['users'].sudo().search([('email', '=', email)], limit = 1)

                if not user: 
                    return self.error_response("Usuario no encontrado.")
                
                _logger.info('Hash de la contraseña del usuario: %s', user.password)


                if not pwd_context.verify(password, user.password):
                    _logger.warning('Contraseña incorrecta para el usuario: %s', email)
                    return self.error_response('Contraseña incorrecta')
                
                response_data = {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'subscription': user.subscription,
                    'message': 'Login realizado'
                }
                response = Response(json.dumps(response_data), content_type='application/json', status=200)
                return self.add_cors_headers(response)

            except Exception as e:
                return self.error_response(f"Error al procesar la solicitud: {str(e)}", status=500)
    
    #Endpoint para GET de los users
    @http.route('/api/user', type='http', auth='public', methods=['GET'], csrf=False)
    def get_user_info(self, **kwargs):
        try:
            users = request.env['users'].sudo().search([])  

            user_list = [{
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'subscription': user.subscription,  
            } for user in users]

            response = Response(json.dumps(user_list), content_type='application/json', status=200)
            return self.add_cors_headers(response)

        except Exception as e:
            return self.error_response(f"Error al procesar la solicitud: {str(e)}", status=500)


    #Endpoint para formulario creación de usuario
    @http.route('/api/users', type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def create_user(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            response = Response(status=204)
            return self.add_cors_headers(response)
        
        if request.httprequest.method == 'POST':
            try:
                data = json.loads(request.httprequest.get_data(as_text=True))

                missing_fields = []
                for field in ['name', 'email', 'password', 'phone', 'subscription', 'zip_code']:
                    if not data.get(field):
                        missing_fields.append(field)

                if missing_fields:
                    return self.error_response(f"Faltan datos obligatorios: {',' .join(missing_fields)}")
                
                is_valid, error_message = UsersAPI.validate_password(data['password'])
                if not is_valid:
                    return self.error_response(f"Error en la contraseña: {error_message}")


                user = request.env['users'].sudo().create({
                    'profession': data['profession'],
                    'email': data['email'],
                    'password': data['password'],
                    'name': data['name'],
                    'enterprise_name': data.get('enterprise_name', None),
                    'phone': data['phone'],
                    'zip_code': data['zip_code'],
                    'subscription': data['subscription'],
                })

                response_data ={
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'subscription': user.subscription,
                    'message': 'Usuario creado correctamente'
                }

                response = Response(json.dumps(response_data), content_type='application/json', status=201)
                return self.add_cors_headers(response)

            except Exception as e:
                print("Error al crear el usuario:", str(e))  # Log añadido
                return self.error_response(f"Error al crear el usuario: {str(e)}")

    @http.route('/api/change_password', type='http', auth='public', methods=['PATCH', 'OPTIONS'], csrf=False)
    def change_password(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self.add_cors_headers(Response(status=204))

        if request.httprequest.method == 'PATCH':
            try:
                data = json.loads(request.httprequest.get_data(as_text=True))
                email = data.get('email')
                new_password = data.get('new_password')

                if not email or not new_password:
                    response = Response(json.dumps({'error': 'Faltan datos obligatorios (email y nueva contraseña)'}),
                                    content_type='application/json', status=400)
                    return self.add_cors_headers(response)

                is_valid, error_message = UsersAPI.validate_password(new_password)
                if not is_valid:
                    return self.error_response(f"Error en la contraseña: {error_message}")


                user = request.env['users'].sudo().search([('email', '=', email)], limit=1)

                if not user:
                    response = Response(json.dumps({'error': 'Usuario no encontrado'}),
                                    content_type='application/json', status=404)
                    return self.add_cors_headers(response)

                user.write({'password': new_password})

                _logger.info(f"Contraseña actualizada para el usuario {email}: {user.password}")

                response = Response(json.dumps({'message': 'Contraseña actualizada correctamente'}),
                                content_type='application/json', status=200)
                return self.add_cors_headers(response)

            except Exception as e:
                response = Response(json.dumps({'error': str(e)}),
                                content_type='application/json', status=500)
            return self.add_cors_headers(response)
          
    def send_reset_email(self, to_email, reset_link):
        from_email = 'noreply@miarquitecto.info'
        from_password = 'Arquitect0-noreply'
        smtp_server = 'smtp.servidor-correo.net'
        smtp_port = 587

        subject = "Recuperación de contraseña"
        body = f"""
        Hola,

        Hemos recibido uan solicitud para restablecer tu contraseña.
        Haga clic en el siguiente enlace para cambiar tu contraseña:

        {reset_link}

        Este enlace expirará en 1 hora.

        Si usted no realizó esta solciitud, ignore este correo.

        Saludos,
        NOMBRE_EQUIPO
        """

        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try: 
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
            server.quit()
            return True
        except Exception as e:
            _logger.error(f"Error enviando correo: {str(e)}")
            return False
        
    
    @http.route('/api/request_password_reset', type='http', auth='public', methods=['POST', 'OPTIONS'], csrf=False)
    def request_password_reset(self, **kwargs):
        if request.httprequest.method == 'OPTIONS':
            return self.add_cors_headers(Response(status=204))
        
        if request.httprequest.method == 'POST':
            try:
                data = json.loads(request.httprequest.get_data(as_text=True))
                email = data.get('email')

                if not email:
                    return self.error_response("El correo es obligatorio.")

                user = request.env['users'].sudo().search([('email', '=', email)], limit=1)

                if not user:
                    return self.error_response("No hay ningún usuario con ese correo.")

                token = uuid.uuid4().hex  # Un token único
                expiration = datetime.utcnow() + timedelta(hours=1)

                user.write({
                    'reset_token': token,
                    'reset_token_expiration': expiration,
                })

                reset_link = f"https://frontend.com/reset-password?token={token}"

                self.send_reset_email(email,reset_link)

                return self.add_cors_headers(Response(
                    json.dumps({'message': 'Si el correo existe, se ha enviado un enlace de recuperación.'}),
                    content_type='application/json',
                    status=200
                ))

            except Exception as e:
                return self.error_response(str(e), status=500)



    def error_response(self, message, status=400):
        response = Response(json.dumps({'error': message}), content_type='application/json', status=status)
        return self.add_cors_headers(response)
    
    # Función para agregar CORS a las respuestas
    def add_cors_headers(self, response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response