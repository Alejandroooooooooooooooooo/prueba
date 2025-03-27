from odoo import http
from odoo.http import request, Response
import json
from odoo.fields import Date
from passlib.hash import bcrypt
from passlib.context import CryptContext
import logging

_logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UsersAPI(http.Controller):


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
                

                hashed_password = pwd_context.hash(data['password'])

                user = request.env['users'].sudo().create({
                    'profession': data['profession'],
                    'email': data['email'],
                    'password': hashed_password,
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
          

    def error_response(self, message, status=400):
        response = Response(json.dumps({'error': message}), content_type='application/json', status=status)
        return self.add_cors_headers(response)
    
    # Función para agregar CORS a las respuestas
    def add_cors_headers(self, response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response