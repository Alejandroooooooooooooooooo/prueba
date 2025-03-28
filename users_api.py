from odoo import http
from odoo.http import request, Response
import json
import os
from passlib.context import CryptContext
import re
import logging

_logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UsersAPI(http.Controller):

    @staticmethod
    def validate_email(email):
        # Expresión regular para validar correo electrónico
        return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

    @staticmethod
    def validate_name_and_surname(name):
        # Validar que solo contenga letras y espacios y que tenga al menos 5 caracteres
        return bool(re.match(r"^[a-zA-Z\s]+$", name)) and len(name) >= 5

    @staticmethod
    def validate_profession(profession):
        # Validar que solo contenga letras y espacios y que tenga al menos 5 caracteres
        return bool(re.match(r"^[a-zA-Z\s]+$", profession)) and len(profession) >= 5

    @staticmethod
    def validate_phone(phone):
        # Validar que sea un número y que tenga al menos 9 dígitos
        return phone.isdigit() and len(phone) >= 9

    @staticmethod
    def validate_zip_code(zip_code):
        # Validar que sea un número y que tenga 5 dígitos
        return zip_code.isdigit() and len(zip_code) == 5

    @staticmethod
    def validate_password(password):
        errors = []

        if len(password) < 8:
            errors.append("La contraseña debe tener al menos 8 caracteres.")
        if not re.search(r'[A-Z]', password):
            errors.append("La contraseña debe contener al menos una letra mayúscula.")
        if not re.search(r'[a-z]', password):
            errors.append("La contraseña debe contener al menos una letra minúscula.")
        if not re.search(r'[0-9]', password):
            errors.append("La contraseña debe contener al menos un número.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>-_+\[\]=;\'\\]', password):
            errors.append("La contraseña debe contener al menos un carácter especial.")

        return errors


    # Endpoint para la creación de usuario
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
                    return self.error_response(f"Faltan datos obligatorios: {','.join(missing_fields)}")

                # Errores de validación
                errors = []

                # Validación de los campos
                if not UsersAPI.validate_email(data['email']):
                    errors.append("El correo electrónico no es válido.")
                if not UsersAPI.validate_name_and_surname(data['name']):
                    errors.append("El nombre debe tener al menos 5 caracteres y contener solo letras y espacios.")
                if not UsersAPI.validate_phone(data['phone']):
                    errors.append("El número de teléfono debe contener al menos 9 dígitos.")
                if not UsersAPI.validate_zip_code(data['zip_code']):
                    errors.append("El código postal debe contener exactamente 5 dígitos.")
                if data.get('profession') and not UsersAPI.validate_profession(data['profession']):
                    errors.append("La profesión debe tener al menos 5 caracteres y contener solo letras y espacios.")
                
                # Validación de la contraseña
                password_errors = UsersAPI.validate_password(data['password'])
                if password_errors:
                    errors.extend(password_errors)

                # Si hay errores, los devolvemos
                if errors:
                    return self.error_response(f"Errores: {', '.join(errors)}")

                # Creación del usuario
                user = request.env['users'].sudo().create({
                    'profession': data.get('profession'),
                    'email': data['email'],
                    'password': data['password'],
                    'name': data['name'],
                    'enterprise_name': data.get('enterprise_name', None),
                    'phone': data['phone'],
                    'zip_code': data['zip_code'],
                    'subscription': data['subscription'],
                })

                response_data = {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'subscription': user.subscription,
                    'message': 'Usuario creado correctamente'
                }

                response = Response(json.dumps(response_data), content_type='application/json', status=201)
                return self.add_cors_headers(response)

            except Exception as e:
                _logger.error("Error al crear el usuario:", exc_info=True)
                return self.error_response(f"Error al crear el usuario: {str(e)}")


    def error_response(self, message, status=400):
        response = Response(json.dumps({'error': message}), content_type='application/json', status=status)
        return self.add_cors_headers(response)

    def add_cors_headers(self, response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response