from odoo import models, fields, api
from passlib.hash import bcrypt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Users(models.Model):
    _name = 'users'
    _description = 'Usuarios'

#Atributos del usuario
    profession = fields.Char(string='Profesión', required=True)
    email = fields.Char(string='Correo Electrónico', required=True)
    password = fields.Text(string='Contraseña', required=True)
    name = fields.Char(string='Nombre', required=True)
    enterprise_name = fields.Char(string='Nombre de la empresa')
    phone = fields.Char(string='Número de Telefono', required=True)

    subscription = fields.Selection([
        ('Partner', 'Partner'),
        ('Lover', 'Lover'),
        ('Corner', 'Corner'),
        ('Franquicia', 'Franquicia'),

    ], string='Tipo de Suscripción', required=True)

    zip_code = fields.Char(string='Código Postal')

    reset_token = fields.Char(string='Token de Restablecimiento', copy=False)
    reset_token_expiration = fields.Datetime(string='Expiración del Token', copy=False)

    terms_accepted = fields.Boolean(string="¿Acepta los términos y condiciones?", required=True, default=False)

    @api.model
    def create(self, vals):
        if vals.get('password'):
            vals['password'] =  pwd_context.hash(vals['password'])
        return super(Users, self).create(vals)

    def write(self, vals):
        if vals.get('password'):
            vals['password'] = pwd_context.hash(vals['password'])
        return super(Users, self).write(vals)   