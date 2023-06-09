# IMPORTS
import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, ValidationError, Length, EqualTo


# checks if a field contains characters that are not allowed
def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(
                f"Character {char} is not allowed.")


# checks the length of a phone number
def validate_phone(form, field):
    if len(field.data) < 13 or len(field.data) > 13:
        raise ValidationError('Invalid phone number.')


# form for registration of a user, each field has validators
class RegisterForm(FlaskForm):

    # a required field for email, only email is accepted in this field
    email = StringField(validators=[Required(), Email()])

    # a required field for the first name of a user, the character_check ensures no excluded characters are entered
    firstname = StringField(validators=[Required(), character_check])

    # a required field for the last name of a user, the character_check ensures no excluded characters are entered
    lastname = StringField(validators=[Required(), character_check])

    # a required field for phone number of a user, must be of lentgh 13
    phone = StringField(validators=[Required(), Length(13,
                                                       message='Phone number must 13 characters long in the form XXXX-XXX-XXXX (including the dashes)'),
                                    validate_phone])

    # a required field for the password of a user
    password = PasswordField(validators=[Required(), Length(min=6, max=12,
                                                            message='Password must be between 6 and 12 characters in length.')])

    # a required field for user to confirm their password
    confirm_password = PasswordField(
        validators=[Required(), EqualTo('password', message='Both password fields must be equal!')])

    # a required field for user to enter their 32 digit pin key
    pin_key = StringField(validators=[Required(), Length(32, message='PIN Key must be exactly 32 characters long')])

    # a field to submit the form
    submit = SubmitField()

    # a validator to confirm if they password contains at least 1 digit, 1 uppercase letter and 1 special character
    def validate_password(self, password):
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*?[^A-Za-z\s0-9])')
        if not p.match(self.password.data):
            raise ValidationError("Password must contain at least 1 digit, 1 uppercase letter and 1 special character.")


# form for a user to login to the web application, each field has a validator
class LoginForm(FlaskForm):

    # a required field for user to enter their email as their username
    username = StringField(validators=[Required(), Email()])

    # a required field for user to enter their password
    password = PasswordField(validators=[Required()])

    # a required field for a user to enter their two factor authentication pin of 6 digits
    pin = StringField(validators=[Required(), Length(6, message='Pin must be 6 digits long and must be verified')])

    # a field to submit the login form
    submit = SubmitField()
