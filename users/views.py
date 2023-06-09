# IMPORTS
import logging
from functools import wraps
from datetime import datetime
from flask import Blueprint, render_template, flash, redirect, url_for, request, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from app import db, requires_roles
from models import User
from users.forms import RegisterForm, LoginForm
import pyotp

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create register form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        pin_key=form.pin_key.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        logging.warning('SECURITY - User registration [%s, %s]', form.email.data, request.remote_addr)

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render register page
    return render_template('register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():

    # checks the number of login attempts
    if not session.get('logins'):
        session['logins'] = 0

    elif session.get('logins') >= 3:
        flash('Number of incorrect logins exceeded')

    # creates login form object
    form = LoginForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():

        # number of login attempts incremented
        session['logins'] += 1

        user = User.query.filter_by(email=form.username.data).first()

        if not user or not check_password_hash(user.password, form.password.data):
            # prompts if invalid login attempts have reached their limit which is 3 attempts
            if session['logins'] == 3:
                flash('Number of incorrect logins exceeded')
            # asks user to check their login details and enter the correct details in order to attempt login again
            elif session['logins'] == 2:
                flash('Please check your login details and try again. 1 login attempt remaining')
            else:
                flash('Please check your login details and try again. 2 login attempts remaining')

            return render_template('login.html', form=form)
        # verification of two factor authentication pin key
        if pyotp.TOTP(user.pin_key).verify(form.pin.data):

            session['logins'] = 0

            # user logged in
            login_user(user)

            # adds the user login time and current login to the database
            user.last_logged_in = user.current_logged_in
            user.current_logged_in = datetime.now()
            db.session.add(user)
            db.session.commit()

            # logs the login data into lottery.log
            logging.warning('SECURITY - Log in [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)

            # checks the role of the user as well as the permissions and redirects to the page accordingly
            if current_user.role == 'admin':
                return redirect(url_for('admin.admin'))
            else:
                return redirect(url_for('users.profile'))

        # error message for incorrect 2FA pin
        else:
            flash("You have supplied an invalid 2FA token!", "danger")

    # if request method is GET or form not valid re-render login page
    return render_template('login.html', form=form)


# view user profile
@users_blueprint.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.firstname)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)


# view logout page for a user
@users_blueprint.route('/logout')
@login_required
def logout():
    # logs the logout data in the lottery.log
    logging.warning('SECURITY - Log out [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)

    # user successfully logged out and redirected to home page
    logout_user()
    return redirect(url_for('index'))