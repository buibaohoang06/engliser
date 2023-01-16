from flask import Blueprint, render_template, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import InputRequired
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from hashlib import sha256, md5
import hmac
import base64
from cryptography.fernet import Fernet
import secrets

#Local Imports
from app import app, mail, db, Users, Verify

#Initialize Blueprint
authbp = Blueprint("auth", __name__, url_prefix="/auth", static_folder="static", template_folder="templates")

#Forms
class LoginForm(FlaskForm):
    email = EmailField(validators=[InputRequired()], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField()

class RegisterForm(FlaskForm):
    email = EmailField(validators=[InputRequired()], render_kw={"placeholder": "Email"})
    fullname = StringField(validators=[InputRequired()], render_kw={"placeholder": "Full Name"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField()

#Functions
def generatePassword(password_str: str):
    return sha256(password_str.encode()).hexdigest()

def validatePassword(password_str: str, compare: str):
    return generatePassword(password_str=password_str) == compare

def generateToken(username: str, hashed_password: str):
    fernet = Fernet(key=app.config['SECRET_KEY'])
    b64_username = base64.b64encode(username.encode('ascii'))
    processed_pass = fernet.encrypt(hashed_password)
    token = f"{b64_username}.{processed_pass}"
    return token
    

#Routes
@authbp.route('/', methods=['GET'])
def authmain():
    return redirect('/auth/login')

@authbp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = Users.query.filter_by(email=form.email.data).first()
            if validatePassword(form.password.data, user.hashed_password):
                login_user(user)
                flash('Logged in!', 'success')
                return redirect('/dashboard')
            else:
                flash('Wrong password!', 'danger')
                return redirect('/auth/login')
        except AttributeError:
            flash('User does not exist!', 'danger')
            return redirect('/auth/login')
    return render_template('auth.html', page="login")

@authbp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            user = Users()
            verify = Verify()

            #Create new user
            userid = str(secrets.token_hex(60))
            user.email = form.email.data
            user.hashed_password = generatePassword(form.password.data)
            user.token = generateToken(username=form.username.data, hashed_password=generatePassword(form.password.data))
            user.fullname = form.fullname.data
            user.verified = False
            user.user_id = userid

            #Create new verification order
            verify.verify_key = secrets.token_hex(16)
            verify.user_id = userid
        except Exception as e:
            pass
