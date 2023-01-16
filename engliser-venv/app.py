from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_migrate import Migrate
from sqlalchemy import UniqueConstraint
from flask_mail import Mail, Message

app = Flask(__name__)

#Configs
app.config['SECRET_KEY'] = "testkey" #Change on production
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hoang.nicolas2409@gmail.com'
app.config['MAIL_PASSWORD'] = 'xaxycpeetmsciwgb'

#Only use SQLAlchemy for handling Roles and Authentication
db = SQLAlchemy(app=app)

#Added Migration
migrate = Migrate(app=app, db=db)

#Flask Mail
mail = Mail(app)

#Normal User table
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.String(), nullable=False)
    token = db.Column(db.String(), nullable=False)
    hashed_password = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True)
    full_name = db.Column(db.String(), nullable=False)
    verified = db.Column(db.Boolean(), default=False)
    role = db.Column(db.String(), nullable=False)
    __table_args__ = (UniqueConstraint('user_id', name="uq_userid"), UniqueConstraint('token', name="uq_token"))

class Verify(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    verify_key = db.Column(db.String(), nullable=False, unique=True)
    user_id = db.Column(db.String(), nullable=False, unique=True)
    __table_args__ = (UniqueConstraint('verify_key', name="uq_verify"), UniqueConstraint('user_id', name="uq_uid"))