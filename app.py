from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, current_user, login_required, LoginManager, UserMixin, logout_user
import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email

TEMPLATES = "./templates"
STATIC = "./static"

app = Flask(__name__, template_folder=TEMPLATES, static_folder=STATIC)

app.config['SECRET_KEY'] = "9d703c1c45ff850c93005106de2d6f5e"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Faça o login para acessar esta página'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class RegistrationForm(FlaskForm):

    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrar')


class LoginForm(FlaskForm):

    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route("/", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.email.data is not None and form.password.data is not None:
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash("Falha no login. Por favor cheque o email e a senha", 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    form = RegistrationForm()
    if form.email.data is not None and form.password.data is not None and form.confirm_password.data is not None:
        email = User.query.filter_by(email=form.email.data).first()
        if email:
            erro = 'Esse email já está sendo usado, por favor escolha outro'
            return render_template('register.html', title='Registrar', form=form)

        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Sua conta foi criada! Agora você pode fazer login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Registrar', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/home")
@login_required
def home():
    dados_aumento = ["20", "30", "40"]
    dados_reducao = ["50", "60", "70"]
    dados_media = ["20", "36", "42"]
    data = datetime.datetime.now().strftime("%m/%d/%Y")
    return render_template("index.html", aumento=dados_aumento, reducao=dados_reducao, media=dados_media, data=data)


@app.route("/navbar")
def navbar():
    return render_template("navbar.html")
