from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'kakukakukakuka'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
Bootstrap(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
    password = PasswordField('Password', validators=[InputRequired()])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already in use', 'danger')
        else:
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/about')
def about_html():
    return render_template('about.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/ghelp')
def ghelp():
    return render_template('ghelp.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied! Admins only.', 'danger')
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/adminlogin')
def adminlogin():
    return render_template('adminlogin.html')

@app.route('/404')
def error_404():
    return render_template('404.html')

@app.route('/adjara')
def adjara():
    return render_template('adjara.html')

@app.route('/index')
def index_html():
    return render_template('index.html')


@app.route('/abkhazia')
def abkhazia():
    return render_template('abkhazia.html')

@app.route('/guria')
def guria():
    return render_template('guria.html')

@app.route('/imereti')
def imereti():
    return render_template('imereti.html')

@app.route('/kakheti')
def kakheti():
    return render_template('kakheti.html')

@app.route('/kvemo_kartli')
def kvemo_kartli():
    return render_template('kvemo_kartli.html')

@app.route('/mtskheta')
def mtskheta():
    return render_template('mtskheta.html')

@app.route('/samegrelo')
def samegrelo():
    return render_template('samegrelo.html')

@app.route('/shida_kartli')
def shida_kartli():
    return render_template('shida_kartli.html')

@app.route('/tbilisi')
def tbilisi():
    return render_template('tbilisi.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.before_request
def handle_html_extension():
    if request.path.endswith('.html'):
        return redirect(request.path[:-5], code=301)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
