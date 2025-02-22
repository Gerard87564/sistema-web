from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sistema_web.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'gerard98065'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('web.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('¡Usuario registrado con éxito!', 'success')
            return redirect(url_for('login'))  

        except IntegrityError:
            db.session.rollback()  
            flash('Este nombre de usuario ya está registrado. Elige otro.', 'danger')
            return redirect(url_for('register'))  
        
    return render_template('registre.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Sessió iniciada correctament!", "success")
            return redirect(url_for('web'))
        else:
            flash("Credencials incorrectes!", "danger")
            return redirect(url_for('login'))

    return render_template('iniciSessio.html')

@app.route('/web')
@login_required
def web():
    return render_template('web.html')

@app.route('/reptes')
def reptes():
    return render_template('reptes.html')

@app.route('/sqli')
def sqli():
    return render_template('sqli.html')

@app.route('/criptografia')
def criptografia():
    return render_template('criptografia.html')

@app.route('/fdigital')
def fdigital():
    return render_template('fdigital.html')

@app.route('/programacio')
def programacio():
    return render_template('programacio.html')

@app.route('/steganografia')
def steganografia():
    return render_template('steganografia.html')

@app.route('/sqligame')
def sqligame():
    return render_template('sqligame.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Sessió tancada correctament!", "success")
    return redirect(url_for('login'))

@app.route('/validate', methods=['POST'])
def validate():
    flag = request.form['flag']
    return redirect(f'http://localhost/flags-validate.php?flag={flag}')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('No tienes permisos para eliminar usuarios.', 'danger')
        return redirect(url_for('web'))

    user_to_delete = User.query.get_or_404(user_id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Usuario {user_to_delete.username} eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()  
        flash(f'Error al eliminar el usuario: {e}', 'danger')

    return redirect(url_for('admin_dashboard'))  

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('web'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

from app import app, db
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)