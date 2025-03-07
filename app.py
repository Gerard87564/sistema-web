from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_migrate import Migrate
import os
from werkzeug.utils import secure_filename
from flask import send_file
from flask import send_from_directory

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
    storage_used = db.Column(db.Integer, default=0) 
    storage_limit = db.Column(db.Integer, default=104857600)  
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('files', lazy=True))

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route("/rename", methods=["POST"])
def rename_file():
    old_name = request.form.get("old_name", "").strip()
    new_name = request.form.get("new_name", "").strip()

    if not old_name or not new_name:
        return jsonify({"error": "Els noms no poden estar buits"}), 400

    old_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(old_name))
    new_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(new_name))

    if not os.path.exists(old_path):
        return jsonify({"error": "El fitxer o carpeta no existeix"}), 404

    try:
        os.rename(old_path, new_path) 

        file_to_update = File.query.filter_by(filename=old_name, filepath=old_path).first()

        if file_to_update:
            file_to_update.filename = new_name 
            file_to_update.filepath = new_path 
            db.session.commit() 
        else:
            return jsonify({"error": "No se encontró el archivo en la base de datos"}), 404

        return redirect(url_for('home'))

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error al renombrar el archivo: {e}"}), 500
    
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('web'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('web'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    file.save(filepath)

    new_file = File(filename=filename, filepath=filepath, user_id=current_user.id)
    db.session.add(new_file)
    db.session.commit()

    flash('Arxiu pujat amb éxit!', 'success')
    return redirect(url_for('list_files'))

@app.route('/files')
@login_required
def list_files():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('web.html', files=files)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403) 
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)


@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    try:
        os.remove(filepath)
        db.session.delete(file) 
        db.session.commit() 
        flash('Archivo eliminado correctamente', 'success')
    except FileNotFoundError:
        flash('File not found.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting file: {e}', 'danger')

    return redirect(url_for('list_files'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))  

    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('web.html', files=files)

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
            flash('¡Usuario registrat amb exit!', 'success')
            return redirect(url_for('login'))  

        except IntegrityError:
            db.session.rollback()  
            flash('Aquest nom de usuari ja está registrat. Escull un altre...', 'danger')
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
            return redirect(url_for('pujadesFitxers'))
        else:
            flash("Credencials incorrectes!", "danger")
            return redirect(url_for('login'))

    return render_template('iniciSessio.html')

@app.route('/web')
@login_required
def web():
    return render_template('web.html')

@app.route('/pujadesFitxers')
@login_required
def pujadesFitxers():
    return render_template('pujadesFitxers.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Sessió tancada correctament!", "success")
    return redirect(url_for('login'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('No tens permisos per a eliminar usuaris.', 'danger')
        return redirect(url_for('web'))

    user_to_delete = User.query.get_or_404(user_id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Usuario {user_to_delete.username} eliminado correctamente.', 'success')
    except Exception as e:
        db.session.rollback()  
        flash(f'Error al eliminar el usuari: {e}', 'danger')

    return redirect(url_for('admin_dashboard'))  

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('No tens permisos per a accedir a aquesta página.', 'danger')
        return redirect(url_for('web'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

from app import app, db
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)