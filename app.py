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
    folder_name = request.form.get('folder_name') 
    
    if folder_name:
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(folder_name))

        if not os.path.exists(folder_path):
            os.makedirs(folder_path) 
    else:
        folder_path = app.config['UPLOAD_FOLDER'] 
    
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.referrer)  

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.referrer) 

    filename = secure_filename(file.filename)
    filepath = os.path.join(folder_path, filename)
    file.save(filepath)

    new_file = File(filename=filename, filepath=filepath, user_id=current_user.id)
    db.session.add(new_file)
    db.session.commit()

    if folder_name:
        return redirect(url_for('list_folder', folder_name=folder_name))
    return redirect(url_for('list_files'))

@app.route('/files')
@login_required
def list_files():
    root_folder = app.config['UPLOAD_FOLDER']

    user_files = File.query.filter(
        File.filepath.startswith(root_folder),
        File.user_id == current_user.id,
        ~File.filepath.like(f"{os.path.join(root_folder, '%', '%')}")
    ).all()

    folders = [
        f for f in os.listdir(root_folder)
        if os.path.isdir(os.path.join(root_folder, f))
    ]

    return render_template('home.html', files=user_files, folders=folders, current_folder=None)


@app.after_request
def no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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

    print(f"Intentando eliminar: {filepath}") 

    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            print("Archivo eliminado del sistema de archivos.")
        except Exception as e:
            flash(f'Error eliminando el archivo: {e}', 'danger')
            return redirect(url_for('list_files'))
    else:
        flash('El archivo no existe en el sistema.', 'warning')

    try:
        db.session.delete(file)
        db.session.commit()
        print("Archivo eliminado de la base de datos.")
        flash('Archivo eliminado correctamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error eliminando de la base de datos: {e}', 'danger')

    return redirect(url_for('list_files'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/home')
@login_required
def home():
    root_folder = app.config['UPLOAD_FOLDER']

    files = File.query.filter_by(user_id=current_user.id).all()

    folders = [
        f for f in os.listdir(root_folder)
        if os.path.isdir(os.path.join(root_folder, f))
    ]

    return render_template('home.html', files=files, folders=folders, current_folder=None)

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
            flash('¡Usuario registrat amb exit!', 'successR')
            return redirect(url_for('login'))  

        except IntegrityError:
            db.session.rollback()  
            flash('Aquest nom de usuari ja está registrat. Escull un altre...', 'errorR')
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
            flash("Sessió iniciada correctament!", "successL")
            return redirect(url_for('web'))
        else:
            flash("Credencials incorrectes!", "errorL")
            return redirect(url_for('login'))
        
    return render_template('iniciSessio.html')

@app.route('/web')
@login_required
def web():
    return render_template('web.html')

@app.route('/verify')
def verify_login():
    if not current_user.is_authenticated:
        return redirect(url_for('login')) 
    else:
        return redirect(url_for('home'))

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

@app.route("/create_folder", methods=["POST"])
@login_required
def create_folder():
    folder_name = request.form.get("folder_name", "").strip()
    if not folder_name:
        flash("El nom de la carpeta no pot estar buit", "danger")
        return redirect(url_for("list_files"))

    folder_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(folder_name))

    try:
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            flash("Carpeta creada exitosament", "success")
        else:
            flash("La carpeta ja existeix", "warning")
    except Exception as e:
        flash(f"Error al crear la carpeta: {e}", "danger")

    return redirect(url_for("list_files"))


@app.route("/move_file", methods=["POST"])
@login_required
def move_file():
    file_id = request.form.get("file_id")
    folder_name = request.form.get("folder_name", "").strip()

    if not file_id or not folder_name:
        flash("Arxiu i carpeta son necessaris", "danger")
        return redirect(url_for("list_files"))

    file = File.query.get(file_id)
    if not file or file.user_id != current_user.id:
        flash("Arxiu no trobat o sense permisos", "danger")
        return redirect(url_for("list_files"))

    old_path = file.filepath
    new_folder = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(folder_name))
    new_path = os.path.join(new_folder, secure_filename(file.filename))

    try:
        if not os.path.exists(new_folder):
            os.makedirs(new_folder)

        os.rename(old_path, new_path)
        file.filepath = new_path
        db.session.commit()
        flash("Arxiu mogut exitosament!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al mover l'arxiu: {e}", "danger")

    return redirect(url_for("list_folder", folder_name=folder_name))

@app.route("/folder/<path:folder_name>")
@login_required
def list_folder(folder_name):
    folder_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(folder_name))

    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        return redirect(url_for("list_files"))

    files = File.query.filter(
        File.filepath.startswith(folder_path),
        File.user_id == current_user.id
    ).all()

    folders = [
        f for f in os.listdir(folder_path)
        if os.path.isdir(os.path.join(folder_path, f))
    ]
    return render_template("home.html", files=files, folders=folders, current_folder=folder_name)

import shutil

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    folder_name = request.form.get("folder_name", "").strip()

    if not folder_name:
        flash("El nom de la carpeta no pot estar buit", "danger")
        return redirect(url_for("list_files"))

    folder_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(folder_name))

    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        flash("La carpeta no existeix", "danger")
        return redirect(url_for("list_files"))

    user_files = File.query.filter(File.filepath.like(f"{folder_path}%"), File.user_id == current_user.id).all()

    try:
        for file in user_files:
            os.remove(file.filepath)  
            db.session.delete(file)  

        db.session.commit()

        shutil.rmtree(folder_path)
        flash("Carpeta eliminada correctament", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Error eliminant carpeta: {e}", "danger")

    return redirect(url_for("list_files"))

@app.route('/move_to_folder', methods=['POST'])
@login_required
def move_to_folder():
    folder_name=request.form.get('folder_name')
    return redirect(url_for("list_folder", folder_name=folder_name))

@app.route('/')
def ruta():
    return redirect(url_for("web"))

from app import app, db
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)