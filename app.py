from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask import abort
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
    
class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    file = db.relationship('File', backref=db.backref('shared_files', lazy=True))
    shared_with = db.relationship('User', foreign_keys=[shared_with_id])
    shared_by = db.relationship('User', foreign_keys=[shared_by_id])

is_production = os.environ.get("RENDER") is not None

UPLOAD_FOLDER = "/tmp/uploads" if is_production else os.path.join(os.getcwd(), "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/rename", methods=["POST"])
def rename_file():
    old_name = request.form.get("old_name", "").strip()
    new_name = request.form.get("new_name", "").strip()
    folder_name = request.form.get("folder_name", "").strip()

    if not old_name or not new_name:
        return jsonify({"error": "Els noms no poden estar buits"}), 400

    upload_folder = app.config["UPLOAD_FOLDER"]
    user_id = str(current_user.id)

    old_path = os.path.normpath(os.path.join(upload_folder, user_id, folder_name, old_name))
    new_path = os.path.normpath(os.path.join(upload_folder, user_id, folder_name, new_name))

    try:
        os.rename(old_path, new_path)

        file_to_update = File.query.filter_by(filename=old_name).first()

        if file_to_update:
            print(f"Arxiu trobat: {file_to_update.filename}, {file_to_update.filepath}")
            file_to_update.filename = new_name
            file_to_update.filepath = os.path.join(folder_name, new_name)
            db.session.commit()
        else:
            return jsonify({
                "error": f"No se encontró archivo con filename={old_name}"
            }), 404

        return redirect(request.referrer or url_for('home'))

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Error al renombrar el archivo: {e}"}), 500


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return redirect(request.referrer or url_for('home'))

    file = request.files['file']
    if file.filename == '':
        return redirect(request.referrer or url_for('home'))

    parent_folder = request.form.get('parent_folder', '').strip()
    if not parent_folder:
        parent_folder = request.args.get('folder', '').strip()

    if parent_folder.startswith("/") or ".." in parent_folder:
        return redirect(request.referrer or url_for('home'))

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    upload_folder = os.path.normpath(os.path.join(user_folder, parent_folder))

    if not upload_folder.startswith(user_folder):
        return redirect(request.referrer or url_for('home'))

    os.makedirs(upload_folder, exist_ok=True)

    file_path = os.path.join(upload_folder, file.filename)

    try:
        file.save(file_path)

        db_file_path = os.path.relpath(file_path, user_folder) 
        new_file = File(user_id=current_user.id, filepath=db_file_path, filename=file.filename)
        db.session.add(new_file)
        db.session.commit()

    except Exception as e:
        flash(f'Error al pujar arxiu: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('home'))

@app.route('/files')
@login_required
def list_files():
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    current_folder = request.args.get('folder', '')

    if current_folder:
        parent_folder = '/'.join(current_folder.split('/')[:-1])  
    else:
        parent_folder = ''

    folder_path = os.path.join(user_folder, current_folder)

    files_in_folder = File.query.filter(
        File.user_id == current_user.id, 
        ~File.filepath.like('%\\%')       
    ).all()

    print(files_in_folder)

    subfolders = [
        f for f in os.listdir(folder_path)
        if os.path.isdir(os.path.join(folder_path, f))
    ]
    
    return render_template('home.html', files=files_in_folder, folders=subfolders, current_folder=current_folder, parent_folder=parent_folder)

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

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    file_path = os.path.normpath(os.path.join(user_folder, file.filepath))

    if not os.path.exists(file_path):
        abort(404)  

    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)

    return send_from_directory(directory, filename, as_attachment=True)

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

    return redirect(request.referrer or url_for('home'))
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/home')
@login_required
def home():
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    files = File.query.filter(
        File.filepath.like(f"{user_folder}/%"),  
        ~File.filepath.like(f"{user_folder}/%/%"),  
        File.user_id == current_user.id
    ).all()
    
    folders = [
        f for f in os.listdir(user_folder)
        if os.path.isdir(os.path.join(user_folder, f)) and not f.startswith('.')
    ]

    return render_template('home.html', files=files, folders=folders, current_folder="")

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


@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    parent_folder = request.form.get('parent_folder', '').strip() or ""  
    new_folder = request.form.get('new_folder', '').strip()

    if not new_folder:
        flash("El nombre de la carpeta no puede estar vacío", "danger")
        return redirect(url_for("home"))

    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(current_user.id))

    folder_path = os.path.normpath(os.path.join(user_folder, parent_folder, new_folder))

    if not folder_path.startswith(user_folder):
        flash("Intento de acceso no autorizado", "danger")
        return redirect(url_for("home"))

    try:
        os.makedirs(folder_path, exist_ok=True)
        flash(f'Carpeta "{new_folder}" creada en "{parent_folder}"', 'success')
    except Exception as e:
        flash(f'Error al crear la carpeta: {str(e)}', 'danger')

    return redirect(url_for('list_files'))

@app.route("/move_file", methods=["POST"])
@login_required
def move_file():
    file_id = request.form.get("file_id")
    folder_name = request.form.get("folder_name", "").strip()

    if not file_id or not folder_name:
        flash("Arxiu i carpeta són necessaris", "danger")
        return redirect(url_for("list_files"))

    file = File.query.get(file_id)
    if not file or file.user_id != current_user.id:
        flash("Arxiu no trobat o sense permisos", "danger")
        return redirect(url_for("list_files"))

    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(current_user.id))
    old_path = os.path.normpath(os.path.join(user_folder, file.filepath))

    current_folder = os.path.dirname(file.filepath)
    if current_folder:  
        new_folder = os.path.normpath(os.path.join(user_folder, current_folder, secure_filename(folder_name)))
    else:  
        new_folder = os.path.normpath(os.path.join(user_folder, secure_filename(folder_name)))

    new_path = os.path.normpath(os.path.join(new_folder, secure_filename(file.filename)))

    try:
        if not os.path.exists(new_folder):
            os.makedirs(new_folder)

        os.rename(old_path, new_path)

        if current_folder:
            file.filepath = os.path.join(current_folder, folder_name, secure_filename(file.filename))
        else:
            file.filepath = os.path.join(folder_name, secure_filename(file.filename))

        db.session.commit()
        flash("Arxiu mogut exitosament!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al moure l'arxiu: {e}", "danger")

    return redirect(url_for("list_folder", folder_name=os.path.join(current_folder, folder_name)))

@app.route('/folder/<path:folder_name>')
@login_required
def list_folder(folder_name):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    folder_path = os.path.normpath(os.path.join(user_folder, folder_name))

    if not folder_path.startswith(user_folder):
        return redirect(url_for('home'))

    formatted_folder_name = folder_name.replace("/", "\\") 
    print(f"Buscando archivos en: {formatted_folder_name}")

    files = File.query.filter(
        File.user_id == current_user.id,
        File.filepath.like(f"{formatted_folder_name}\\%"),
        ~File.filepath.like(f"{formatted_folder_name}\\%\\%")  
    ).all()

    folders = [
        f for f in os.listdir(folder_path)
        if os.path.isdir(os.path.join(folder_path, f))
    ]

    if folder_name:
            parent_folder = '/'.join(folder_name.split('/')[:-1])
    else:
        parent_folder = ''

    return render_template('home.html', files=files, folders=folders, current_folder=folder_name, parent_folder=parent_folder)

import shutil

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    folder_name = request.form.get("folder_name", "").strip()
    parent_folder = request.form.get("parent_folder", "").strip()

    if not folder_name:
        flash("El nom de la carpeta és necessari", "danger")
        return redirect(url_for("list_files"))

    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(current_user.id))
    if parent_folder:
        folder_path = os.path.normpath(os.path.join(user_folder, parent_folder, secure_filename(folder_name)))
    else:
        folder_path = os.path.normpath(os.path.join(user_folder, secure_filename(folder_name)))

    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        flash("La carpeta no existeix o no es troba", "danger")
        return redirect(url_for("list_files"))

    try:
        shutil.rmtree(folder_path)
        print(f"Carpeta eliminada: {folder_path}")

        relative_folder_path = os.path.relpath(folder_path, user_folder)
        File.query.filter(File.filepath.like(f"{relative_folder_path}%")).delete(synchronize_session=False)
        db.session.commit()

        flash("Carpeta eliminada correctament!", "success")
    except PermissionError as e:
        db.session.rollback()
        print(f"Error de permisos al eliminar la carpeta {folder_path}: {e}")
        flash(f"Error de permisos al eliminar la carpeta: {e}", "danger")
    except OSError as e:
        db.session.rollback()
        print(f"Error al eliminar la carpeta {folder_path}: {e}")
        flash(f"Error al eliminar la carpeta: {e}", "danger")
    except Exception as e:
        db.session.rollback()
        print(f"Error inesperat al eliminar la carpeta {folder_path}: {e}")
        flash(f"Error inesperat: {e}", "danger")

    if parent_folder == '':
        return redirect(url_for("list_files"))
    else:
        return redirect(url_for("list_folder", folder_name=parent_folder))
    
@app.route('/move_to_folder', methods=['POST'])
@login_required
def move_to_folder():
    folder_name = request.form.get("folder_name", "").strip()
    current_folder = request.form.get("current_folder", "").strip()

    if current_folder and current_folder.lower() != "none":
        full_path = os.path.join(current_folder, folder_name)
    else:
        full_path = folder_name

    full_path = full_path.replace("\\", "/")  

    return redirect(url_for("list_folder", folder_name=full_path))

@app.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id:
        return redirect(url_for('home'))

    shared_with_username = request.form.get("shared_with", "").strip().lower()
    shared_with_user = User.query.filter_by(username=shared_with_username).first()

    if not shared_with_user or shared_with_user.id == current_user.id:
        return redirect(url_for('home'))

    already_shared = SharedFile.query.filter_by(file_id=file.id, shared_with_id=shared_with_user.id).first()
    if already_shared:
        return redirect(url_for('home'))

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(shared_with_user.id))
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    original_file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id), file.filepath)
    copied_file_path = os.path.join(user_folder, os.path.basename(file.filename))

    try:
        shutil.copy(original_file_path, copied_file_path)

        shared_file = SharedFile(file_id=file.id, shared_with_id=shared_with_user.id, shared_by_id=current_user.id)
        db.session.add(shared_file)
        db.session.commit()
    except Exception as e:
        db.session.rollback()

    return redirect(request.referrer or url_for('home'))

@app.route('/shared_files')
@login_required
def shared_files():
    shared_files = db.session.query(SharedFile, File).join(File).filter(SharedFile.shared_with_id == current_user.id).all()
    
    return render_template('shared_files.html', shared_files=shared_files)

@app.route('/download_shared_file/<int:file_id>')
@login_required
def download_shared_file(file_id):
    shared_file = SharedFile.query.get_or_404(file_id)

    if shared_file.shared_with_id != current_user.id:
        abort(403)  

    shared_file_record = File.query.get_or_404(shared_file.file_id)

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    file_path = os.path.join(user_folder, os.path.basename(shared_file_record.filename))  # Usa la copia en la carpeta del usuario

    if not os.path.exists(file_path):
        abort(404)

    return send_from_directory(os.path.dirname(file_path), os.path.basename(file_path), as_attachment=True)

@app.route('/')
def ruta():
    return redirect(url_for("web"))

from app import app, db
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)