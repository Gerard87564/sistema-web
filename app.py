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
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sistema_web.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'gerard98065'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    path = db.Column(db.String(255), nullable=False)

    user = db.relationship('User', backref=db.backref('folders', lazy=True))
    
class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    file = db.relationship('File', backref=db.backref('shared_files', lazy=True))
    shared_with = db.relationship('User', foreign_keys=[shared_with_id])
    shared_by = db.relationship('User', foreign_keys=[shared_by_id])

class LoginForm(FlaskForm):
    username = StringField('Usuari', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Contrasenya', validators=[InputRequired()])
    submit = SubmitField('Iniciar Sessió')

class RegisterForm(FlaskForm):
    username = StringField('Usuari', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('Contrasenya', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirma la contrasenya', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Registrar-se')

is_production = os.environ.get("RENDER") is not None

UPLOAD_FOLDER = "/tmp/uploads" if is_production else os.path.join(os.getcwd(), "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/rename", methods=["POST"])
@login_required
def rename_file():
    old_name = request.form.get("old_name", "").strip()
    new_name = request.form.get("new_name", "").strip()
    folder_name = request.form.get("folder_name", "").strip()

    if not old_name or not new_name:
        return jsonify({"error": "Els noms no poden estar buits"}), 400

    ftp = connect_ftp()
    user_id = str(current_user.id)
    folder_path = f"/{user_id}/{folder_name}".strip("/")

    try:
        ftp.cwd(f"/{folder_path}")

        ftp.rename(old_name, new_name)

        file_to_update = File.query.filter_by(user_id=current_user.id, filename=old_name).first()

        if file_to_update:
            print(f"Arxiu trobat: {file_to_update.filename}, {file_to_update.filepath}")
            file_to_update.filename = new_name
            file_to_update.filepath = os.path.join(folder_name, new_name)
            db.session.commit()
        else:
            return jsonify({
                "error": f"No se encontró archivo con filename={old_name}"
            }), 404

        flash("Archivo renombrado correctamente", "success")
        return redirect(request.referrer or url_for('home'))

    except Exception as e:
        db.session.rollback()
        print(f"Error al renombrar el archivo en el FTP: {e}")
        return redirect(request.referrer or url_for('home'))

    finally:
        ftp.quit()
    
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return redirect(request.referrer or url_for('home'))

    file = request.files['file']
    if file.filename == '':
        return redirect(request.referrer or url_for('home'))

    current_folder = request.form.get('folder', '').strip()  
    ftp = connect_ftp()
    try:
        full_path = f"/{current_user.id}/{current_folder}".strip("/")

        for part in full_path.split("/"):
            try:
                ftp.mkd(part)
            except:
                pass
            ftp.cwd(part)

        ftp.storbinary(f"STOR {file.filename}", file.stream)

        relative_path = f"{current_folder}/{file.filename}" if current_folder else file.filename
        relative_path = relative_path.strip("/")

        new_file = File(user_id=current_user.id, filepath=relative_path, filename=file.filename)
        db.session.add(new_file)
        db.session.commit()

    except Exception as e:
        print(f"Error pujant arxiu al FTP: {e}")
    finally:
        ftp.quit()

    return redirect(request.referrer or url_for('list_files'))

from ftplib import error_perm

@app.route('/files')
@login_required
def list_files():
    current_folder = request.args.get('folder', '').strip()
    parent_folder = '/'.join(current_folder.split('/')[:-1]) if current_folder else ''

    ftp = connect_ftp()
    user_folder = f"/{current_user.id}/{current_folder}".strip("/")

    try:
        ftp.cwd(f"/{user_folder}")
    except error_perm:
        flash("La carpeta no existe en el FTP", "warning")
        ftp.quit()
        return redirect(url_for('home'))

    files_in_folder = []
    subfolders = []

    try:
        entries = []
        ftp.retrlines('LIST', entries.append)

        for entry in entries:
            parts = entry.split()
            if len(parts) < 9:
                continue  
            name = parts[-1]
            is_dir = entry.startswith('d') 

            if is_dir:
                subfolders.append(name)
            else:
                file = File.query.filter_by(user_id=current_user.id, filename=name).first()
                if file:
                    files_in_folder.append(file)

    except Exception as e:
        flash(f"Error al listar archivos: {e}", "danger")

    ftp.quit()

    return render_template(
        'home.html',
        files=files_in_folder,
        folders=subfolders,
        current_folder=current_folder,
        parent_folder=parent_folder
    )

@app.after_request
def no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

import tempfile
from flask import after_this_request

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id:
        abort(403)

    ftp = connect_ftp()
    user_folder = f"/{current_user.id}"
    local_dir = tempfile.mkdtemp()
    local_path = os.path.join(local_dir, secure_filename(file.filename))

    try:
        ftp.cwd(user_folder)

        if "/" in file.filepath:
            subfolder = os.path.dirname(file.filepath)
            ftp.cwd(subfolder)

        ftp.retrbinary(f"RETR {file.filename}", open(local_path, "wb").write)

        return send_file(local_path, as_attachment=True)

    except Exception as e:
        abort(500, description=f"Error al descargar: {e}")

    finally:
        ftp.quit()

        @after_this_request
        def cleanup(response):
            try:
                os.remove(local_path)
                os.rmdir(local_dir)
            except:
                pass
            return response

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id:
        flash('Acceso no autorizado.', 'danger')
        return redirect(url_for('home'))

    ftp = connect_ftp()
    user_folder = f"/{current_user.id}"
    ftp_filepath = f"{user_folder}/{file.filename}"

    try:
        ftp.cwd(user_folder)
        ftp.delete(file.filename)
        print(f"Archivo {file.filename} eliminado del FTP.")
    except Exception as e:
        flash(f'Error al eliminar el archivo del FTP: {e}', 'danger')
        ftp.quit()
        return redirect(url_for('home'))

    ftp.quit()

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
    ftp = connect_ftp()
    user_folder = f"/{current_user.id}"

    files_in_folder = []
    subfolders = []

    try:
        ftp.cwd(user_folder)
    except error_perm:
        try:
            ftp.mkd(user_folder)
            ftp.cwd(user_folder)
        except Exception as e:
            ftp.quit()
            return redirect(url_for('login'))

    try:
        entries = []
        ftp.retrlines('LIST', entries.append)

        for entry in entries:
            parts = entry.split()
            name = parts[-1]
            is_dir = entry.upper().startswith('D') or entry.startswith('drw')

            if is_dir:
                subfolders.append(name)
            else:
                file = File.query.filter_by(user_id=current_user.id, filename=name).first()
                if file:
                    files_in_folder.append(file)

    except Exception as e:
        print(f"Error al llistar contingut del FTP: {e}")

    ftp.quit()

    return render_template(
        'home.html',
        files=files_in_folder,
        folders=subfolders,
        current_folder=""
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.lower()
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        try:
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('¡Usuari registrat amb èxit!', 'success')
            return redirect(url_for('login'))

        except IntegrityError:
            db.session.rollback()
            flash('Aquest usuari ja existeix.', 'danger')
    return render_template('registre.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit(): 
        username = form.username.data.lower()
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            print("Sessió iniciada correctament!")
            return redirect(url_for('web'))
        else:
            flash("Credencials incorrectes!", "errorL")
            return redirect(url_for('login'))
        
    return render_template('iniciSessio.html', form=form)

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
    flash("Sessió tancada correctament.", "info")
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
        print("El nom de la carpeta no pot estar buit")
        return redirect(url_for("home"))

    user_folder = f"/{current_user.id}"
    full_path = f"{user_folder}/{parent_folder}/{new_folder}".replace("//", "/").strip("/")

    ftp = connect_ftp()

    try:
        ftp.cwd(user_folder)

        if parent_folder:
            try:
                ftp.cwd(parent_folder) 
                print(f"Estem en el directori: {ftp.pwd()}")
            except error_perm:
                print(f"El directori '{parent_folder}' no existeix. Creant-lo...")
                ftp.mkd(parent_folder)
                ftp.cwd(parent_folder)  
                print(f"Creat el directori pare: {parent_folder}")

        try:
            ftp.mkd(new_folder)  
            print(f'Carpeta "{new_folder}" creada en "{parent_folder}"')

            existing_folder = Folder.query.filter_by(user_id=current_user.id, path=full_path).first()

            if existing_folder:
                existing_folder.path = full_path
                db.session.commit()
                print(f"Carpeta actualizada en la base de datos: {full_path}")
            else:
                new_folder_entry = Folder(user_id=current_user.id, path=full_path)
                db.session.add(new_folder_entry)
                db.session.commit()
                print(f"Carpeta nova creada en la base de dades: {full_path}")

        except error_perm as e:
            if "File exists" not in str(e):  
                print(f"Error al crear la carpeta: {str(e)}")

    except Exception as e:
        print(f"Error general: {str(e)}")

    finally:
        ftp.quit()

    return redirect(url_for('list_files'))

@app.route("/move_file", methods=["POST"])
@login_required
def move_file():
    ftp = connect_ftp()

    file_id = request.form.get("file_id")
    folder_name = request.form.get("folder_name", "").strip()

    if not file_id or not folder_name:
        flash("Arxiu i carpeta són necessaris", "danger")
        return redirect(url_for("list_files"))

    file = File.query.get(file_id)
    if not file or file.user_id != current_user.id:
        flash("Arxiu no trobat o sense permisos", "danger")
        return redirect(url_for("list_files"))

    old_path = f"/{current_user.id}/{file.filepath}".replace("\\", "/")

    current_folder = os.path.dirname(file.filepath)

    if current_folder:
        new_folder_path = f"/{current_user.id}/{current_folder}/{folder_name}".replace("\\", "/")
        new_filepath = f"{current_folder}/{folder_name}/{file.filename}".replace("\\", "/")
    else:
        new_folder_path = f"/{current_user.id}/{folder_name}".replace("\\", "/")
        new_filepath = f"{folder_name}/{file.filename}".replace("\\", "/")

    new_path = f"{new_folder_path}/{file.filename}"

    try:
        try:
            ftp.mkd(new_folder_path)
            print(f"Carpeta creada: {new_folder_path}")
        except Exception as e:
            print(f"La carpeta ja existeix o error creant carpeta: {e}")

        print(f"Movent de {old_path} a {new_path}")
        ftp.rename(old_path, new_path)

        file.filepath = new_filepath
        db.session.commit()
        flash("Arxiu mogut exitosament!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al moure l'arxiu: {e}", "danger")
    finally:
        ftp.quit()

    return redirect(url_for("list_folder", folder_name=os.path.dirname(file.filepath)))


@app.route('/folder/<path:folder_name>')
@login_required
def list_folder(folder_name):
    print(f"Accediendo a la carpeta: {folder_name}")
    ftp = connect_ftp()

    user_folder = f"/{current_user.id}"
    folder_path = f"{user_folder}/{folder_name}".strip("/")

    print(f"Intentando acceder al directorio: {folder_path}")
    try:
        ftp.cwd(folder_path)
    except Exception as e:
        print(f"Error al intentar acceder al directorio: {e}")
        flash(f"Error al acceder al directorio: {e}", "danger")
        ftp.quit()
        return redirect(url_for('home'))

    formatted_folder_name = folder_name.replace("/", "\\")
    print(f"Buscando archivos en: {formatted_folder_name}")

    files_in_folder = []
    subfolders = []

    try:
        entries = []
        ftp.retrlines('LIST', entries.append)

        for entry in entries:
            parts = entry.split()
            name = parts[-1]
            is_dir = entry.upper().startswith('D') or entry.startswith('drw')

            if is_dir:
                subfolders.append(name)
            else:
                file = File.query.filter_by(user_id=current_user.id, filename=name).first()
                if file:
                    files_in_folder.append(file)

    except Exception as e:
        print(f"Error al listar archivos: {e}")
        flash(f"Error al listar archivos: {e}", "danger")
        ftp.quit()
        return redirect(url_for('home'))

    ftp.quit()

    if folder_name:
        parent_folder = '/'.join(folder_name.split('/')[:-1])
    else:
        parent_folder = ''

    return render_template(
        'home.html',
        files=files_in_folder,
        folders=subfolders,
        current_folder=folder_name,
        parent_folder=parent_folder
    )

import shutil

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    from ftplib import error_perm

    folder_name = request.form.get("folder_name", "").strip()
    parent_folder = request.form.get("parent_folder", "").strip()

    if not folder_name:
        return redirect(url_for("list_files"))

    ftp = connect_ftp()

    if parent_folder:
        folder_path = f"/{current_user.id}/{parent_folder}/{folder_name}".replace("\\", "/")
    else:
        folder_path = f"/{current_user.id}/{folder_name}".replace("\\", "/")

    print(f"Intentant eliminar carpeta: {folder_path}")

    def delete_ftp_folder(path):
        try:
            ftp.cwd(path)
            entries = []
            ftp.retrlines('LIST', entries.append)

            for entry in entries:
                parts = entry.split()
                name = parts[-1]
                item_path = f"{path}/{name}"

                if entry.upper().startswith('D') or entry.startswith('drw'):
                    delete_ftp_folder(item_path) 
                else:
                    ftp.delete(item_path)

            ftp.cwd("..")
            ftp.rmd(path)
            print(f"Carpeta eliminada: {path}")
        except error_perm as e:
            raise Exception(f"No es pot eliminar la carpeta: {e}")

    try:
        delete_ftp_folder(folder_path)

        relative_path = os.path.join(parent_folder, folder_name).replace("\\", "/")
        File.query.filter(File.filepath.like(f"{relative_path}%"), File.user_id == current_user.id).delete(synchronize_session=False)
        db.session.commit()

        flash("Carpeta eliminada correctament!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al eliminar la carpeta: {e}", "danger")
    finally:
        ftp.quit()

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

from io import BytesIO

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

    ftp = connect_ftp()
    try:
        original_path = f"/{current_user.id}/{file.filepath}"
        dest_path = f"/{shared_with_user.id}/{os.path.basename(file.filename)}"

        bio = BytesIO()
        ftp.retrbinary(f"RETR {original_path}", bio.write)
        bio.seek(0)

        try:
            ftp.cwd(f"/{shared_with_user.id}")
        except Exception:
            ftp.mkd(f"/{shared_with_user.id}")

        ftp.storbinary(f"STOR {dest_path}", bio)

        shared_file = SharedFile(file_id=file.id, shared_with_id=shared_with_user.id, shared_by_id=current_user.id)
        db.session.add(shared_file)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f"Error compartint arxiu: {e}", "danger")
    finally:
        ftp.quit()

    return redirect(request.referrer or url_for('home'))

@app.route('/shared_files')
@login_required
def shared_files():
    shared_files = db.session.query(SharedFile, File).join(File).filter(SharedFile.shared_with_id == current_user.id).all()
    
    return render_template('shared_files.html', shared_files=shared_files)

from flask import send_file

@app.route('/download_shared_file/<int:file_id>')
@login_required
def download_shared_file(file_id):
    shared_file = SharedFile.query.get_or_404(file_id)

    if shared_file.shared_with_id != current_user.id:
        abort(403) 

    shared_file_record = File.query.get_or_404(shared_file.file_id)
    filename = os.path.basename(shared_file_record.filename)

    ftp = connect_ftp()
    try:
        shared_user_folder = f"/{current_user.id}"
        file_path = f"{shared_user_folder}/{filename}"

        bio = BytesIO()
        ftp.retrbinary(f"RETR {file_path}", bio.write)
        bio.seek(0)

        return send_file(
            bio,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        print(f"Error al descargar el archivo compartido: {e}")
        abort(404)
    finally:
        ftp.quit()
    
@app.route('/')
def ruta():
    return redirect(url_for("web"))

from ftplib import FTP

def connect_ftp():
    env = os.getenv('ENV', 'local')
    if env == 'render':
        host = 'sistema-web-0579.onrender.com'
        port = 2121
    else:
        host = '192.168.1.49'
        port = 21

    ftp = FTP()
    ftp.connect(host, port)
    ftp.login('gerard', 'educem123')
    return ftp

from app import app, db
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)