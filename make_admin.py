from app import app, db, User 
with app.app_context():
    user = User.query.filter_by(username='josep').first()
    if user:
        user.is_admin = True
        db.session.commit()
        print(f"El usuario '{user.username}' ahora es administrador.")
    else:
        print("Usuario no encontrado.")