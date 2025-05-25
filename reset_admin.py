from app import app, db, User
from werkzeug.security import generate_password_hash

def reset_admin():
    with app.app_context():
        # Set your desired credentials
        new_username = "admin"
        new_password = "admin123"  # Change to a stronger password!
        new_email = "admin@example.com"

        # Check if admin exists
        admin = User.query.filter_by(is_admin=True).first()
        
        if admin:
            # Update existing admin
            admin.username = new_username
            admin.password = generate_password_hash(new_password)
            admin.email = new_email
            db.session.commit()
            print(f"✔ Admin updated! Username: {new_username}, Password: {new_password}")
        else:
            # Create new admin
            new_admin = User(username=new_username, email=new_email, is_admin=True)
            new_admin.set_password(new_password)
            db.session.add(new_admin)
            db.session.commit()
            print(f"✔ New admin created! Username: {new_username}, Password: {new_password}")

if __name__ == "__main__":
    reset_admin()