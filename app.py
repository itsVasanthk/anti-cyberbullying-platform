from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import joblib

# Initialize the Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize the database and migration extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Load ML model and vectorizer
model = joblib.load("bullying_detection_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# User model for Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password, password)

# Load user by ID for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        message = request.form["message"]
        if message:
            msg_vector = vectorizer.transform([message])
            prediction = model.predict(msg_vector)[0]
            result = "Bullying Detected 🚨" if prediction == 1 else "Not Bullying ✅"
    return render_template("index.html", result=result)

@app.route("/report", methods=["GET", "POST"])
def report():
    message = None
    if request.method == "POST":
        message = "Thank you for your report. We will review it shortly."
    return render_template("report.html", message=message)

@app.route("/support")
def support():
    return render_template("support.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", name=current_user.username)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!")
            return redirect(url_for("profile"))
        else:
            flash("Login failed. Check your username and/or password.")

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Check for existing user
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash("Username or Email already exists.")
            return redirect(url_for('signup'))

        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! You can now log in.")
        return redirect(url_for('login'))

    return render_template("signup.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("login"))

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure the database is created
    app.run(debug=True)
