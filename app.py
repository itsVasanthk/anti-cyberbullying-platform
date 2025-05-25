from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import joblib
from datetime import datetime
from preprocessing import clean_text  # <-- Import your preprocessing function

# Initialize the Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
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

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password, password)


# Report model
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reported_by = db.Column(db.String(150))
    offender_username = db.Column(db.String(150))
    offender_profile = db.Column(db.String(300))
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Pending')  # New field


# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# India-specific helpline data
INDIA_HELPLINES = [
    {
        "name": "Cyber Crime India (MHA)",
        "contact": "155260",
        "website": "https://cybercrime.gov.in",
        "description": "Official portal to report cyberbullying crimes",
        "type": "legal"
    },
    {
        "name": "Childline India (for minors)",
        "contact": "1098",
        "website": "https://www.childlineindia.org",
        "description": "24/7 helpline for children facing abuse or bullying",
        "type": "child_protection"
    },
    {
        "name": "iCall Psychosocial Helpline",
        "contact": "9152987821",
        "website": "https://icallhelpline.org",
        "description": "Mental health support by Tata Institute",
        "type": "mental_health"
    },
    {
        "name": "National Commission for Women",
        "contact": "7827170170",
        "website": "https://ncw.nic.in",
        "description": "Women-specific cyber harassment support",
        "type": "legal"
    }
]

# Home route with prediction and helplines
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        message = request.form["message"]
        if message:
            cleaned_message = clean_text(message)
            msg_vector = vectorizer.transform([cleaned_message])
            prediction = model.predict(msg_vector)[0]
            result = "Bullying Detected 🚨" if prediction == 1 else "Not Bullying ✅"
    return render_template("index.html", 
                         result=result,
                         helplines=INDIA_HELPLINES)


# Report route
@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    message = None
    if request.method == "POST":
        offender_username = request.form.get("offender_username")
        offender_profile = request.form.get("offender_profile")
        report_text = request.form.get("report_text")
        reported_by = current_user.username

        if report_text:
            report_entry = Report(
                reported_by=reported_by,
                offender_username=offender_username,
                offender_profile=offender_profile,
                message=report_text
            )
            db.session.add(report_entry)
            db.session.commit()
            message = "Thank you for your report. We will review it shortly."

    return render_template("report.html", message=message)


# Support page (redirects to helplines)
@app.route("/support")
def support():
    return redirect(url_for("helplines"))


# Profile page
@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", name=current_user.username)


# Login
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


# Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash("Username or Email already exists.")
            return redirect(url_for('signup'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! You can now log in.")
        return redirect(url_for('login'))

    return render_template("signup.html")


# Logout
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("login"))


# Admin Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_admin:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for("home"))

    reports = Report.query.order_by(Report.timestamp.desc()).all()
    return render_template("dashboard.html", reports=reports)


@app.route("/update_status/<int:report_id>", methods=["POST"])
@login_required
def update_status(report_id):
    if not current_user.is_admin:
        flash("Unauthorized action", "danger")
        return redirect(url_for("home"))

    new_status = request.form.get("status")
    report = Report.query.get_or_404(report_id)
    report.status = new_status
    db.session.commit()
    flash(f"Status updated to {new_status}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/user_dashboard")
@login_required
def user_dashboard():
    user_reports = Report.query.filter_by(reported_by=current_user.username).order_by(Report.timestamp.desc()).all()
    return render_template("user_dashboard.html", reports=user_reports)


# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)