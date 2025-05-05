from flask import Flask, render_template, request, redirect, flash, url_for, session
from models import db, User
import joblib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
db.init_app(app)

# Load ML model and vectorizer
model = joblib.load("bullying_detection_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

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
def profile():
    return "User Profile Page"

@app.route("/login", methods=["GET", "POST"])
def login():
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

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
