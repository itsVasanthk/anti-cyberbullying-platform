from flask import Flask, render_template, request, jsonify
import joblib

app = Flask(__name__)

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
        # Save the report or just acknowledge it
        message = "Thank you for your report. We will review it shortly."
    return render_template("report.html", message=message)

@app.route("/support")
def support():
    return render_template("support.html")

@app.route("/profile")
def profile():
    return "User Profile Page"

@app.route("/login")
def login():
    return "Login Page"
if __name__ == "__main__":
    app.run(debug=True)
