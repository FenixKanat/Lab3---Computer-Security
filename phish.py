from flask import Flask, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder="templates")
CORS(app)

@app.route("/")
def index():
    return render_template("phish.html")

if __name__ == "__main__":
    print("Serving evil site at http://evil.test:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
