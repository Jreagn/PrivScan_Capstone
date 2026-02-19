from flask import Flask, request
from pathlib import Path
from waitress import serve

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

@app.route("/scan", methods=["POST"])
def scan():
    print("Request received")
    if "file" not in request.files:
        return "No file field", 400
    f = request.files["file"]
    f.save(UPLOAD_DIR / f.filename)
    print(f"Saved: {f.filename}")
    return "File received", 200

print("Starting server...")
serve(app, host="0.0.0.0", port=65432)