from flask import Flask, request
from pathlib import Path
from waitress import serve

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 800 * 1024 * 1024 * 1024

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

@app.route("/scan", methods=["POST"])
def scan():
    filename = request.headers.get("X-Filename")
    if not filename:
        return "Missing filename header", 400

    dest = UPLOAD_DIR / filename
    chunk_size = 256 * 1024

    with open(dest, "wb") as f:
        while True:
            chunk = request.stream.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)

    return "File received", 200


print("Starting server...")
# serve(app, host="0.0.0.0", port=65432, channel_timeout=1000000, asyncore_loop_timeout=5, connection_limit=1000)
app.run(host="0.0.0.0", port=65432)
