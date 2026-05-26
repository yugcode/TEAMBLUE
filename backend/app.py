from flask import Flask, request, jsonify
from flask_cors import CORS
from core.ingestor import ingest_stream
from core.mapper import map_events
from core.scorer import score_events, coverage_summary

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return jsonify({"message": "Backend Running"})


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    events = ingest_stream(file.stream, file.filename)
    mapped = map_events(events)
    scored = score_events(mapped)
    summary = coverage_summary(scored)

    return jsonify({
        "summary": summary,
        "events": scored
    })


if __name__ == "__main__":
    app.run(debug=True)
