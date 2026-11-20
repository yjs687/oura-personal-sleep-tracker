
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "Oura Personal Sleep Tracker is running."

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/oauth/callback")
def oauth_callback():
    error = request.args.get("error")
    if error:
        return "Oura authorization was not completed.", 400

    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        return "Missing OAuth authorization parameters.", 400

    # The authorization code will be securely exchanged
    # for tokens in the next development step.
    return (
        "Oura authorization callback received. "
        "You may close this page."
    )
