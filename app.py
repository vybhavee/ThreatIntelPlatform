from flask import Flask, render_template
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db = client["threat_intel_db"]
collection = db["threat_indicators"]

@app.route('/')
def dashboard():
    threats = list(collection.find().sort("timestamp", -1))
    total = len(threats)
    blocked = len([t for t in threats if t.get("blocked")])
    active = total - blocked
    return render_template('dashboard.html', threats=threats, total=total, blocked=blocked, active=active)

if __name__ == '__main__':
    app.run(debug=True, port=5000)