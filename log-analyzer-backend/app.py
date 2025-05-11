import os
from flask import Flask,session
from flask_cors import CORS
from flask import request, jsonify,session,make_response
from functools import wraps
import joblib
import psycopg2
from werkzeug.utils import secure_filename
import csv
from datetime import datetime
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = os.getenv('bd2b11b6619618c12fc9b7816c054cd15c6fb1b055a9652747b11cdb4fa23ceb',"secret_key")
CORS(app, supports_credentials=True, origins=["http://localhost:3000","https://log-analyzer-frontend.onrender.com"])
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:MastersUS24!123@localhost/log_analysis")

def requires_auth(auth):
    @wraps(auth)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return auth(*args, **kwargs)
    return decorated

def get_db_connection():
    connection = psycopg2.connect(DATABASE_URL)
    return connection

# Create database table to store log files
def create_logs_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS logs (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP,
                        device TEXT,
                        protocol TEXT,
                        url TEXT,
                        action TEXT,
                        application TEXT,
                        category TEXT,
                        source_ip TEXT,
                        destination_ip TEXT,
                        http_method TEXT,
                        status_code TEXT,
                        user_agent TEXT,
                        username TEXT,
                        threat TEXT)
                ''')
    conn.commit()
    cursor.close()
    conn.close()
    
# Create database table to store user information
def create_users_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL )
                ''')
    conn.commit()
    cursor.close()
    conn.close()

create_logs_table()
create_users_table()

@app.route('/')
def home():
    return 'Welcome'

# API to register user
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    hashed = generate_password_hash(password)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed))
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except psycopg2.Error as e:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        cur.close()
        conn.close()

# API to login a user post registration
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
    result = cur.fetchone()
    cur.close()
    conn.close()

    if result and check_password_hash(result[0], password):
        session['user'] = username
        print(f"Session data: {session}")
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# API to check is user is logged in
@app.route('/check-auth')
def check_auth():
    if 'user' in session:
        return jsonify({'loggedIn': True, 'user': session['user']})
    else:
        return jsonify({'loggedIn': False}), 401

# API which enables user to upload log files for analysis
@app.route('/upload', methods=['POST'])
@requires_auth
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify({'message': 'File uploaded successfully', 'filename': filename})

# Function to parse the log file that is uploaded
def parse_zscaler_log(file_path):
    events = []
    threat_counts = defaultdict(int)

    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 26:
                continue
            timestamp = row[0]
            device = row[1]
            protocol = row[2]
            url = row[3]
            action = row[4]
            app_name = row[5]
            category = row[6]
            source_ip = row[21]
            destination_ip = row[22]
            http_method = row[23]
            status_code = row[24]
            user_agent = row[25]
            threat = row[14] 
            user = row[19]    

            event = {
                        "timestamp": timestamp,
                        "device": device,
                        "protocol": protocol,
                        "url": url,
                        "action": action,
                        "application": app_name,
                        "category": category,
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "http_method": http_method,
                        "status_code": status_code,
                        "user_agent": user_agent,
                        "user": user,
                        "threat": threat
                    }
            events.append(event)

            if threat and threat.lower() != "none":
                threat_counts[threat] += 1

    summary = {
                "total_events": len(events),
                "total_threats": sum(threat_counts.values()),
                "top_threats": dict(sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:5])
            }

    return {"summary": summary, "timeline": events}

# Function to save parse log files to database
def save_logs_to_db(events):
    conn = get_db_connection()
    cursor = conn.cursor()
    for event in events:
        cursor.execute('''
            INSERT INTO logs (timestamp, device, protocol, url, action, application, category, source_ip, destination_ip, http_method, status_code, user_agent, username, threat)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            event['timestamp'], event['device'], event['protocol'], event['url'],
            event['action'], event['application'], event['category'], event['source_ip'],
            event['destination_ip'], event['http_method'], event['status_code'], event['user_agent'],
            event['user'], event['threat']
        ))
    conn.commit()
    cursor.close()
    conn.close()

# API to give analysis of uploaded log files
@app.route('/analyze-zscaler', methods=['POST'])
@requires_auth
def analyze_zscaler():
    data = request.get_json()
    filename = data.get('filename')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    results = parse_zscaler_log(file_path)
    events = results["timeline"]

    save_logs_to_db(events)

    blocked_events = [event for event in events if event.get("action") == "Blocked"]
    threat_blocked_events = [
    event for event in blocked_events
    if event.get("threat") and event.get("threat").lower() != "none"
    ]
    other_blocked_events = [
    event for event in blocked_events
    if not event.get("threat") or event.get("threat").lower() == "none"
    ]

    additional_note = None
    if other_blocked_events:
        additional_note = f"There were {len(other_blocked_events)} events that were blocked but not classified as known threats."

    return jsonify({
    "summary": results["summary"],
    "blocked_threats": [
        {
            "timestamp": event.get("timestamp"),
            "url": event.get("url"),
            "threat": event.get("threat"),
            "user": event.get("device", "Unknown")
        }
        for event in threat_blocked_events
    ],
     "note": additional_note,
})

# API to analyze log files uploaded in the past
@app.route('/analyze-db-logs', methods=['GET'])
@requires_auth
def analyze_db_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
                    SELECT timestamp,url,source_ip,threat
                    FROM logs 
                    WHERE action = 'Blocked'
                    LIMIT 15
                ''')
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    blocked_threats = []
    for row in rows:
        blocked_threats.append({
            "timestamp": row[0],
            "url": row[1],
            "source_ip":row[2],
            "threat":row[3]
            })
    #print(blocked_threats)
    return jsonify(blocked_threats)

#API to logout a user
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    resp = make_response(jsonify({'message': 'Logged out successfully'}), 200)
    resp.set_cookie('session', '', expires=0)
    return resp

if __name__ == '__main__':
    app.run()