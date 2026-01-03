import sys
import logging
import json
import threading
import re
import hashlib
import time
import uuid
import requests
import subprocess
import webbrowser
import os
import base64
import io
import sqlite3
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from neonize.client import NewClient
from neonize.events import ConnectedEv, MessageEv, PairStatusEv, LoggedOutEv
from neonize.types import MessageServerID
from neonize.utils import log
from datetime import timedelta
import smtplib
from email.mime.text import MIMEText
from groq import Groq
import qrcode
import datetime

def get_ist_time():
    try:
        # Try fetching from WorldTimeAPI
        response = requests.get("http://worldtimeapi.org/api/timezone/Asia/Kolkata", timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Extract HH:MM from datetime string (e.g., "2023-10-27T14:30:00.123456+05:30")
            dt_str = data["datetime"]
            dt_obj = datetime.datetime.fromisoformat(dt_str)
            return dt_obj.strftime("%H:%M")
    except Exception as e:
        print(f"Error fetching IST time: {e}")
    return None

# --- CONFIGURATION ---
SECURITY_URL = "https://gist.githubusercontent.com/vijaykumarpallerla/4973d166642851341aa855a6169d2f5d/raw/gistfile1.txt"

# --- FLASK APP SETUP ---
app = Flask(__name__)
app.secret_key = "super_secret_key_change_this_in_production"  # Required for sessions
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# --- DATA STORAGE PATHS ---
APP_FOLDER = os.path.dirname(os.path.abspath(__file__))
LOCAL_APPDATA = os.getenv('LOCALAPPDATA')
USER_DATA_FOLDER = os.path.join(LOCAL_APPDATA, "WhatsappApp")
os.makedirs(USER_DATA_FOLDER, exist_ok=True)

# Database for Users (Username/Password)
USERS_DB_FILE = os.path.join(USER_DATA_FOLDER, "users.db")

# --- GLOBAL MANAGERS ---
# Active Clients: { user_id: ClientInstance }
active_clients = {}
# QR Data: { user_id: {"code": "base64...", "connected": False} }
qr_data_store = {}
# Group Messages: { user_id: { group_jid: [msgs] } }
user_messages = {}

# --- DATABASE FUNCTIONS ---
def get_db_connection():
    conn = sqlite3.connect(USERS_DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # Create table with email column if not exists
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT, password TEXT)''')
        
        # Migration: Check if email column exists, if not add it (for existing DBs)
        c.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in c.fetchall()]
        if "email" not in columns:
            print("Migrating DB: Adding email column...")
            try:
                c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            except Exception as e:
                print(f"Migration Error: {e}")
                
        conn.commit()
    except Exception as e:
        print(f"DB Init Error: {e}")
    finally:
        if conn:
            conn.close()

def get_user(username):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        return user
    except Exception as e:
        print(f"DB Error (get_user): {e}")
        return None
    finally:
        if conn:
            conn.close()

def get_user_by_email(email):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        return user
    except Exception as e:
        print(f"DB Error (get_user_by_email): {e}")
        return None
    finally:
        if conn:
            conn.close()

def create_user(username, email, password):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        hashed_pw = generate_password_hash(password)
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_pw))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        print(f"DB Error (create_user): {e}")
        return False
    finally:
        if conn:
            conn.close()

def update_password(user_id, new_password):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        hashed_pw = generate_password_hash(new_password)
        c.execute("UPDATE users SET password=? WHERE id=?", (hashed_pw, user_id))
        conn.commit()
    except Exception as e:
        print(f"DB Error (update_password): {e}")
    finally:
        if conn:
            conn.close()

# --- USER CONFIG MANAGEMENT ---
def get_user_config_path(user_id):
    user_folder = os.path.join(USER_DATA_FOLDER, f"user_{user_id}")
    os.makedirs(user_folder, exist_ok=True)
    return os.path.join(user_folder, "config.json")

def get_user_db_path(user_id):
    user_folder = os.path.join(USER_DATA_FOLDER, f"user_{user_id}")
    os.makedirs(user_folder, exist_ok=True)
    return os.path.join(user_folder, "cognitive.db")

def load_user_config(user_id):
    path = get_user_config_path(user_id)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            pass
    return {
        "email_user": "",
        "email_pass": "",
        "dest_email": "",
        "allowed_jids": [],
        "groq_api_key": "",
        "auto_allow": False,
        "start_time": "09:00",
        "end_time": "18:00"
    }

def save_user_config(user_id, config):
    path = get_user_config_path(user_id)
    with open(path, "w") as f:
        json.dump(config, f, indent=4)

# --- BOT LOGIC (Per User) ---
def start_bot_for_user(user_id):
    if user_id in active_clients:
        return # Already running

    print(f"Starting bot for User ID: {user_id}")
    
    db_path = get_user_db_path(user_id)
    client = NewClient(db_path)
    
    # Initialize storage for this user
    if user_id not in qr_data_store:
        qr_data_store[user_id] = {"code": None, "connected": False}
    if user_id not in user_messages:
        user_messages[user_id] = {}

    # --- EVENT HANDLERS ---
    @client.qr
    def handle_qr(client, qr_code_string):
        try:
            print(f"[User {user_id}] QR Code Received")
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(qr_code_string)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            
            qr_data_store[user_id]["code"] = img_str
            qr_data_store[user_id]["connected"] = False
        except Exception as e:
            print(f"QR Error: {e}")

    @client.event(ConnectedEv)
    def on_connected(client, event):
        print(f"[User {user_id}] Connected!")
        qr_data_store[user_id]["connected"] = True
        qr_data_store[user_id]["code"] = None

    @client.event(LoggedOutEv)
    def on_logged_out(client, event):
        print(f"[User {user_id}] Logged Out via Phone!")
        
        # 1. Delete session file
        if os.path.exists(db_path):
            try:
                client.disconnect() # Ensure it's closed
                os.remove(db_path)
                print(f"[User {user_id}] Session file deleted.")
            except Exception as e:
                print(f"[User {user_id}] Error cleaning up: {e}")
        
        # 2. Reset store
        qr_data_store[user_id] = {"code": None, "connected": False}
        
        # 3. Remove from active clients so it restarts on next poll
        if user_id in active_clients:
            del active_clients[user_id]

    @client.event(MessageEv)
    def on_message(client, message):
        # 1. GET INFO
        chat_id = message.Info.MessageSource.Chat
        jid = chat_id.User
        is_group = "g.us" in str(chat_id)
        text = message.Message.conversation or message.Message.extendedTextMessage.text
        
        # 2. Store Group Messages
        if is_group and text:
            timestamp = time.strftime("%I:%M %p")
            sender_name = getattr(message.Info, "PushName", getattr(message.Info, "push_name", "Unknown"))
            
            if jid not in user_messages[user_id]:
                user_messages[user_id][jid] = []
            
            user_messages[user_id][jid].append({
                "text": text,
                "timestamp": timestamp,
                "sender": sender_name
            })
            # Keep last 50
            if len(user_messages[user_id][jid]) > 50:
                user_messages[user_id][jid] = user_messages[user_id][jid][-50:]

        # 3. Process Logic (Whitelist + AI)
        config = load_user_config(user_id)
        allowed_jids = {item["jid"] for item in config.get("allowed_jids", [])}
        
        # --- AUTO-ALLOW & TIME CHECK ---
        should_process = False
        if config.get("auto_allow", False):
            try:
                # Fetch IST Time
                ist_time_str = get_ist_time()
                if ist_time_str:
                    current_time = time.strptime(ist_time_str, "%H:%M")
                    start_time = time.strptime(config.get("start_time", "09:00"), "%H:%M")
                    end_time = time.strptime(config.get("end_time", "18:00"), "%H:%M")
                    
                    if start_time <= current_time <= end_time:
                        should_process = True
                    else:
                        print(f"[User {user_id}] Message skipped: Outside allowed time window ({ist_time_str})")
                else:
                    print(f"[User {user_id}] Message skipped: Could not fetch IST time")
            except Exception as e:
                print(f"[User {user_id}] Time Check Error: {e}")
        else:
            print(f"[User {user_id}] Message skipped: Auto-Allow is OFF")

        if should_process and str(jid) in allowed_jids and text:
            print(f"[User {user_id}] Processing message from {jid}")
            # ... (AI Logic would go here, simplified for now) ...
            
    # Connect in a separate thread to not block
    def run_client():
        try:
            client.connect()
        except Exception as e:
            print(f"[User {user_id}] Client Error: {e}")

    thread = threading.Thread(target=run_client, daemon=True)
    thread.start()
    
    active_clients[user_id] = client

# --- FLASK ROUTES ---

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user_id = session["user_id"]
    config = load_user_config(user_id)
    
    # Ensure bot is running
    if user_id not in active_clients:
        start_bot_for_user(user_id)
        
    return render_template("index.html", config=config, username=session.get("username"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = get_user(username)
        
        if user:
            # Handle both old schema (id, username, password) and new schema (id, username, email, password)
            password_hash = user[3] if len(user) > 3 else user[2]
            
            if check_password_hash(password_hash, password):
                session["user_id"] = user[0]
                session["username"] = user[1]
                return redirect(url_for("index"))
            else:
                return render_template("login.html", error="Invalid credentials")
        else:
            return render_template("login.html", error="Invalid credentials")
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        
        if password != confirm:
            return render_template("register.html", error="Passwords do not match")
            
        if create_user(username, email, password):
            flash("Account created! Please login.")
            return redirect(url_for("login"))
        else:
            return render_template("register.html", error="Username already exists")
            
    return render_template("register.html")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = get_user_by_email(email)
        
        if user:
            session["reset_user_id"] = user[0]
            return redirect(url_for("reset_password"))
        else:
            return render_template("forgot_password.html", error="Email not found")
            
    return render_template("forgot_password.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if "reset_user_id" not in session:
        return redirect(url_for("login"))
        
    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        
        if password != confirm:
            return render_template("reset_password.html", error="Passwords do not match")
            
        user_id = session["reset_user_id"]
        update_password(user_id, password)
        session.pop("reset_user_id", None) # Clear the reset session
        
        return render_template("login.html", message="Password updated successfully! Please login.")
        
    return render_template("reset_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/save", methods=["POST"])
def save():
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    user_id = session["user_id"]
    config = load_user_config(user_id)
    
    config["email_user"] = request.form.get("email_user")
    config["email_pass"] = request.form.get("email_pass")
    config["dest_email"] = request.form.get("dest_email")
    config["groq_api_key"] = request.form.get("groq_api_key")
    
    # Auto-Allow Settings
    config["auto_allow"] = "auto_allow" in request.form
    config["start_time"] = request.form.get("start_time")
    config["end_time"] = request.form.get("end_time")
    
    # Handle Whitelist
    jids = request.form.getlist("jids")
    names = request.form.getlist("names")
    new_whitelist = []
    for jid, name in zip(jids, names):
        if jid.strip():
            new_whitelist.append({"jid": jid.strip(), "name": name.strip()})
    config["allowed_jids"] = new_whitelist
    
    save_user_config(user_id, config)
    return redirect(url_for("index", message="Configuration Saved!", status="success"))

@app.route("/whatsapp")
def whatsapp():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("whatsapp.html")

@app.route("/qr_status")
def qr_status():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session["user_id"]
    # Ensure bot is started
    if user_id not in active_clients:
        start_bot_for_user(user_id)
        
    return jsonify(qr_data_store.get(user_id, {"code": None, "connected": False}))

@app.route("/group_messages")
def get_group_messages():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    user_id = session["user_id"]
    msgs = user_messages.get(user_id, {})
    
    config = load_user_config(user_id)
    allowed_jids = {item["jid"] for item in config.get("allowed_jids", [])}
    
    response = {}
    for group_id, messages in msgs.items():
        response[group_id] = {
            "whitelisted": group_id in allowed_jids,
            "messages": messages[-3:] if len(messages) > 3 else messages
        }
    return jsonify(response)

@app.route("/add_to_whitelist", methods=["POST"])
def add_to_whitelist():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    user_id = session["user_id"]
    data = request.json
    group_id = data.get("group_id")
    
    config = load_user_config(user_id)
    allowed_jids = [str(item["jid"]) for item in config.get("allowed_jids", [])]
    
    if str(group_id) not in allowed_jids:
        config["allowed_jids"].append({"jid": str(group_id), "name": f"Group {str(group_id)[:10]}"})
        save_user_config(user_id, config)
        return jsonify({"success": True})
        
    return jsonify({"success": False, "message": "Already whitelisted"})

@app.route("/remove_from_whitelist", methods=["POST"])
def remove_from_whitelist():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    user_id = session["user_id"]
    data = request.json
    group_id = data.get("group_id")
    
    config = load_user_config(user_id)
    config["allowed_jids"] = [item for item in config.get("allowed_jids", []) if str(item["jid"]) != str(group_id)]
    save_user_config(user_id, config)
    
    return jsonify({"success": True})

@app.route("/disconnect_whatsapp", methods=["POST"])
def disconnect_whatsapp():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    user_id = session["user_id"]
    
    # 1. Stop the client if running
    if user_id in active_clients:
        try:
            active_clients[user_id].disconnect()
        except:
            pass
        del active_clients[user_id]
        
    # 2. Clear QR Data
    if user_id in qr_data_store:
        del qr_data_store[user_id]
        
    # 3. Delete Session File (Force new QR)
    db_path = get_user_db_path(user_id)
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            print(f"[User {user_id}] Session file deleted for fresh login.")
        except Exception as e:
            print(f"[User {user_id}] Error deleting session file: {e}")
            
    return jsonify({"success": True})

# --- MAIN ---
if __name__ == "__main__":
    init_db()
    print("Multi-User WhatsApp Manager Running...")
    app.run(host="0.0.0.0", port=5000, debug=True)