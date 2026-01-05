import sys
import logging
import json
import threading
import hashlib
import time
import uuid
import requests
import subprocess
import webbrowser
import os
import base64
import io
import psycopg2
from psycopg2.extras import RealDictCursor
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, Response, stream_with_context, send_file
from werkzeug.security import generate_password_hash, check_password_hash # Keeping for safety, though unused
from neonize.client import NewClient
from neonize.events import ConnectedEv, MessageEv, PairStatusEv, LoggedOutEv, QREv
from neonize.types import MessageServerID
from neonize.utils import log
from datetime import timedelta
import socket
# import smtplib # Removed SMTP
# from email.mime.text import MIMEText # Removed SMTP MIME
from groq import Groq
import qrcode
import datetime
import re
try:
    import redis
except Exception:
    redis = None

# Load .env (prefer python-dotenv, fallback to manual parser)
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded .env via python-dotenv", flush=True)
except Exception:
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        k, v = line.split('=', 1)
                        v = v.strip()
                        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                            v = v[1:-1]
                        os.environ.setdefault(k.strip(), v)
            print("Loaded .env manually", flush=True)
        except Exception as e:
            print(f"Error loading .env: {e}", flush=True)

# Ensure stdout/stderr use UTF-8 to avoid UnicodeEncodeError on Windows consoles
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    os.environ.setdefault('PYTHONIOENCODING', 'utf-8')

# --- GOOGLE AUTH IMPORTS ---
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

# --- CONFIGURATION ---
# Database Connection
DB_URL = os.environ.get("DATABASE_URL")

if not DB_URL:
    # For local testing, you must set this env var or uncomment the line below (TEMPORARILY)
    # DB_URL = "postgresql://neondb_owner:npg_Dqx2nsVjg0Ol@ep-flat-sky-ad2jtyax-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
    print("CRITICAL ERROR: DATABASE_URL environment variable is not set.")

# Google Auth Configuration
CLIENT_SECRETS_FILE = "google.json"

# Create google.json from environment variable if it doesn't exist (For Render)
if not os.path.exists(CLIENT_SECRETS_FILE):
    google_json_env = os.environ.get("GOOGLE_JSON")
    if google_json_env:
        try:
            with open(CLIENT_SECRETS_FILE, "w") as f:
                f.write(google_json_env)
            print("Created google.json from environment variable.")
        except Exception as e:
            print(f"Error creating google.json: {e}")

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.send",
    "openid"
]

def get_ist_time():
    try:
        # Calculate IST: UTC + 5:30
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        ist_now = utc_now + timedelta(hours=5, minutes=30)
        return ist_now.strftime("%H:%M")
    except Exception as e:
        print(f"Error calculating IST time: {e}")
    return None

# --- HELPER FUNCTIONS ---

def get_google_creds(user_id):
    """Retrieve and refresh Google Credentials for a user."""
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT google_token FROM users WHERE id=%s", (user_id,))
        row = c.fetchone()
        
        if not row or not row['google_token']:
            return None
            
        token_data = json.loads(row['google_token'])
        creds = Credentials.from_authorized_user_info(token_data, SCOPES)
        
        if creds and creds.expired and creds.refresh_token:
            print("Refreshing Google Token...", flush=True)
            creds.refresh(Request())
            # Save refreshed token back to DB
            c.execute("UPDATE users SET google_token=%s WHERE id=%s", (creds.to_json(), user_id))
            conn.commit()
            
        return creds
    except Exception as e:
        print(f"Auth Error: {e}", flush=True)
        return None
    finally:
        if conn:
            conn.close()

def send_email(config, subject, body, reply_to=None):
    """Send email using Gmail API."""
    try:
        # We need the user_id to fetch credentials. 
        # Since this function is called from the main loop, we need to pass user_id in config or arguments.
        # Assuming config now has 'user_id'
        user_id = config.get("user_id")
        dest_email = config.get("dest_email")

        if not user_id or not dest_email:
            print("Email configuration missing (user_id or dest_email).", flush=True)
            return False

        creds = get_google_creds(user_id)
        if not creds:
            print("No valid Google Credentials found for user.", flush=True)
            return False

        service = build('gmail', 'v1', credentials=creds)

        message_text = f"To: {dest_email}\nSubject: {subject}\n\n{body}"
        if reply_to:
             message_text = f"Reply-To: {reply_to}\n" + message_text
             
        raw_message = base64.urlsafe_b64encode(message_text.encode("utf-8")).decode("utf-8")
        message = {'raw': raw_message}

        sent_message = service.users().messages().send(userId="me", body=message).execute()
        print(f"Email sent to {dest_email} (Msg ID: {sent_message['id']})", flush=True)
        return True

    except Exception as e:
        print(f"Gmail API Error: {e}", flush=True)
        return False

def analyze_message(api_key, text):
    try:
        client = Groq(api_key=api_key)
        prompt = f"""
        Analyze the following LinkedIn post text to determine if it is a valid USA Job Opening.

        STRICT REJECTION RULES (If any of these are true, "is_usa_hiring" MUST be false):
        1. Phone Numbers: If a phone/WhatsApp number is present, it MUST start with +1 (USA). If it starts with +91 or any other country code, REJECT IT immediately.
        2. Salary: If a salary is mentioned, it MUST be in Dollars ($). If it is in Rupees (₹), Lakhs, or implies a non-US monthly rate (e.g., "20k-50k monthly" without $ context), REJECT IT.
        3. Location: If the location is explicitly outside the USA, REJECT IT.

        CRITERIA FOR "is_usa_hiring" = true:
        - It MUST be a job opening/hiring.
        - It MUST be located in the USA (or imply USA context with $ salary / +1 phone).
        - IGNORE: Hotlists, Services, Achievements, Promotions, General News.
        - IGNORE: Job seekers asking for jobs.

        If it passes all rules, extract:
        - Job Role/Title (e.g., "Python Developer"). Use "Unknown Role" if not found.
        - Contact Email Address (if present). Use null if not found.

        Post Text:
        "{text[:3000]}" 
        
        Reply ONLY with a JSON object in this format:
        {{
            "is_usa_hiring": true/false,
            "role": "extracted role",
            "email": "extracted_email@example.com" or null
        }}
        """
        
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant that outputs only valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama-3.1-8b-instant",
            temperature=0
        )
        
        response_text = chat_completion.choices[0].message.content.strip()
        # Extract JSON if wrapped in code blocks
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if match:
            json_str = match.group(0)
            return json.loads(json_str)
            
    except Exception as e:
        print(f"AI Error: {e}", flush=True)
        
    return {"is_usa_hiring": False, "role": "Unknown", "email": None}

# --- FLASK APP SETUP ---
app = Flask(__name__)
app.secret_key = "super_secret_key_change_this_in_production"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Allow OAuth over HTTP for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 

# --- DATA STORAGE PATHS ---
APP_FOLDER = os.path.dirname(os.path.abspath(__file__))
USER_DATA_FOLDER = os.path.join(APP_FOLDER, "whatsapp_sessions")
os.makedirs(USER_DATA_FOLDER, exist_ok=True)

# --- REDIS / UPSTASH CONFIG ---
# Support multiple env var names and strip surrounding quotes (your .env uses
# UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN with quotes).
def _clean_env(v):
    if v is None:
        return None
    v = v.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v

REDIS_URL = _clean_env(os.environ.get('REDIS_URL') or os.environ.get('REDIS_TLS_URL'))
UPSTASH_REST_URL = _clean_env(os.environ.get('UPSTASH_REDIS_REST_URL') or os.environ.get('UPSTASH_REST_URL') or os.environ.get('UPSTASH_URL') or os.environ.get('UPSTASH_REDIS_URL'))
UPSTASH_REST_TOKEN = _clean_env(os.environ.get('UPSTASH_REDIS_REST_TOKEN') or os.environ.get('UPSTASH_REST_TOKEN') or os.environ.get('UPSTASH_TOKEN'))

redis_client = None
if REDIS_URL and redis:
    try:
        redis_client = redis.from_url(REDIS_URL)
        print("Initialized redis client from REDIS_URL", flush=True)
    except Exception as e:
        print(f"Redis init error: {e}", flush=True)
elif UPSTASH_REST_URL and UPSTASH_REST_TOKEN:
    print("Upstash REST configured; will use REST API for QR storage", flush=True)

# QR TTL (seconds) for storing QR in Redis/Upstash; default 300s
QR_TTL = int(_clean_env(os.environ.get('QR_TTL') or '300') or 300)

def set_qr_in_store(user_id, data_bytes, ttl=300):
    key = f"qr:{user_id}"
    try:
        if redis_client:
            redis_client.set(key, data_bytes, ex=ttl)
            return True
        if UPSTASH_REST_URL and UPSTASH_REST_TOKEN:
            url = UPSTASH_REST_URL.rstrip('/') + f"/set/{key}"
            b64 = base64.b64encode(data_bytes).decode()
            headers = {'Authorization': f'Bearer {UPSTASH_REST_TOKEN}'}
            resp = requests.post(url, json={"value": b64}, headers=headers, timeout=5)
            return resp.status_code == 200
    except Exception as e:
        print(f"set_qr_in_store error: {e}", flush=True)
    return False

def get_qr_from_store(user_id):
    key = f"qr:{user_id}"
    try:
        if redis_client:
            val = redis_client.get(key)
            if val:
                return val if isinstance(val, (bytes, bytearray)) else val.encode()
        if UPSTASH_REST_URL and UPSTASH_REST_TOKEN:
            url = UPSTASH_REST_URL.rstrip('/') + f"/get/{key}"
            headers = {'Authorization': f'Bearer {UPSTASH_REST_TOKEN}'}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                j = resp.json()
                v = j.get('result') or j.get('value') or j.get('result_raw') or j.get('value_raw')
                if v:
                    # Some Upstash responses store a JSON string as the value, e.g.
                    # { "result": "{\"value\": \"<base64>\"}" }
                    # Handle that case by parsing the nested JSON and extracting the inner base64 value.
                    if isinstance(v, str) and v.strip().startswith('{'):
                        try:
                            inner = json.loads(v)
                            inner_val = inner.get('value') or inner.get('result') or inner.get('value_raw') or inner.get('result_raw')
                            if inner_val:
                                try:
                                    return base64.b64decode(inner_val)
                                except Exception:
                                    return inner_val.encode()
                        except Exception:
                            # fallthrough to try decoding the original v
                            pass
                    try:
                        return base64.b64decode(v)
                    except Exception:
                        return v.encode()
    except Exception as e:
        print(f"get_qr_from_store error: {e}", flush=True)
    return None

def delete_qr_in_store(user_id):
    key = f"qr:{user_id}"
    try:
        if redis_client:
            redis_client.delete(key)
            return True
        if UPSTASH_REST_URL and UPSTASH_REST_TOKEN:
            url = UPSTASH_REST_URL.rstrip('/') + f"/del/{key}"
            headers = {'Authorization': f'Bearer {UPSTASH_REST_TOKEN}'}
            resp = requests.post(url, headers=headers, timeout=5)
            return resp.status_code == 200
    except Exception as e:
        print(f"delete_qr_in_store error: {e}", flush=True)
    return False

# --- GLOBAL MANAGERS ---
active_clients = {}
qr_data_store = {}

# --- DATABASE FUNCTIONS (NEON / POSTGRES) ---
def get_db_connection():
    conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    # If no DATABASE_URL is configured, skip DB initialization to allow
    # local testing without a Postgres server.
    if not DB_URL:
        print("DATABASE_URL not set — skipping DB initialization.", flush=True)
        return

    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # 1. Users Table (Modified for Google Auth)
        # We add google_token column if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id SERIAL PRIMARY KEY, username TEXT UNIQUE, email TEXT, password TEXT, google_token TEXT)''')
        
        try:
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_token TEXT")
        except:
            pass

        # 2. User Configs Table
        c.execute('''CREATE TABLE IF NOT EXISTS user_configs
                     (user_id INTEGER PRIMARY KEY REFERENCES users(id), config JSONB)''')
        
        # 3. Messages Table
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), 
                      group_jid TEXT, sender TEXT, text TEXT, timestamp TEXT, 
                      content_hash TEXT, sent_email BOOLEAN DEFAULT FALSE,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        try:
            c.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS content_hash TEXT")
            c.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_email BOOLEAN DEFAULT FALSE")
        except:
            pass
            
        conn.commit()
        print("Neon Database Initialized Successfully.")
    except Exception as e:
        print(f"DB Init Error: {e}")
    finally:
        if conn:
            conn.close()

def get_user_by_email(email):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = c.fetchone()
        return user
    except Exception as e:
        print(f"DB Error (get_user_by_email): {e}")
        return None
    finally:
        if conn:
            conn.close()

def create_or_update_google_user(email, token_json):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT id FROM users WHERE email=%s", (email,))
        existing = c.fetchone()
        
        if existing:
            user_id = existing['id']
            c.execute("UPDATE users SET google_token=%s WHERE id=%s", (token_json, user_id))
        else:
            # Create new user
            # Username is email for simplicity
            c.execute("INSERT INTO users (username, email, google_token) VALUES (%s, %s, %s) RETURNING id", 
                      (email, email, token_json))
            user_id = c.fetchone()['id']
            
            # Initialize default config
            default_config = {
                "dest_email": "", # Default to empty, user must set it
                "allowed_jids": [], "groq_api_key": "",
                "auto_allow": False, "start_time": "09:00", "end_time": "18:00"
            }
            c.execute("INSERT INTO user_configs (user_id, config) VALUES (%s, %s)", (user_id, json.dumps(default_config)))
            
        conn.commit()
        return user_id
    except Exception as e:
        print(f"DB Error (create_google_user): {e}")
        return None
    finally:
        if conn:
            conn.close()

def load_user_config(user_id):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT config FROM user_configs WHERE user_id=%s", (user_id,))
        res = c.fetchone()
        if res:
            config = res['config']
            config['user_id'] = user_id # Inject user_id for send_email
            return config
    except Exception as e:
        print(f"DB Error (load_config): {e}")
    finally:
        if conn:
            conn.close()
    return {"user_id": user_id}

def save_user_config(user_id, config):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE user_configs SET config=%s WHERE user_id=%s", (json.dumps(config), user_id))
        conn.commit()
    except Exception as e:
        print(f"DB Error (save_config): {e}")
    finally:
        if conn:
            conn.close()

def save_message(user_id, jid, sender, text, timestamp):
    conn = None
    try:
        content_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''INSERT INTO messages (user_id, group_jid, sender, text, timestamp, content_hash) 
                     VALUES (%s, %s, %s, %s, %s, %s)''', 
                  (user_id, str(jid), sender, text, timestamp, content_hash))
        conn.commit()
    except Exception as e:
        print(f"DB Error (save_message): {e}")
    finally:
        if conn:
            conn.close()

def is_duplicate_message(user_id, text):
    conn = None
    is_dup = False
    try:
        content_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM messages WHERE user_id=%s AND content_hash=%s", (user_id, content_hash))
        if c.fetchone():
            is_dup = True
    except Exception as e:
        print(f"DB Error (check_dup): {e}")
    finally:
        if conn:
            conn.close()
    return is_dup

def get_email_stats(user_id):
    conn = None
    stats = {"today": 0, "total": 0}
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM messages WHERE user_id=%s AND sent_email=TRUE", (user_id,))
        stats["total"] = c.fetchone()['count']
        
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        ist_now = utc_now + timedelta(hours=5, minutes=30)
        ist_start_of_day = ist_now.replace(hour=0, minute=0, second=0, microsecond=0)
        utc_start_of_day = ist_start_of_day - timedelta(hours=5, minutes=30)
        
        c.execute("SELECT COUNT(*) FROM messages WHERE user_id=%s AND sent_email=TRUE AND created_at >= %s", (user_id, utc_start_of_day))
        stats["today"] = c.fetchone()['count']
        
    except Exception as e:
        print(f"Stats Error: {e}")
    finally:
        if conn:
            conn.close()
    return stats

# --- WHATSAPP CLIENT MANAGEMENT ---
def get_client(user_id):
    print(f"Getting client for user {user_id}", flush=True)
    if user_id in active_clients:
        print("Returning active client", flush=True)
        return active_clients[user_id]
        print(f"WhatsApp Connected for user {user_id}", flush=True)

    # Create a per-user NewClient instance and register QR callback
    db_path = os.path.join(USER_DATA_FOLDER, f"whatsapp_session_{user_id}.db")
    try:
        client = NewClient(db_path)
    except Exception:
        # Fallback to unnamed client if DB path is not accepted
        client = NewClient()

    @client.qr
    def on_qr(client_obj, code_bytes: bytes):
        try:
            qr = qrcode.QRCode()
            qr.add_data(code_bytes)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffered = io.BytesIO()
            img.save(buffered, format='PNG')

            # Persist QR image to a file so other gunicorn workers / processes can serve it
            filename = f"qr_user_{user_id}.png"
            filepath = os.path.join(USER_DATA_FOLDER, filename)
            try:
                with open(filepath, 'wb') as f:
                    f.write(buffered.getvalue())
            except Exception:
                # If disk write fails, continue and rely on Redis/Upstash
                pass

            # Also store in shared store (Redis or Upstash REST) for multi-worker visibility
            try:
                set_qr_in_store(user_id, buffered.getvalue(), ttl=QR_TTL)
            except Exception as e:
                print(f"[User {user_id}] set_qr_in_store failed: {e}", flush=True)

            qr_data_store[user_id] = {"code": None, "connected": False, "file": filename}
            print(f"[User {user_id}] New QR Code Generated -> {filepath}", flush=True)
        except Exception as e:
            print(f"[User {user_id}] Error processing QR callback: {e}", flush=True)

    @client.event(PairStatusEv)
    def on_pair_status(client_obj, event: PairStatusEv):
        print(f"Pair Status: {event}", flush=True)
        try:
            # event.id.id indicates a successful login/pair
            if getattr(event, 'id', None) and getattr(event.id, 'id', None):
                # Mark connected and remove any saved QR file
                fn = qr_data_store.get(user_id, {}).get('file')
                if fn:
                    try:
                        os.remove(os.path.join(USER_DATA_FOLDER, fn))
                    except Exception:
                        pass
                    # remove from shared store as well
                    try:
                        delete_qr_in_store(user_id)
                    except Exception:
                        pass
                qr_data_store[user_id] = {"connected": True, "code": None, "file": None}
        except Exception as e:
            print(f"Error in on_pair_status handler: {e}", flush=True)

    @client.event(ConnectedEv)
    def on_connected(client_obj, event: ConnectedEv):
        print(f"Connected Event: {event}", flush=True)
        fn = qr_data_store.get(user_id, {}).get('file')
        if fn:
            try:
                os.remove(os.path.join(USER_DATA_FOLDER, fn))
            except Exception:
                pass
            try:
                delete_qr_in_store(user_id)
            except Exception:
                pass
        qr_data_store[user_id] = {"connected": True, "code": None, "file": None}

    @client.event(LoggedOutEv)
    def on_logged_out(client_obj, event: LoggedOutEv):
        fn = qr_data_store.get(user_id, {}).get('file')
        if fn:
            try:
                os.remove(os.path.join(USER_DATA_FOLDER, fn))
            except Exception:
                pass
            try:
                delete_qr_in_store(user_id)
            except Exception:
                pass
        qr_data_store[user_id] = {"connected": False, "code": None, "file": None}
        if user_id in active_clients:
            del active_clients[user_id]
        print(f"Logged out user {user_id}", flush=True)

    @client.event(MessageEv)
    def on_message(client_obj, event: MessageEv):
        try:
            print(f"DEBUG: Received MessageEv", flush=True)
            # Basic message handling logic
            config = load_user_config(user_id)
            if not config:
                return

            # Handle event.info vs event.Info
            info = getattr(event, 'info', getattr(event, 'Info', None))
            if not info:
                print(f"DEBUG: No info/Info in event: {dir(event)}", flush=True)
                return

            # Robust JID extraction
            source = getattr(info, 'message_source', getattr(info, 'MessageSource', None))
            if not source:
                print(f"DEBUG: No MessageSource in info: {dir(info)}", flush=True)
                return

            chat = getattr(source, 'chat', getattr(source, 'Chat', None))
            sender = getattr(source, 'sender', getattr(source, 'Sender', None))
            
            if not chat or not sender:
                 print(f"DEBUG: Missing chat/sender in source: {dir(source)}", flush=True)
                 return

            chat_jid = getattr(chat, 'user', getattr(chat, 'User', None)) or \
                       getattr(chat, '_serialized', getattr(chat, 'Serialized', None))
            
            sender_jid = getattr(sender, 'user', getattr(sender, 'User', None)) or \
                         getattr(sender, '_serialized', getattr(sender, 'Serialized', None))
            
            # Check if group is allowed
            allowed_jids = config.get("allowed_jids", [])
            # Normalize allowed_jids to set of strings
            allowed_set = set()
            for item in allowed_jids:
                if isinstance(item, dict):
                    allowed_set.add(item.get('jid'))
                else:
                    allowed_set.add(item)

            # --- CORRECTED LOGIC START ---
            
            # Determine if this is a group JID. Use a heuristic that matches common
            # WhatsApp group identifiers (e.g. ending with '@g.us' or numeric IDs that
            # start with '120'). This lets us store only group messages for the UI.
            def is_group_jid(jid):
                try:
                    s = str(jid)
                    if '@g.us' in s: return True
                    if s.startswith('120'): return True
                    # fallback: consider presence of 'g.' or 'group' as group
                    if 'g.' in s or 'group' in s.lower(): return True
                except Exception:
                    pass
                return False

            # If not a group, ignore (we only want groups in Recent Groups)
            if not is_group_jid(chat_jid):
                return

            # --- Saving vs Processing ---
            # Always save group messages so the Recent Groups UI can show them.
            # Keep AI/email processing gated by the existing toggles (auto_allow),
            # time window, and whitelist to avoid changing processing behaviour.
            
            message_text = ""
            
            # Robust Message Text Extraction
            msg_obj = getattr(event, 'message', getattr(event, 'Message', None))
            if msg_obj:
                conversation = getattr(msg_obj, 'conversation', getattr(msg_obj, 'Conversation', None))
                extended = getattr(msg_obj, 'extended_text_message', getattr(msg_obj, 'ExtendedTextMessage', None))
                
                if conversation:
                    message_text = conversation
                elif extended:
                    message_text = getattr(extended, 'text', getattr(extended, 'Text', None))
            
            if not message_text:
                return

            # Duplicate check
            if is_duplicate_message(user_id, message_text):
                print("Duplicate message ignored.")
                return

            # Save message
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_message(user_id, chat_jid, sender_jid, message_text, timestamp)
            
            # Analyze and Send Email
            analysis = analyze_message(config.get("groq_api_key"), message_text)
            if analysis.get("is_usa_hiring"):
                role = analysis.get('role', 'Unknown Role')
                extracted_email = analysis.get('email')
                
                subject = f"{{Whatsapp Alert}} New Job Found role {role}"
                body = f"Role: {role}\nEmail: {extracted_email}\n\nOriginal Post:\n{message_text}"
                
                send_email(config, subject, body, reply_to=extracted_email)

        except Exception as e:
            print(f"Message Error: {e}", flush=True)
            try:
                import traceback
                traceback.print_exc()
            except:
                pass

    active_clients[user_id] = client
    return client

# --- FLASK ROUTES ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/google_auth')
def google_auth():
    # Google OAuth Flow
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True))
    
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true', prompt='consent')
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session.get('state')
    if not state:
        return redirect(url_for('login'))
        
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state,
        redirect_uri=url_for('callback', _external=True))
        
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    
    # Get User Info
    service = build('oauth2', 'v2', credentials=creds)
    user_info = service.userinfo().get().execute()
    email = user_info.get('email')
    
    # Create/Update User in DB
    user_id = create_or_update_google_user(email, creds.to_json())
    session['user_id'] = user_id
    session['email'] = email
    
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    config = load_user_config(user_id)
    stats = get_email_stats(user_id)
    
    return render_template('index.html', config=config, stats=stats)


@app.route('/stats')
def stats():
    # Return email-send statistics for the current session user.
    user_id = session.get('user_id')
    if not user_id:
        # Return zeroed stats if no session (keeps frontend polling simple)
        return jsonify({"today": 0, "total": 0})

    stats = get_email_stats(user_id)
    return jsonify(stats)

@app.route('/update_config', methods=['POST'])
def update_config():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
    user_id = session['user_id']
    data = request.form.to_dict()
    
    config = load_user_config(user_id)
    
    # Update fields
    config['dest_email'] = data.get('dest_email', config.get('dest_email'))
    config['groq_api_key'] = data.get('groq_api_key', config.get('groq_api_key'))
    config['auto_allow'] = 'auto_allow' in data
    config['start_time'] = data.get('start_time', config.get('start_time'))
    config['end_time'] = data.get('end_time', config.get('end_time'))
    
    save_user_config(user_id, config)
    flash("Settings updated successfully!")
    return redirect(url_for('dashboard'))

@app.route('/connect_whatsapp')
def connect_whatsapp():
    print("Connect WhatsApp route hit", flush=True)
    if 'user_id' not in session:
        # If this is an AJAX/fetch call, return 401 JSON so the UI can redirect.
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    client = get_client(user_id)
    
    def start_client():
        print(f"Starting client thread for user {user_id}", flush=True)
        try:
            client.connect()
            print("Client connect() called", flush=True)
        except Exception as e:
            print(f"Client Connect Error: {e}", flush=True)
            
    threading.Thread(target=start_client, daemon=True).start()
    # If this was triggered via AJAX from the dashboard, return JSON so the UI
    # remains on the dashboard and can poll for the QR.
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'started'})

    return render_template('whatsapp.html')

@app.route('/qr_status')
def qr_status():
    # Return per-session QR status, fall back to session-less (None) entry
    user_id = session.get('user_id', None)
    data = qr_data_store.get(user_id)
    if data is None:
        data = qr_data_store.get(None, {"connected": False, "code": None})
        # If no in-memory QR found for this worker, try the shared store (Redis/Upstash)
        # This lets other workers generate the QR and still have this worker report it.
        try:
            if user_id is not None:
                stored = get_qr_from_store(user_id)
                if stored:
                    filename = f"qr_user_{user_id}.png"
                    data = {"connected": False, "code": None, "file": filename}
        except Exception:
            pass
    # If a filename is present, convert it to an accessible URL
    file_name = data.get('file') if isinstance(data, dict) else None
    result = {k: v for k, v in data.items()} if isinstance(data, dict) else data
    if file_name:
        try:
            result['file_url'] = url_for('qr_image', filename=file_name, _external=True)
        except Exception:
            result['file_url'] = None
    return jsonify(result)


@app.route('/qr_image/<path:filename>')
def qr_image(filename):
    # Serve QR images from USER_DATA_FOLDER. Prevent path traversal by resolving path.
    safe_path = os.path.join(USER_DATA_FOLDER, os.path.basename(filename))
    if not os.path.exists(safe_path):
        # If file not found on disk, try to fetch from Redis/Upstash when filename matches our pattern
        m = re.match(r'^qr_user_(\d+)\.png$', os.path.basename(filename))
        if m:
            uid = m.group(1)
            data = get_qr_from_store(uid)
            if data:
                return send_file(io.BytesIO(data), mimetype='image/png')
        return jsonify({'error': 'not found'}), 404
    return send_file(safe_path, mimetype='image/png')


@app.route('/qr_stream')
def qr_stream():
    # Server-Sent Events stream for real-time QR/connection status
    # Allow fallback to session-less stream (key None) so UI can receive
    # updates even if the client was started without a logged-in session.
    user_id = session.get('user_id', None)

    def event_stream(uid):
        last = None
        while True:
            try:
                data = qr_data_store.get(uid, {"connected": False, "code": None})
                # Only send when changed to reduce chatter
                if data != last:
                    yield f"data: {json.dumps(data)}\n\n"
                    last = data.copy() if isinstance(data, dict) else data
            except GeneratorExit:
                break
            except Exception as e:
                # If anything goes wrong, send a minimal error payload and continue
                try:
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"
                except Exception:
                    pass
            time.sleep(1)

    return Response(stream_with_context(event_stream(user_id)), mimetype='text/event-stream')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
    
@app.route('/toggle_group', methods=['POST'])
def toggle_group():
    if 'user_id' not in session:
        return jsonify({"status": "error"}), 401
        
    user_id = session['user_id']
    action = request.json.get('action')
    jid = request.json.get('jid')
    
    config = load_user_config(user_id)
    allowed = set(config.get('allowed_jids', []))
    
    if action == 'add':
        allowed.add(jid)
    elif action == 'remove' and jid in allowed:
        allowed.remove(jid)
        
    config['allowed_jids'] = list(allowed)
    save_user_config(user_id, config)
    
    return jsonify({"status": "success", "allowed_jids": list(allowed)})

@app.route('/group_messages')
def group_messages():
    if 'user_id' not in session:
        return jsonify({}), 401
    user_id = session['user_id']
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # Fetch last 100 messages to populate the feed
        c.execute("SELECT * FROM messages WHERE user_id=%s ORDER BY id DESC LIMIT 100", (user_id,))
        rows = c.fetchall()
        
        config = load_user_config(user_id)
        
        allowed_jids_raw = config.get('allowed_jids', [])
        allowed_set = set()
        for item in allowed_jids_raw:
            if isinstance(item, dict):
                allowed_set.add(item.get('jid'))
            else:
                allowed_set.add(item)
        
        grouped = {}
        for row in rows:
            gid = row['group_jid']
            if gid not in grouped:
                grouped[gid] = {
                    "whitelisted": gid in allowed_set,
                    "messages": []
                }
            grouped[gid]['messages'].append({
                "sender": row['sender'],
                "text": row['text'],
                "timestamp": row['timestamp']
            })
            
        # Reverse for chronological order (oldest to newest) so UI shows last one as latest
        for gid in grouped:
            grouped[gid]['messages'].reverse()
            
        return jsonify(grouped)
    except Exception as e:
        print(f"Group Messages Error: {e}")
        return jsonify({})
    finally:
        if conn: conn.close()

@app.route('/add_to_whitelist', methods=['POST'])
def add_to_whitelist():
    if 'user_id' not in session: return jsonify({"status": "error"}), 401
    user_id = session['user_id']
    data = request.json
    jid = data.get('group_id')
    
    config = load_user_config(user_id)
    allowed = config.get('allowed_jids', [])
    
    # Check if already exists
    exists = False
    for item in allowed:
        if isinstance(item, dict) and item.get('jid') == jid:
            exists = True
        elif item == jid:
            exists = True
            
    if not exists:
        # Add as object
        allowed.append({"jid": jid, "name": "Unknown"})
        config['allowed_jids'] = allowed
        save_user_config(user_id, config)
        
    return jsonify({"status": "success"})

@app.route('/remove_from_whitelist', methods=['POST'])
def remove_from_whitelist():
    if 'user_id' not in session: return jsonify({"status": "error"}), 401
    user_id = session['user_id']
    data = request.json
    jid = data.get('group_id')
    
    config = load_user_config(user_id)
    allowed = config.get('allowed_jids', [])
    
    new_allowed = []
    for item in allowed:
        if isinstance(item, dict):
            if item.get('jid') != jid:
                new_allowed.append(item)
        else:
            if item != jid:
                new_allowed.append(item)
                
    config['allowed_jids'] = new_allowed
    save_user_config(user_id, config)
        
    return jsonify({"status": "success"})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)