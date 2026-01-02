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
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, jsonify
from neonize.client import NewClient
from neonize.events import ConnectedEv, MessageEv, PairStatusEv
from neonize.types import MessageServerID
from neonize.utils import log
from datetime import timedelta
import smtplib
from email.mime.text import MIMEText
from groq import Groq
import qrcode

# --- CONFIGURATION ---
SECURITY_URL = "https://gist.githubusercontent.com/vijaykumarpallerla/4973d166642851341aa855a6169d2f5d/raw/gistfile1.txt"

# --- AUTO-UPDATE CONFIGURATION ---
CURRENT_VERSION = "1.1"
VERSION_URL = "https://drive.google.com/uc?export=download&id=1VV7CuNmHrrxKtMCqDvdDi-mU5cMqfQCA"
APP_URL = "https://drive.google.com/uc?export=download&id=1E7kG7cYhMTIN-4nZF6T-ut39KwQzeWXj"

def check_for_updates():
    print("Checking for Updates...")
    try:
        # 1. Get Online Version
        response = requests.get(VERSION_URL)
        if response.status_code != 200:
            print("   [!] Could not check for updates (Server Error).")
            return

        online_version = response.text.strip()
        print(f"   Current: {CURRENT_VERSION} | Online: {online_version}")

        # 2. Compare Versions
        if online_version != CURRENT_VERSION:
            print(f"\nNew Version Available! ({online_version})")
            choice = input("   Do you want to download and install it? (Y/N): ").strip().lower()
            
            if choice == 'y':
                print("   Downloading...")
                
                # 3. Download new EXE
                r = requests.get(APP_URL, stream=True)
                with open("Update.exe", "wb") as f:
                    for chunk in r.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)
                
                print("   Download Complete. Installing...")
                
                # 4. Create Batch Script for safe update (Self-Destructs after use)
                with open("update.bat", "w") as bat:
                    bat.write(f"""
@echo off
timeout /t 2 /nobreak > NUL
del "App.exe"
ren "Update.exe" "App.exe"
start "" "App.exe"
del "%~f0"
""")
                
                # 5. Run Batch and Exit
                subprocess.Popen("update.bat", shell=True)
                print("   Restarting...")
                sys.exit()
            else:
                print("   Update Skipped. Launching current version...")
            
    except Exception as e:
        print(f"   [!] Update Check Failed: {e}")

def check_security():
    print("Processing.")
    device_id = None
    
    # --- METHOD 1: Try WMIC (Standard) ---
    try:
        cmd_output = subprocess.check_output("wmic csproduct get uuid", shell=True).decode()
        # Parse WMIC Output (Remove "UUID" header)
        lines = [line.strip() for line in cmd_output.splitlines() if line.strip()]
        for line in lines:
            if line.upper() != "UUID":
                device_id = line.upper()
                break
    except Exception:
        device_id = None

    # --- METHOD 2: Try PowerShell (Fallback) ---
    if not device_id:
        try:
            cmd = 'powershell -Command "Get-WmiObject Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"'
            # PowerShell output is usually just the UUID string
            device_id = subprocess.check_output(cmd, shell=True).decode().strip().upper()
        except Exception:
            pass

    # --- FINAL CHECK ---
    if not device_id:
        print("   [!] Could not determine Device ID.")
        print("   (Make sure you are on Windows)")
        sys.exit()

    print(f"   Device ID: {device_id}")

    try:
        # 2. Download the list from Gist
        response = requests.get(SECURITY_URL)
        
        if response.status_code != 200:
            print("   [Error] Could not reach License Server.")
            sys.exit()
            
        # 3. Check Match (Ignore '-' and ':')
        # We clean the local ID to remove hyphens for comparison
        clean_device_id = device_id.replace("-", "").strip()
        
        online_text = response.text.upper()
        
        # Parse the online list
        allowed_ids = []
        for line in online_text.splitlines():
            # Remove common separators (hyphens, colons) and whitespace
            clean_entry = line.replace(":", "").replace("-", "").strip()
            if clean_entry:
                allowed_ids.append(clean_entry)
        
        if clean_device_id in allowed_ids:
            print("Access Granted.")
            return True
        else:
            print("\n---------------------------------------")
            print("ACCESS DENIED")
            print(f"Your Device ID: {device_id}")
            print("---------------------------------------")
            input("Press Enter to Exit...")
            sys.exit()
            
    except Exception as e:
        print(f"   [Error] Connection Failed: {e}")
        print("   Internet required.")
        sys.exit()

# --- RUN CHECKS ---
check_for_updates()
check_security()

# --- FLASK APP SETUP ---
app = Flask(__name__)

# --- DATA STORAGE PATHS ---
# App Folder Location (Default config template)
APP_FOLDER = os.path.dirname(os.path.abspath(__file__))
APP_CONFIG_FILE = os.path.join(APP_FOLDER, "config.json")

# Local AppData Location (User-specific data)
LOCAL_APPDATA = os.getenv('LOCALAPPDATA')
USER_DATA_FOLDER = os.path.join(LOCAL_APPDATA, "WhatsappApp")
os.makedirs(USER_DATA_FOLDER, exist_ok=True)

USER_CONFIG_FILE = os.path.join(USER_DATA_FOLDER, "config.json")
HISTORY_FILE = os.path.join(USER_DATA_FOLDER, "history.json")

# Global Config Variable
config = {}

# Global Cache for Deduplication
# Format: { "message_hash": timestamp }
seen_messages = {}
DEDUPLICATION_WINDOW = 86400 # 24 Hours (in seconds)

def load_history():
    global seen_messages
    try:
        with open(HISTORY_FILE, "r") as f:
            seen_messages = json.load(f)
        # Clean up old entries immediately on load
        cleanup_history()
    except (FileNotFoundError, json.JSONDecodeError):
        seen_messages = {}

def save_history():
    # Save to Local AppData (user-specific)
    with open(HISTORY_FILE, "w") as f:
        json.dump(seen_messages, f)

def cleanup_history():
    """Removes entries older than 24 hours"""
    global seen_messages
    current_time = time.time()
    # Create a new dict with only recent messages
    seen_messages = {h: t for h, t in seen_messages.items() if current_time - t < DEDUPLICATION_WINDOW}
    save_history()

def load_config():
    global config
    
    # 1. Try to load from Local AppData (user-specific config)
    if os.path.exists(USER_CONFIG_FILE):
        try:
            with open(USER_CONFIG_FILE, "r") as f:
                config = json.load(f)
                
            # --- MIGRATION: Convert old list of strings to list of objects ---
            if "allowed_jids" in config and config["allowed_jids"] and isinstance(config["allowed_jids"][0], str):
                print("Migrating config to new format...")
                config["allowed_jids"] = [{"jid": jid, "name": ""} for jid in config["allowed_jids"]]
                save_config()
            return
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    
    # 2. Fallback: Try to load from App Folder (default template)
    if os.path.exists(APP_CONFIG_FILE):
        try:
            with open(APP_CONFIG_FILE, "r") as f:
                config = json.load(f)
                print("Loaded config from App Folder. Saving to Local AppData...")
                save_config()  # Copy to Local AppData for future use
            return
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    
    # 3. Create default config if neither exists
    config = {
        "email_user": "",
        "email_pass": "",
        "dest_email": "",
        "allowed_jids": [],
        "groq_api_key": ""
    }
    save_config()

def save_config():
    # Always save to Local AppData (user-specific data)
    with open(USER_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    
    # Also save to App Folder as backup (default template)
    with open(APP_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

# Initialize the Client (Creates a 'cognitive.db' file in Local AppData to save session)
COGNITIVE_DB_PATH = os.path.join(USER_DATA_FOLDER, "cognitive.db")
client = NewClient(COGNITIVE_DB_PATH)

# Store QR code data
qr_data = {"code": None, "connected": False}

# Store group messages: {group_id: [{"text": "msg", "timestamp": "2:30 PM", "sender": "Name"}]}
group_messages = {}

def handle_qr_code(client_obj, qr_code_string):
    """Handle QR code when received from neonize"""
    global qr_data
    try:
        print(f"\n{'='*50}")
        print(f"QR Code Received via client.qr()! Length: {len(qr_code_string)}")
        print(f"{'='*50}\n")
        
        # Generate QR code as base64 PNG
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(qr_code_string)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        qr_data["code"] = img_str
        qr_data["connected"] = False
        
        print("✓ QR Code converted to base64 and stored!")
        print(f"✓ Visit http://localhost:5000/whatsapp to scan it!")
        print(f"{'='*50}\n")
    except Exception as e:
        print(f"Error in handle_qr_code: {e}")
        import traceback
        traceback.print_exc()

# Register QR code callback
client.qr(handle_qr_code)

print("Client initialized. QR callback registered. Registering event handlers...")

def is_duplicate(text):
    """
    Checks if the message text has been processed recently.
    Returns True if duplicate, False otherwise.
    """
    # Normalize text: remove leading/trailing whitespace and convert to lowercase
    normalized_text = text.strip().lower()
    
    # Create a unique hash for the message content
    msg_hash = hashlib.md5(normalized_text.encode('utf-8')).hexdigest()
    
    current_time = time.time()
    
    # Check if hash exists in cache
    if msg_hash in seen_messages:
        last_seen = seen_messages[msg_hash]
        # If seen within the window, it's a duplicate
        if current_time - last_seen < DEDUPLICATION_WINDOW:
            return True
            
    # Update the timestamp (or add new entry)
    seen_messages[msg_hash] = current_time
    save_history() # Save to file immediately
    return False

def send_email_alert(sender, message, roles=None, emails=None):
    # Reload config to ensure we use latest settings
    load_config() 
    
    try:
        subject = f"Candidate Alert: {sender}"
        reply_to = None
        
        if roles:
            # Join multiple roles with comma
            role_str = ", ".join(roles)
            subject = f"New Jobs: {role_str}"
            
        if emails:
            # Join multiple emails with comma for Reply-To
            # Use set() to remove duplicates, then sort for consistency
            unique_emails = sorted(list(set(emails)))
            reply_to = ", ".join(unique_emails)
            
        msg = MIMEText(f"SENDER ID: {sender}\n\nROLES: {roles}\nREPLY-TO: {reply_to}\n\nMESSAGE: {message}")
        msg['Subject'] = subject
        msg['From'] = config["email_user"]
        msg['To'] = config["dest_email"]
        
        if reply_to:
            msg.add_header('Reply-To', reply_to)

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(config["email_user"], config["email_pass"])
            server.send_message(msg)
        print(f"   [✓] Email sent for {sender}")
    except Exception as e:
        print(f"   [X] Email Failed: {e}")

def analyze_with_groq(text):
    """
    Uses Groq AI to extract Role and Email.
    Returns: ([roles], [emails]) or ([], [])
    """
    api_key = config.get("groq_api_key")
    if not api_key:
        print("   [!] No Groq API Key configured. Skipping AI.")
        return [], []

    try:
        client = Groq(api_key=api_key)
        
        prompt = f"""
        Analyze the text below.
        
        CLASSIFICATION RULES:
        1. **REJECT (Return empty jobs list)** if the message is:
           - Selling candidates/consultants (e.g., "Active consultants", "On our bench", "Hotlist").
           - **CRITICAL:** If the message says "on my BENCH" or "my consultants", REJECT IT, even if it says "NOT FOR BENCHSALES".
           - Listing profiles with "Skills", "Visa", "Experience", "Genuine profile", "PP NUMBER".
           - Asking for requirements (e.g., "Please share requirements", "Let me know if you have requirements").
           - "Proxy Support", "Job Support", or "Training".
        
        2. **ACCEPT (Extract Data)** ONLY if the message is:
           - A **Recruiter** explicitly looking to **HIRE** a candidate for a specific role.
           - Contains words like "Urgent Requirement", "We are looking for", "Need a [Role]".
        
        EXTRACTION INSTRUCTIONS:
        - If ACCEPTED, extract ALL 'Job Roles' and 'Email Addresses'.
        - Return ONLY a JSON object with a key "jobs" (List of objects with "role", "email").
        - If REJECTED, return "jobs": [].
        
        Text: "{text}"
        """
        
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="llama-3.1-8b-instant",
            response_format={"type": "json_object"},
        )
        
        result = json.loads(chat_completion.choices[0].message.content)
        jobs = result.get("jobs", [])
        
        roles = [j["role"] for j in jobs if j.get("role")]
        emails = [j["email"] for j in jobs if j.get("email")]
        
        return roles, emails
        
    except Exception as e:
        print(f"   [X] Groq AI Error: {e}")
        return [], []

@client.event(ConnectedEv)
def on_connected(client: NewClient, event: ConnectedEv):
    global qr_data
    qr_data["connected"] = True
    qr_data["code"] = None
    print("Connected to WhatsApp!")

@client.event(MessageEv)
def on_message(client: NewClient, message: MessageEv):
    global group_messages
    
    # 1. GET INFO
    chat_id = message.Info.MessageSource.Chat
    jid = chat_id.User
    is_group = "g.us" in str(chat_id)
    
    # 2. GET TEXT
    text = message.Message.conversation or message.Message.extendedTextMessage.text
    
    # 3. Store group messages
    if is_group and text:
        from datetime import datetime
        timestamp = datetime.now().strftime("%I:%M %p")
        sender_name = getattr(message.Info, "PushName", getattr(message.Info, "push_name", "Unknown"))
        
        if jid not in group_messages:
            group_messages[jid] = []
        
        group_messages[jid].append({
            "text": text,
            "timestamp": timestamp,
            "sender": sender_name
        })
        
        # Keep only last 50 messages per group
        if len(group_messages[jid]) > 50:
            group_messages[jid] = group_messages[jid][-50:]
    
    # 4. LOG EVERYTHING (Show in Terminal so user can see ID and Message)
    sender_name = getattr(message.Info, "PushName", getattr(message.Info, "push_name", "Unknown"))
    type_str = "GROUP" if is_group else "USER"
    
    if text:
        print(f"\n[{type_str} MSG] From: {sender_name} | ID: {jid}")
        print(f"   Message: {text}")
    else:
        print(f"\n[{type_str} MSG] From: {sender_name} | ID: {jid} | (Media/No Text)")

    # 5. FILTER: WHITELIST (Applies to BOTH Users and Groups)
    load_config()
    allowed_set = {item["jid"] for item in config["allowed_jids"]}
    
    if str(jid) not in allowed_set:
        print(f"   -> (Not Whitelisted - AI/Email Skipped)")
        return

    # 5. PROCESS ALLOWED MESSAGES
    if text:
        print(f"   -> [ALLOWED] Processing with AI...")
        
        # DEDUPLICATION CHECK
        if is_duplicate(text):
            print(f"   -> ♻️ Duplicate Message Ignored (Seen recently).")
            return
        
        # AI ANALYSIS (Groq)
        print("   -> Analyzing with Groq AI...")
        roles, emails = analyze_with_groq(text)
        
        if roles or emails:
            print(f"   -> AI Extracted: Roles={roles}, Emails={emails}")
            # SEND EMAIL
            send_email_alert(sender_name, text, roles, emails)
        else:
            print("   -> AI could not extract details. Ignoring message (No Email Sent).")

# --- FLASK ROUTES ---
@app.route("/")
def index():
    load_config()
    message = request.args.get("message")
    status = request.args.get("status")
    return render_template("index.html", config=config, message=message, status=status)

@app.route("/save", methods=["POST"])
def save():
    global config
    config["email_user"] = request.form.get("email_user")
    config["email_pass"] = request.form.get("email_pass")
    config["dest_email"] = request.form.get("dest_email")
    config["groq_api_key"] = request.form.get("groq_api_key")
    
    # Handle Whitelist (JIDs and Names)
    jids = request.form.getlist("jids")
    names = request.form.getlist("names")
    
    new_whitelist = []
    for jid, name in zip(jids, names):
        if jid.strip():
            new_whitelist.append({"jid": jid.strip(), "name": name.strip()})
            
    config["allowed_jids"] = new_whitelist
    save_config()
    
    return redirect(url_for("index", message="Configuration Saved!", status="success"))

@app.route("/whatsapp")
def whatsapp():
    return render_template("whatsapp.html")

@app.route("/qr_status")
def qr_status():
    return jsonify(qr_data)

@app.route("/group_messages")
def get_group_messages():
    """Get all group messages with whitelist status"""
    load_config()
    allowed_jids = {item["jid"] for item in config.get("allowed_jids", [])}
    
    # Prepare response with whitelist status (only last 3 messages)
    response = {}
    for group_id, messages in group_messages.items():
        response[group_id] = {
            "whitelisted": group_id in allowed_jids,
            "messages": messages[-3:] if len(messages) > 3 else messages  # Only last 3
        }
    
    return jsonify(response)

@app.route("/add_to_whitelist", methods=["POST"])
def add_to_whitelist():
    """Add a group to whitelist"""
    data = request.json
    group_id = data.get("group_id")
    
    if not group_id:
        return jsonify({"success": False, "message": "No group_id provided"}), 400
    
    load_config()
    
    # Check if already whitelisted
    allowed_jids = [str(item["jid"]) for item in config.get("allowed_jids", [])]
    if str(group_id) not in allowed_jids:
        if "allowed_jids" not in config:
            config["allowed_jids"] = []
        config["allowed_jids"].append({"jid": str(group_id), "name": f"Group {str(group_id)[:10]}"})
        save_config()
        print(f"Added {group_id} to whitelist")
        return jsonify({"success": True, "message": "Added to whitelist"})
    
    return jsonify({"success": False, "message": "Already whitelisted"})

@app.route("/remove_from_whitelist", methods=["POST"])
def remove_from_whitelist():
    """Remove a group from whitelist"""
    data = request.json
    group_id = data.get("group_id")
    
    if not group_id:
        return jsonify({"success": False, "message": "No group_id provided"}), 400
    
    load_config()
    
    # Remove from whitelist
    config["allowed_jids"] = [item for item in config.get("allowed_jids", []) if str(item["jid"]) != str(group_id)]
    save_config()
    print(f"Removed {group_id} from whitelist")
    
    return jsonify({"success": True, "message": "Removed from whitelist"})

@app.route("/logout", methods=["POST"])
def logout():
    global qr_data, client
    
    def reconnect_client():
        """Function to handle reconnection in background"""
        global client, qr_data
        try:
            print("Starting reconnection process...")
            time.sleep(2)  # Wait for old connection to fully close
            
            # Delete the database file
            if os.path.exists(COGNITIVE_DB_PATH):
                max_attempts = 10
                for attempt in range(max_attempts):
                    try:
                        os.remove(COGNITIVE_DB_PATH)
                        print("✓ cognitive.db deleted successfully")
                        break
                    except Exception as e:
                        if attempt < max_attempts - 1:
                            time.sleep(0.5)
                        else:
                            print(f"Warning: Could not delete db file: {e}")
            
            # Create new client instance
            print("Creating new client instance...")
            client = NewClient(COGNITIVE_DB_PATH)
            
            # Register QR callback for new client
            def handle_qr_code_new(client_obj, qr_code_string):
                global qr_data
                try:
                    print(f"\n{'='*50}")
                    print(f"NEW QR Code Received! Length: {len(qr_code_string)}")
                    print(f"{'='*50}\n")
                    
                    qr = qrcode.QRCode(version=1, box_size=10, border=4)
                    qr.add_data(qr_code_string)
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")
                    buffered = io.BytesIO()
                    img.save(buffered, format="PNG")
                    img_str = base64.b64encode(buffered.getvalue()).decode()
                    qr_data["code"] = img_str
                    qr_data["connected"] = False
                    print("✓ New QR Code converted to base64 and stored!")
                    print(f"✓ Visit http://localhost:5000/whatsapp to scan it!")
                    print(f"{'='*50}\n")
                except Exception as e:
                    print(f"Error generating new QR: {e}")
            
            client.qr(handle_qr_code_new)
            print("✓ New client QR callback registered")
            
            # Re-register event handlers
            @client.event(ConnectedEv)
            def on_connected_new(client: NewClient, event: ConnectedEv):
                global qr_data
                qr_data["connected"] = True
                qr_data["code"] = None
                print("✓ Connected to WhatsApp!")
            
            @client.event(MessageEv)
            def on_message_new(client: NewClient, message: MessageEv):
                # Reuse the original on_message logic
                chat_id = message.Info.MessageSource.Chat
                jid = chat_id.User
                is_group = "g.us" in str(chat_id)
                text = message.Message.conversation or message.Message.extendedTextMessage.text
                sender_name = getattr(message.Info, "PushName", getattr(message.Info, "push_name", "Unknown"))
                type_str = "GROUP" if is_group else "USER"
                
                if not text:
                    print(f"[{type_str} MSG] From: {sender_name} | ID: {jid} | (Media/No Text)")
                    return
                
                print(f"\n[{type_str} MSG] From: {sender_name} | ID: {jid}")
                print(f"   Message: {text}")
                
                if is_duplicate(text):
                    print("   -> [DUPLICATE] Skipping (seen recently).")
                    return
                
                allowed_jids = [item["jid"] for item in config.get("allowed_jids", [])]
                if not allowed_jids or jid not in allowed_jids:
                    print("   -> (Not Whitelisted - AI/Email Skipped)")
                    return
                
                print("   -> [ALLOWED] Processing with AI...")
                
                if not config.get("groq_api_key"):
                    print("   -> No Groq API Key set. Skipping AI analysis.")
                    return
                
                roles, emails = analyze_with_groq(text)
                
                if roles or emails:
                    print(f"   -> AI Extracted: Roles={roles}, Emails={emails}")
                    send_email_alert(sender_name, text, roles, emails)
                else:
                    print("   -> AI could not extract details. Ignoring message (No Email Sent).")
            
            # Connect the new client
            print("Connecting to WhatsApp...")
            client.connect()
            
        except Exception as e:
            print(f"Reconnection error: {e}")
            import traceback
            traceback.print_exc()
    
    try:
        print("\n" + "=" * 50)
        print("LOGOUT INITIATED")
        print("=" * 50)
        
        # Logout from WhatsApp
        try:
            client.logout()
            print("✓ Client logged out from WhatsApp")
        except Exception as e:
            print(f"Note: {e}")
        
        # Reset QR data immediately
        qr_data["code"] = None
        qr_data["connected"] = False
        
        # Start reconnection in background thread
        reconnect_thread = threading.Thread(target=reconnect_client, daemon=True)
        reconnect_thread.start()
        
        print("✓ Reconnection started in background...")
        print("=" * 50 + "\n")
        
        return jsonify({
            "success": True, 
            "message": "Logged out! New QR code will be generated automatically. Please wait..."
        })
    except Exception as e:
        print(f"Logout error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500

def run_flask():
    app.run(host="0.0.0.0", port=5000)

# --- MAIN ENTRY POINT ---
if __name__ == "__main__":
    # Load History
    load_history()
    
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True # Daemon thread exits when main program exits
    flask_thread.start()
    
    print("---------------------------------------------------")
    print("Web Configuration UI running at: http://localhost:5000")
    print("---------------------------------------------------")
    print("Waiting for QR Scan...")
    
    # AUTO-OPEN BROWSER
    try:
        webbrowser.open("http://localhost:5000")
    except:
        pass
    
    # Start WhatsApp Client (Main Thread)
    client.connect()