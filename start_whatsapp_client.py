import os
import time
import threading

# Load .env entries (simple parser)
env_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(env_path):
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
                os.environ.setdefault(k, v)

# Import the app module and start the client for a test user
import app

USER_ID = os.environ.get('TEST_USER_ID') or '6'
print(f"Starting WhatsApp client for user {USER_ID}")
client = app.get_client(USER_ID)

# Start client in a thread to avoid blocking
def run_client():
    try:
        client.connect()
        print("client.connect() returned")
    except Exception as e:
        print(f"Error starting client: {e}")

t = threading.Thread(target=run_client, daemon=True)
t.start()

# Keep the script alive so the client thread runs and emits QR
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print('Stopping')
