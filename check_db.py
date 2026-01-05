import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import datetime

DB_URL = os.environ.get("DATABASE_URL")
if not DB_URL:
    print("DATABASE_URL not set")
    exit(1)

try:
    conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
    c = conn.cursor()

    print("--- USERS ---")
    c.execute("SELECT id, email, username FROM users")
    users = c.fetchall()
    for u in users:
        print(f"ID: {u['id']}, Email: {u['email']}, Username: {u['username']}")

    print("\n--- CONFIGS ---")
    c.execute("SELECT user_id, config FROM user_configs")
    configs = c.fetchall()
    for cfg in configs:
        print(f"User ID: {cfg['user_id']}")
        print(json.dumps(cfg['config'], indent=2))

    print("\n--- EMAIL STATS ---")
    for u in users:
        uid = u['id']
        c.execute("SELECT COUNT(*) FROM messages WHERE user_id=%s AND sent_email=TRUE", (uid,))
        total = c.fetchone()['count']
        
        # Today (IST logic as per app.py)
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        ist_now = utc_now + datetime.timedelta(hours=5, minutes=30)
        ist_start = ist_now.replace(hour=0, minute=0, second=0, microsecond=0)
        utc_start = ist_start - datetime.timedelta(hours=5, minutes=30)
        
        c.execute("SELECT COUNT(*) FROM messages WHERE user_id=%s AND sent_email=TRUE AND created_at >= %s", (uid, utc_start))
        today = c.fetchone()['count']
        
        print(f"User {uid} ({u['email']}): Today={today}, Total={total}")

    conn.close()
except Exception as e:
    print(f"Error: {e}")
