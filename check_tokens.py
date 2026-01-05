import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json

DB_URL = os.environ.get("DATABASE_URL")
if not DB_URL:
    print("DATABASE_URL not set")
    exit(1)

conn = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
c = conn.cursor()

print("--- GOOGLE TOKENS ---")
c.execute("SELECT id, email, google_token FROM users")
rows = c.fetchall()

for row in rows:
    token_data = row['google_token']
    has_token = False
    has_refresh = False
    
    if token_data:
        try:
            data = json.loads(token_data)
            if 'token' in data: has_token = True
            if 'refresh_token' in data: has_refresh = True
        except:
            pass
            
    print(f"User {row['id']} ({row['email']}):")
    print(f"  - Has Access Token: {has_token}")
    print(f"  - Has Refresh Token: {has_refresh}")
    if not has_refresh:
        print("    (WARNING: This user needs to logout and login again to get a refresh token)")

conn.close()
