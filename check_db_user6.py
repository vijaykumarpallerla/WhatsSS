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

print("--- USER 6 CONFIG ---")
c.execute("SELECT config FROM user_configs WHERE user_id=6")
res = c.fetchone()
if res:
    print(json.dumps(res['config'], indent=2))
else:
    print("User 6 config not found")

conn.close()
