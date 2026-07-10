#!/usr/bin/env python3
"""Create or promote the admin user for BotStop."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from spiderfoot import SpiderFootDb
from spiderfoot.auth import hash_password

ADMIN_EMAIL = 'ekosolarize@gmail.com'
ADMIN_NAME = 'Admin'
DB_PATH = os.environ.get('SPIDERFOOT_DATA', '/var/lib/spiderfoot') + '/spiderfoot.db'

cfg = {'__database': DB_PATH}
dbh = SpiderFootDb(cfg)

existing = dbh.userGetByEmail(ADMIN_EMAIL)
if existing:
    # Promote to admin
    with dbh.dbhLock:
        dbh.dbh.execute("UPDATE tbl_users SET role='admin' WHERE email=?", (ADMIN_EMAIL,))
        dbh.conn.commit()
    print(f"Promoted {ADMIN_EMAIL} to admin.")
else:
    pwd = input("Set a password for the admin account: ").strip()
    dbh.userCreate(ADMIN_EMAIL, ADMIN_NAME, password_hash=hash_password(pwd), role='admin')
    print(f"Created admin user {ADMIN_EMAIL}.")
