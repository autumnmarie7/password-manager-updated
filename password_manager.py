import sqlite3
import bcrypt
from typing import Optional, List, Tuple
from database import create_connection, create_tables
from encryption import get_fernet

# ---------- USER (master password) ----------

def user_exists(username: str) -> bool:
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row is not None

def create_user(username: str, master_password: str) -> None:
    """
    Create initial user with a bcrypt hash of the master password.
    """
    create_tables()
    conn = create_connection()
    cur = conn.cursor()
    master_hash = bcrypt.hashpw(master_password.encode("utf-8"), bcrypt.gensalt())
    cur.execute(
        "INSERT INTO users (username, master_hash) VALUES (?, ?)",
        (username, master_hash.decode("utf-8")),
    )
    conn.commit()
    conn.close()

def verify_master(username: str, master_password: str) -> Optional[int]:
    """
    Returns user_id if password is correct, otherwise None.
    """
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, master_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    user_id, stored_hash = row
    ok = bcrypt.checkpw(master_password.encode("utf-8"), stored_hash.encode("utf-8"))
    return user_id if ok else None

# ---------- PASSWORD ENTRIES ----------

def add_password(user_id: int, master_password: str, account_name: str, plain_password: str) -> None:
    f = get_fernet(master_password)
    cipher = f.encrypt(plain_password.encode("utf-8")).decode("utf-8")

    conn = create_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO passwords (user_id, account_name, encrypted_password) VALUES (?, ?, ?)",
        (user_id, account_name, cipher),
    )
    conn.commit()
    conn.close()

def get_password(user_id: int, master_password: str, account_name: str) -> Optional[str]:
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT encrypted_password FROM passwords WHERE user_id = ? AND account_name = ?",
        (user_id, account_name),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    cipher = row[0]
    f = get_fernet(master_password)
    try:
        return f.decrypt(cipher.encode("utf-8")).decode("utf-8")
    except Exception:
        return None

def delete_password(user_id: int, account_name: str) -> bool:
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM passwords WHERE user_id = ? AND account_name = ?",
        (user_id, account_name),
    )
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def list_accounts(user_id: int) -> List[Tuple[int, str]]:
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, account_name FROM passwords WHERE user_id = ? ORDER BY account_name",
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows
