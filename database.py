import os
import sqlite3
from datetime import datetime


# Always keep database inside the project folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "activity_log.db")


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_database():

    conn = get_connection()
    cursor = conn.cursor()

    # Events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    # Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            risk_level TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def log_event(event_type, file_path):

    # Make sure tables exist
    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO events (
            event_type,
            file_path,
            timestamp
        )
        VALUES (?, ?, ?)
        """,
        (
            event_type,
            file_path,
            datetime.now().isoformat()
        )
    )

    conn.commit()
    conn.close()


def log_alert(risk_level, event_count, message):

    # Make sure tables exist
    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO alerts (
            risk_level,
            event_count,
            message,
            timestamp
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            risk_level,
            event_count,
            message,
            datetime.now().isoformat()
        )
    )

    conn.commit()
    conn.close()


def get_recent_events(limit=20):

    # Make sure tables exist
    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            event_type,
            file_path,
            timestamp
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_recent_alerts(limit=20):

    # Make sure tables exist
    init_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            risk_level,
            event_count,
            message,
            timestamp
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    conn.close()

    return rows