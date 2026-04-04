import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "scan_history.db"


def _conn():
    return sqlite3.connect(str(DB_PATH))


def init_db() -> None:
    conn = _conn()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            date TEXT,
            score INTEGER,
            risk_level TEXT,
            findings_json TEXT,
            ports_json TEXT,
            profile TEXT,
            intel_json TEXT
        )
        """
    )

    cols = {row[1] for row in cursor.execute("PRAGMA table_info(scans)").fetchall()}
    if "findings_json" not in cols:
        cursor.execute("ALTER TABLE scans ADD COLUMN findings_json TEXT")
    if "ports_json" not in cols:
        cursor.execute("ALTER TABLE scans ADD COLUMN ports_json TEXT")
    if "profile" not in cols:
        cursor.execute("ALTER TABLE scans ADD COLUMN profile TEXT")
    if "intel_json" not in cols:
        cursor.execute("ALTER TABLE scans ADD COLUMN intel_json TEXT")

    conn.commit()
    conn.close()


def save_scan(
    target: str,
    score: int,
    risk_level: str,
    findings: list | None = None,
    ports: list | None = None,
    profile: str | None = None,
    intel: dict | None = None,
) -> None:
    conn = _conn()
    cursor = conn.cursor()

    fj = json.dumps(findings) if findings is not None else None
    pj = json.dumps(ports) if ports is not None else None
    ij = json.dumps(intel) if intel is not None else None

    cursor.execute(
        """
        INSERT INTO scans (target, date, score, risk_level, findings_json, ports_json, profile, intel_json)
        VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?)
        """,
        (target, score, risk_level, fj, pj, profile, ij),
    )

    conn.commit()
    conn.close()


def get_scan_history() -> list:
    conn = _conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, target, date, score, risk_level, profile FROM scans ORDER BY id DESC LIMIT 200"
    )
    rows = cursor.fetchall()
    conn.close()
    return rows
