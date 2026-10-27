from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path(os.getenv("IP_INVESTIGATOR_DB_PATH") or (Path(__file__).resolve().parent.parent / "data" / "ip_investigator.db"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or DEFAULT_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str | Path | None = None) -> None:
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Aberto',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                generated_at_utc TEXT,
                saved_at_utc TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                bundle_json TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_analyses_case_id ON analyses(case_id);
            CREATE INDEX IF NOT EXISTS idx_analyses_ip ON analyses(ip);
            """
        )


def create_case(name: str, description: str = "", db_path: str | Path | None = None) -> int:
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValueError("O nome do caso é obrigatório.")
    now = _utc_now()
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO cases(name, description, status, created_at_utc, updated_at_utc) VALUES (?, ?, 'Aberto', ?, ?)",
            (clean_name, (description or "").strip(), now, now),
        )
        return int(cur.lastrowid)


def list_cases(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT c.*, COUNT(a.id) AS analysis_count
            FROM cases c
            LEFT JOIN analyses a ON a.case_id = c.id
            GROUP BY c.id
            ORDER BY c.updated_at_utc DESC, c.id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_case(case_id: int, db_path: str | Path | None = None) -> dict[str, Any] | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (int(case_id),)).fetchone()
    return dict(row) if row else None


def update_case(
    case_id: int,
    *,
    name: str | None = None,
    description: str | None = None,
    status: str | None = None,
    db_path: str | Path | None = None,
) -> None:
    current = get_case(case_id, db_path)
    if not current:
        raise ValueError("Caso não encontrado.")
    new_name = (name if name is not None else current["name"]).strip()
    if not new_name:
        raise ValueError("O nome do caso é obrigatório.")
    new_description = description if description is not None else current["description"]
    new_status = status if status is not None else current["status"]
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE cases SET name=?, description=?, status=?, updated_at_utc=? WHERE id=?",
            (new_name, new_description, new_status, _utc_now(), int(case_id)),
        )


def delete_case(case_id: int, db_path: str | Path | None = None) -> None:
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM cases WHERE id = ?", (int(case_id),))


def add_analysis_to_case(
    case_id: int,
    bundle: dict[str, Any],
    *,
    label: str = "",
    db_path: str | Path | None = None,
) -> int:
    if not get_case(case_id, db_path):
        raise ValueError("Caso não encontrado.")
    payload = json.dumps(bundle, ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    ip = str((bundle.get("query") or {}).get("ip") or "")
    if not ip:
        raise ValueError("Bundle sem endereço IP.")
    now = _utc_now()
    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO analyses(case_id, ip, label, generated_at_utc, saved_at_utc, bundle_sha256, bundle_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(case_id),
                ip,
                (label or "").strip(),
                bundle.get("generated_at_utc"),
                now,
                digest,
                payload,
            ),
        )
        conn.execute("UPDATE cases SET updated_at_utc=? WHERE id=?", (now, int(case_id)))
        return int(cur.lastrowid)


def get_case_analyses(case_id: int, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM analyses WHERE case_id=? ORDER BY saved_at_utc DESC, id DESC",
            (int(case_id),),
        ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["bundle"] = json.loads(item.pop("bundle_json"))
        except json.JSONDecodeError:
            item["bundle"] = None
        out.append(item)
    return out


def remove_analysis(analysis_id: int, db_path: str | Path | None = None) -> None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT case_id FROM analyses WHERE id=?", (int(analysis_id),)).fetchone()
        conn.execute("DELETE FROM analyses WHERE id=?", (int(analysis_id),))
        if row:
            conn.execute("UPDATE cases SET updated_at_utc=? WHERE id=?", (_utc_now(), int(row["case_id"])))


def export_case(case_id: int, db_path: str | Path | None = None) -> dict[str, Any]:
    case = get_case(case_id, db_path)
    if not case:
        raise ValueError("Caso não encontrado.")
    analyses = get_case_analyses(case_id, db_path)
    return {
        "exported_at_utc": _utc_now(),
        "case": case,
        "analyses": [
            {
                "id": item["id"],
                "ip": item["ip"],
                "label": item["label"],
                "generated_at_utc": item["generated_at_utc"],
                "saved_at_utc": item["saved_at_utc"],
                "bundle_sha256": item["bundle_sha256"],
                "bundle": item["bundle"],
            }
            for item in analyses
        ],
    }
