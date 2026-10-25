from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import current_app, g


# =========================================================
# Database connection
# =========================================================

def get_db() -> sqlite3.Connection:
    """
    Open one SQLite connection for the current Flask request.
    """
    if "db" not in g:
        database_path = Path(
            current_app.config["DATABASE_PATH"]
        )

        database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        g.db = sqlite3.connect(
            database_path,
            timeout=10,
        )

        g.db.row_factory = sqlite3.Row

        g.db.execute(
            "PRAGMA foreign_keys = ON"
        )

    return g.db


def close_db(
    error: Exception | None = None,
) -> None:
    """
    Close the request-scoped database connection.
    """
    database = g.pop(
        "db",
        None,
    )

    if database is not None:
        database.close()


# =========================================================
# Database migration
# =========================================================

def _ensure_user_columns(
    database: sqlite3.Connection,
) -> None:
    """
    Add missing security columns to an existing users table.

    This preserves existing accounts when new features are
    introduced.
    """
    existing_columns = {
        row["name"]
        for row in database.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    }

    required_columns = {
        "failed_login_attempts":
            "INTEGER NOT NULL DEFAULT 0",

        "locked_until":
            "REAL",

        "lockout_demo_mode":
            (
                "INTEGER NOT NULL DEFAULT 0 "
                "CHECK (lockout_demo_mode IN (0, 1))"
            ),

        "password_reset_otp_hash":
            "TEXT",

        "password_reset_otp_expires_at":
            "REAL",

        "password_reset_otp_attempts":
            "INTEGER NOT NULL DEFAULT 0",

        "password_change_otp_hash":
            "TEXT",

        "password_change_otp_expires_at":
            "REAL",

        "password_change_otp_attempts":
            "INTEGER NOT NULL DEFAULT 0",

        "pending_password_hash":
            "TEXT",

        "password_change_current_attempts":
            "INTEGER NOT NULL DEFAULT 0",

        "password_change_locked_until":
            "REAL",
    }

    for (
        column_name,
        column_definition,
    ) in required_columns.items():
        if column_name not in existing_columns:
            database.execute(
                f"""
                ALTER TABLE users
                ADD COLUMN {column_name} {column_definition}
                """
            )


# =========================================================
# Database initialisation
# =========================================================

def init_db() -> None:
    """
    Create and migrate the users and audit-log tables.
    """
    database = get_db()

    database.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,

            email TEXT NOT NULL
                COLLATE NOCASE
                UNIQUE,

            username TEXT NOT NULL
                COLLATE NOCASE
                UNIQUE,

            password_hash TEXT NOT NULL,

            email_verified INTEGER NOT NULL
                DEFAULT 0
                CHECK (email_verified IN (0, 1)),

            registration_otp_hash TEXT,

            registration_otp_expires_at REAL,

            registration_otp_attempts INTEGER NOT NULL
                DEFAULT 0,

            login_otp_hash TEXT,

            login_otp_expires_at REAL,

            login_otp_attempts INTEGER NOT NULL
                DEFAULT 0,

            failed_login_attempts INTEGER NOT NULL
                DEFAULT 0,

            locked_until REAL,

            lockout_demo_mode INTEGER NOT NULL
                DEFAULT 0
                CHECK (lockout_demo_mode IN (0, 1)),

            password_reset_otp_hash TEXT,

            password_reset_otp_expires_at REAL,

            password_reset_otp_attempts INTEGER NOT NULL
                DEFAULT 0,

            password_change_otp_hash TEXT,

            password_change_otp_expires_at REAL,

            password_change_otp_attempts INTEGER NOT NULL
                DEFAULT 0,

            pending_password_hash TEXT,

            password_change_current_attempts INTEGER NOT NULL
                DEFAULT 0,

            password_change_locked_until REAL,

            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_login_at TEXT
        )
        """
    )

    _ensure_user_columns(
        database
    )

    database.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            username_snapshot TEXT NOT NULL
                DEFAULT 'Unknown account',

            event_type TEXT NOT NULL,

            outcome TEXT NOT NULL
                CHECK (
                    outcome IN (
                        'SUCCESS',
                        'FAILURE',
                        'INFO'
                    )
                ),

            ip_address TEXT NOT NULL
                DEFAULT 'Unknown',

            user_agent TEXT NOT NULL
                DEFAULT 'Unknown',

            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(user_id)
                ON DELETE SET NULL
        )
        """
    )

    database.execute(
        """
        CREATE INDEX IF NOT EXISTS
            idx_audit_logs_user_created
        ON audit_logs (
            user_id,
            created_at DESC
        )
        """
    )

    database.commit()


# =========================================================
# User lookup and creation
# =========================================================

def username_exists(
    username: str,
) -> bool:
    database = get_db()

    user = database.execute(
        """
        SELECT user_id
        FROM users
        WHERE username = ?
        """,
        (
            username.strip(),
        ),
    ).fetchone()

    return user is not None


def email_exists(
    email: str,
) -> bool:
    database = get_db()

    user = database.execute(
        """
        SELECT user_id
        FROM users
        WHERE email = ?
        """,
        (
            email.strip().lower(),
        ),
    ).fetchone()

    return user is not None


def create_user(
    email: str,
    username: str,
    password_hash: str,
    registration_otp_hash: str,
    registration_otp_expires_at: float,
) -> int:
    database = get_db()

    cursor = database.execute(
        """
        INSERT INTO users (
            email,
            username,
            password_hash,
            email_verified,
            registration_otp_hash,
            registration_otp_expires_at,
            registration_otp_attempts
        )
        VALUES (?, ?, ?, 0, ?, ?, 0)
        """,
        (
            email.strip().lower(),
            username.strip(),
            password_hash,
            registration_otp_hash,
            registration_otp_expires_at,
        ),
    )

    database.commit()

    return int(
        cursor.lastrowid
    )


def get_user_by_id(
    user_id: int,
) -> sqlite3.Row | None:
    database = get_db()

    return database.execute(
        """
        SELECT *
        FROM users
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    ).fetchone()


def get_user_by_identity(
    identity: str,
) -> sqlite3.Row | None:
    database = get_db()

    normalised_identity = (
        identity.strip()
    )

    return database.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
           OR email = ?
        """,
        (
            normalised_identity,
            normalised_identity.lower(),
        ),
    ).fetchone()


def get_user_by_email(
    email: str,
) -> sqlite3.Row | None:
    database = get_db()

    return database.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (
            email.strip().lower(),
        ),
    ).fetchone()


def get_all_users() -> list[sqlite3.Row]:
    """
    Return only privacy-safe information for the active-user
    directory.
    """
    database = get_db()

    return database.execute(
        """
        SELECT
            user_id,
            username,
            last_login_at
        FROM users
        WHERE email_verified = 1
        ORDER BY
            CASE
                WHEN last_login_at IS NULL
                    THEN 1
                ELSE 0
            END,
            last_login_at DESC,
            username COLLATE NOCASE ASC
        """
    ).fetchall()


# =========================================================
# Registration email verification
# =========================================================

def set_registration_otp(
    user_id: int,
    otp_hash: str,
    expires_at: float,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET registration_otp_hash = ?,
            registration_otp_expires_at = ?,
            registration_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            otp_hash,
            expires_at,
            user_id,
        ),
    )

    database.commit()


def increment_registration_otp_attempts(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET registration_otp_attempts =
            registration_otp_attempts + 1
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def mark_email_verified(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET email_verified = 1,
            registration_otp_hash = NULL,
            registration_otp_expires_at = NULL,
            registration_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


# =========================================================
# Login OTP
# =========================================================

def set_login_otp(
    user_id: int,
    otp_hash: str,
    expires_at: float,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET login_otp_hash = ?,
            login_otp_expires_at = ?,
            login_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            otp_hash,
            expires_at,
            user_id,
        ),
    )

    database.commit()


def increment_login_otp_attempts(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET login_otp_attempts =
            login_otp_attempts + 1
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def clear_login_otp(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET login_otp_hash = NULL,
            login_otp_expires_at = NULL,
            login_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def update_last_login(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET last_login_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


# =========================================================
# Login account lockout
# =========================================================

def register_failed_login_attempt(
    user_id: int,
    max_attempts: int,
    lockout_seconds: int,
    current_time: float,
) -> tuple[int, float | None]:
    """
    Increase the failed login-password counter.

    Returns:
        (failed_attempts, locked_until)
    """
    database = get_db()

    row = database.execute(
        """
        SELECT failed_login_attempts
        FROM users
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    ).fetchone()

    current_attempts = (
        int(
            row["failed_login_attempts"]
            or 0
        )
        if row is not None
        else 0
    )

    new_attempts = (
        current_attempts + 1
    )

    if new_attempts >= max_attempts:
        locked_until = (
            current_time
            + lockout_seconds
        )

        database.execute(
            """
            UPDATE users
            SET failed_login_attempts = 0,
                locked_until = ?
            WHERE user_id = ?
            """,
            (
                locked_until,
                user_id,
            ),
        )

        database.commit()

        return (
            0,
            locked_until,
        )

    database.execute(
        """
        UPDATE users
        SET failed_login_attempts = ?,
            locked_until = NULL
        WHERE user_id = ?
        """,
        (
            new_attempts,
            user_id,
        ),
    )

    database.commit()

    return (
        new_attempts,
        None,
    )


def clear_login_lockout(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET failed_login_attempts = 0,
            locked_until = NULL
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def set_lockout_demo_mode(
    user_id: int,
    enabled: bool,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET lockout_demo_mode = ?
        WHERE user_id = ?
        """,
        (
            1 if enabled else 0,
            user_id,
        ),
    )

    database.commit()


# =========================================================
# Password-change current-password lockout
# =========================================================

def register_failed_password_change_attempt(
    user_id: int,
    max_attempts: int,
    cooldown_seconds: int,
    current_time: float,
) -> tuple[int, float | None]:
    """
    Record an incorrect current-password attempt made through
    the secure password-change feature.

    Returns:
        (failed_attempts, locked_until)
    """
    database = get_db()

    row = database.execute(
        """
        SELECT password_change_current_attempts
        FROM users
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    ).fetchone()

    current_attempts = (
        int(
            row[
                "password_change_current_attempts"
            ]
            or 0
        )
        if row is not None
        else 0
    )

    new_attempts = (
        current_attempts + 1
    )

    if new_attempts >= max_attempts:
        locked_until = (
            current_time
            + cooldown_seconds
        )

        database.execute(
            """
            UPDATE users
            SET password_change_current_attempts = 0,
                password_change_locked_until = ?,
                pending_password_hash = NULL,
                password_change_otp_hash = NULL,
                password_change_otp_expires_at = NULL,
                password_change_otp_attempts = 0
            WHERE user_id = ?
            """,
            (
                locked_until,
                user_id,
            ),
        )

        database.commit()

        return (
            0,
            locked_until,
        )

    database.execute(
        """
        UPDATE users
        SET password_change_current_attempts = ?,
            password_change_locked_until = NULL
        WHERE user_id = ?
        """,
        (
            new_attempts,
            user_id,
        ),
    )

    database.commit()

    return (
        new_attempts,
        None,
    )


def clear_password_change_lockout(
    user_id: int,
) -> None:
    """
    Reset current-password failures and remove the
    password-change cooldown.
    """
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET password_change_current_attempts = 0,
            password_change_locked_until = NULL
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


# =========================================================
# Forgotten-password reset
# =========================================================

def set_password_reset_otp(
    user_id: int,
    otp_hash: str,
    expires_at: float,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET password_reset_otp_hash = ?,
            password_reset_otp_expires_at = ?,
            password_reset_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            otp_hash,
            expires_at,
            user_id,
        ),
    )

    database.commit()


def increment_password_reset_otp_attempts(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET password_reset_otp_attempts =
            password_reset_otp_attempts + 1
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def clear_password_reset_otp(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET password_reset_otp_hash = NULL,
            password_reset_otp_expires_at = NULL,
            password_reset_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def update_password(
    user_id: int,
    password_hash: str,
) -> None:
    """
    Replace a password after a successful forgotten-password
    reset and clear related temporary security state.
    """
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET password_hash = ?,

            login_otp_hash = NULL,
            login_otp_expires_at = NULL,
            login_otp_attempts = 0,

            failed_login_attempts = 0,
            locked_until = NULL,

            password_reset_otp_hash = NULL,
            password_reset_otp_expires_at = NULL,
            password_reset_otp_attempts = 0,

            password_change_otp_hash = NULL,
            password_change_otp_expires_at = NULL,
            password_change_otp_attempts = 0,
            pending_password_hash = NULL,

            password_change_current_attempts = 0,
            password_change_locked_until = NULL

        WHERE user_id = ?
        """,
        (
            password_hash,
            user_id,
        ),
    )

    database.commit()


# =========================================================
# Authenticated password change
# =========================================================

def set_password_change_request(
    user_id: int,
    pending_password_hash: str,
    otp_hash: str,
    expires_at: float,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET pending_password_hash = ?,
            password_change_otp_hash = ?,
            password_change_otp_expires_at = ?,
            password_change_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            pending_password_hash,
            otp_hash,
            expires_at,
            user_id,
        ),
    )

    database.commit()


def increment_password_change_otp_attempts(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET password_change_otp_attempts =
            password_change_otp_attempts + 1
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def clear_password_change_request(
    user_id: int,
) -> None:
    database = get_db()

    database.execute(
        """
        UPDATE users
        SET pending_password_hash = NULL,
            password_change_otp_hash = NULL,
            password_change_otp_expires_at = NULL,
            password_change_otp_attempts = 0
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()


def apply_pending_password_change(
    user_id: int,
) -> bool:
    """
    Apply the pending password hash after successful
    email-code verification.
    """
    database = get_db()

    row = database.execute(
        """
        SELECT pending_password_hash
        FROM users
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    ).fetchone()

    if (
        row is None
        or not row[
            "pending_password_hash"
        ]
    ):
        return False

    database.execute(
        """
        UPDATE users
        SET password_hash = pending_password_hash,

            pending_password_hash = NULL,

            password_change_otp_hash = NULL,
            password_change_otp_expires_at = NULL,
            password_change_otp_attempts = 0,

            login_otp_hash = NULL,
            login_otp_expires_at = NULL,
            login_otp_attempts = 0,

            failed_login_attempts = 0,
            locked_until = NULL,

            password_change_current_attempts = 0,
            password_change_locked_until = NULL

        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()

    return True


# =========================================================
# Security audit log
# =========================================================

def create_audit_log(
    event_type: str,
    outcome: str,
    ip_address: str,
    user_agent: str,
    user_id: int | None = None,
    username: str | None = None,
) -> None:
    allowed_outcomes = {
        "SUCCESS",
        "FAILURE",
        "INFO",
    }

    normalised_outcome = (
        outcome.strip().upper()
    )

    if normalised_outcome not in allowed_outcomes:
        raise ValueError(
            "Audit outcome must be SUCCESS, FAILURE or INFO."
        )

    safe_event_type = (
        event_type.strip().upper()[:80]
        or "UNKNOWN_EVENT"
    )

    safe_username = (
        username.strip()[:50]
        if username
        else "Unknown account"
    )

    safe_ip_address = (
        ip_address.strip()[:45]
        if ip_address
        else "Unknown"
    )

    safe_user_agent = (
        user_agent.strip()[:255]
        if user_agent
        else "Unknown"
    )

    database = get_db()

    database.execute(
        """
        INSERT INTO audit_logs (
            user_id,
            username_snapshot,
            event_type,
            outcome,
            ip_address,
            user_agent
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            safe_username,
            safe_event_type,
            normalised_outcome,
            safe_ip_address,
            safe_user_agent,
        ),
    )

    database.commit()


def get_recent_audit_logs(
    user_id: int,
    limit: int = 10,
) -> list[sqlite3.Row]:
    safe_limit = max(
        1,
        min(
            int(limit),
            20,
        ),
    )

    database = get_db()

    return database.execute(
        """
        SELECT
            audit_id,
            event_type,
            outcome,
            created_at
        FROM audit_logs
        WHERE user_id = ?
        ORDER BY audit_id DESC
        LIMIT ?
        """,
        (
            user_id,
            safe_limit,
        ),
    ).fetchall()


# =========================================================
# Account deletion
# =========================================================

def delete_user(
    user_id: int,
) -> bool:
    database = get_db()

    cursor = database.execute(
        """
        DELETE FROM users
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    database.commit()

    return cursor.rowcount > 0