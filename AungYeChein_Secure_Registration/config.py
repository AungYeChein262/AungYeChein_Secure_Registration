from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent

load_dotenv(
    BASE_DIR / ".env"
)


def get_boolean_environment_value(
    name: str,
    default: bool,
) -> bool:
    raw_value = os.environ.get(name)

    if raw_value is None:
        return default

    return raw_value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


class Config:
    SECRET_KEY = (
        os.environ.get("SECRET_KEY")
        or secrets.token_hex(32)
    )

    DATABASE_PATH = (
        BASE_DIR
        / "database"
        / "users.db"
    )

    MAX_CONTENT_LENGTH = (
        1 * 1024 * 1024
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    SESSION_COOKIE_SECURE = (
        get_boolean_environment_value(
            "SESSION_COOKIE_SECURE",
            False,
        )
    )

    SESSION_REFRESH_EACH_REQUEST = False

    MAIL_SERVER = os.environ.get(
        "MAIL_SERVER",
        "smtp.gmail.com",
    )

    MAIL_PORT = int(
        os.environ.get(
            "MAIL_PORT",
            "465",
        )
    )

    MAIL_USE_SSL = (
        get_boolean_environment_value(
            "MAIL_USE_SSL",
            True,
        )
    )

    MAIL_USERNAME = os.environ.get(
        "MAIL_USERNAME",
        "",
    ).strip()

    MAIL_APP_PASSWORD = os.environ.get(
        "MAIL_APP_PASSWORD",
        "",
    ).strip()

    MAIL_SENDER_NAME = os.environ.get(
        "MAIL_SENDER_NAME",
        "CET324 Secure Registration",
    ).strip()

    MAIL_TIMEOUT_SECONDS = int(
        os.environ.get(
            "MAIL_TIMEOUT_SECONDS",
            "20",
        )
    )

    OTP_EXPIRY_SECONDS = int(
        os.environ.get(
            "OTP_EXPIRY_SECONDS",
            "300",
        )
    )

    OTP_MAX_ATTEMPTS = int(
        os.environ.get(
            "OTP_MAX_ATTEMPTS",
            "5",
        )
    )

    OTP_RESEND_WAIT_SECONDS = int(
        os.environ.get(
            "OTP_RESEND_WAIT_SECONDS",
            "60",
        )
    )

    SESSION_IDLE_TIMEOUT_STANDARD_SECONDS = int(
        os.environ.get(
            "SESSION_IDLE_TIMEOUT_STANDARD_SECONDS",
            "900",
        )
    )

    SESSION_IDLE_TIMEOUT_DEMO_SECONDS = int(
        os.environ.get(
            "SESSION_IDLE_TIMEOUT_DEMO_SECONDS",
            "5",
        )
    )

    SESSION_ABSOLUTE_TIMEOUT_SECONDS = int(
        os.environ.get(
            "SESSION_ABSOLUTE_TIMEOUT_SECONDS",
            "7200",
        )
    )

    LOGIN_LOCKOUT_MAX_ATTEMPTS = int(
        os.environ.get(
            "LOGIN_LOCKOUT_MAX_ATTEMPTS",
            "5",
        )
    )

    LOGIN_LOCKOUT_STANDARD_SECONDS = int(
        os.environ.get(
            "LOGIN_LOCKOUT_STANDARD_SECONDS",
            "300",
        )
    )

    LOGIN_LOCKOUT_DEMO_SECONDS = int(
        os.environ.get(
            "LOGIN_LOCKOUT_DEMO_SECONDS",
            "15",
        )
    )

    LOGIN_RAPID_REQUEST_MAX_REQUESTS = int(
        os.environ.get(
            "LOGIN_RAPID_REQUEST_MAX_REQUESTS",
            "8",
        )
    )

    LOGIN_RAPID_REQUEST_WINDOW_SECONDS = int(
        os.environ.get(
            "LOGIN_RAPID_REQUEST_WINDOW_SECONDS",
            "15",
        )
    )

    PASSWORD_RESET_EXPIRY_SECONDS = int(
        os.environ.get(
            "PASSWORD_RESET_EXPIRY_SECONDS",
            "600",
        )
    )

    PASSWORD_CHANGE_EXPIRY_SECONDS = int(
        os.environ.get(
            "PASSWORD_CHANGE_EXPIRY_SECONDS",
            "300",
        )
    )

    PASSWORD_CHANGE_MAX_CURRENT_ATTEMPTS = int(
        os.environ.get(
            "PASSWORD_CHANGE_MAX_CURRENT_ATTEMPTS",
            "3",
        )
    )

    PASSWORD_CHANGE_STANDARD_COOLDOWN_SECONDS = int(
        os.environ.get(
            "PASSWORD_CHANGE_STANDARD_COOLDOWN_SECONDS",
            "300",
        )
    )

    PASSWORD_CHANGE_DEMO_COOLDOWN_SECONDS = int(
        os.environ.get(
            "PASSWORD_CHANGE_DEMO_COOLDOWN_SECONDS",
            "15",
        )
    )