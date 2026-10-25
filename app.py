from __future__ import annotations

import io
import math
import re
import sqlite3
import time
from functools import wraps
from typing import Any, Callable


from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from captcha import (
    CAPTCHA_EXPIRY_SECONDS,
    generate_captcha,
    hash_captcha_answer,
    verify_captcha_answer,
)
from config import Config
from database import (
    apply_pending_password_change,
    clear_login_lockout,
    clear_login_otp,
    clear_password_change_lockout,
    clear_password_change_request,
    clear_password_reset_otp,
    close_db,
    create_audit_log,
    create_user,
    delete_user,
    email_exists,
    get_all_users,
    get_recent_audit_logs,
    get_user_by_email,
    get_user_by_id,
    get_user_by_identity,
    increment_login_otp_attempts,
    increment_password_change_otp_attempts,
    increment_password_reset_otp_attempts,
    increment_registration_otp_attempts,
    init_db,
    mark_email_verified,
    register_failed_login_attempt,
    register_failed_password_change_attempt,
    set_lockout_demo_mode,
    set_login_otp,
    set_password_change_request,
    set_password_reset_otp,
    set_registration_otp,
    update_last_login,
    update_password,
    username_exists,
)

from email_service import (
    EmailDeliveryError,
    send_security_notification,
    send_verification_code,
)
from otp_security import (
    generate_otp_code,
    hash_otp_code,
    verify_otp_code,
)
from password_security import (
    evaluate_password_strength,
    hash_password,
    verify_password,
)


# =========================================================
# Application setup
# =========================================================

app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
    headers_enabled=True,
    retry_after="delta-seconds",
)

app.teardown_appcontext(close_db)


EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


# Used to show a clear security message during SQL-injection testing.
# Parameterised queries remain the main SQL-injection protection.
SQL_INJECTION_PATTERN = re.compile(
    r"(?i)(?:"
    r"'|"
    r"--|"
    r"/\*|\*/|"
    r";|"
    r"\bunion\s+select\b|"
    r"\bor\s+\d+\s*=\s*\d+|"
    r"\band\s+\d+\s*=\s*\d+"
    r")"
)


# =========================================================
# Validation and shared helpers
# =========================================================

def validate_username(
    username: str,
) -> list[str]:
    errors: list[str] = []

    if not username:
        return ["Username is required."]

    if len(username) < 4:
        errors.append(
            "Username must contain at least 4 characters."
        )

    if len(username) > 30:
        errors.append(
            "Username must contain no more than 30 characters."
        )

    if not username.replace("_", "").isalnum():
        errors.append(
            "Username may contain only letters, "
            "numbers and underscores."
        )

    return errors


def validate_email_address(
    email: str,
) -> list[str]:
    errors: list[str] = []

    if not email:
        return ["Email address is required."]

    if len(email) > 254:
        errors.append(
            "Email address must contain no more "
            "than 254 characters."
        )

    if not EMAIL_PATTERN.fullmatch(email):
        errors.append(
            "Enter a valid email address."
        )

    return errors


def get_request_ip_address() -> str:
    return (
        request.remote_addr
        or "Unknown"
    )


def get_request_user_agent() -> str:
    return (
        request.headers.get(
            "User-Agent",
            "Unknown",
        )
        or "Unknown"
    )[:180]


def record_security_event(
    event_type: str,
    outcome: str,
    user_id: int | None = None,
    username: str | None = None,
) -> None:
    """
    Audit logging must never interrupt the main security action.
    """
    try:
        create_audit_log(
            event_type=event_type,
            outcome=outcome,
            user_id=user_id,
            username=username,
            ip_address=get_request_ip_address(),
            user_agent=get_request_user_agent(),
        )

    except Exception:
        app.logger.exception(
            "The security event could not be written."
        )


def send_security_notification_safely(
    recipient_email: str,
    event_title: str,
    event_description: str,
) -> None:
    """
    Notification failure does not undo the completed security action.
    """
    details = (
        f"{event_description}\n\n"
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
        f"IP address: {get_request_ip_address()}\n"
        f"Browser: {get_request_user_agent()}"
    )

    try:
        send_security_notification(
            recipient_email=recipient_email,
            event_title=event_title,
            event_details=details,
        )

    except EmailDeliveryError:
        app.logger.exception(
            "A security notification could not be sent."
        )


def get_login_rapid_request_limit() -> str:
    """
    Return the per-IP rapid-request limit used by the login route.

    The default demonstration window is 15 seconds.
    """
    max_requests = int(
        app.config[
            "LOGIN_RAPID_REQUEST_MAX_REQUESTS"
        ]
    )

    window_seconds = int(
        app.config[
            "LOGIN_RAPID_REQUEST_WINDOW_SECONDS"
        ]
    )

    return (
        f"{max_requests} per "
        f"{window_seconds} seconds"
    )


def get_resend_wait_seconds(
    expires_at: float | None,
    expiry_seconds: int | None = None,
) -> int:
    if not expires_at:
        return 0

    lifetime = (
        int(expiry_seconds)
        if expiry_seconds is not None
        else int(app.config["OTP_EXPIRY_SECONDS"])
    )

    sent_at = float(expires_at) - lifetime

    resend_available_at = (
        sent_at
        + int(app.config["OTP_RESEND_WAIT_SECONDS"])
    )

    return max(
        0,
        math.ceil(
            resend_available_at
            - time.time()
        ),
    )


# =========================================================
# Session timeout
# =========================================================

def get_session_timeout_mode() -> str:
    selected_mode = session.get(
        "session_timeout_mode",
        "standard",
    )

    if selected_mode not in {
        "standard",
        "demo",
    }:
        return "standard"

    return selected_mode


def get_session_idle_timeout_seconds() -> int:
    if get_session_timeout_mode() == "demo":
        return int(
            app.config[
                "SESSION_IDLE_TIMEOUT_DEMO_SECONDS"
            ]
        )

    return int(
        app.config[
            "SESSION_IDLE_TIMEOUT_STANDARD_SECONDS"
        ]
    )


def get_session_timestamp(
    key: str,
    fallback: float,
) -> float:
    try:
        return float(
            session.get(
                key,
                fallback,
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        return fallback


def initialise_authenticated_session(
    user_id: int,
) -> None:
    current_time = time.time()

    session.clear()

    session[
        "authenticated_user_id"
    ] = user_id

    session[
        "session_timeout_mode"
    ] = "standard"

    session[
        "session_started_at"
    ] = current_time

    session[
        "session_last_activity_at"
    ] = current_time


def expire_authenticated_session() -> Response:
    user_id_value = session.get(
        "authenticated_user_id"
    )

    if user_id_value:
        user = get_user_by_id(
            int(user_id_value)
        )

        if user is not None:
            record_security_event(
                event_type="SESSION_EXPIRED",
                outcome="INFO",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

    session.clear()

    flash(
        "Your session expired for security reasons. "
        "Please log in again.",
        "error",
    )

    return redirect(
        url_for("login")
    )


@app.before_request
def enforce_session_timeout() -> Response | None:
    if request.endpoint == "static":
        return None

    authenticated_user_id = session.get(
        "authenticated_user_id"
    )

    if not authenticated_user_id:
        return None

    current_time = time.time()

    if "session_started_at" not in session:
        session[
            "session_started_at"
        ] = current_time

    if "session_last_activity_at" not in session:
        session[
            "session_last_activity_at"
        ] = current_time

    session_started_at = get_session_timestamp(
        "session_started_at",
        current_time,
    )

    session_last_activity_at = get_session_timestamp(
        "session_last_activity_at",
        current_time,
    )

    idle_timeout_seconds = (
        get_session_idle_timeout_seconds()
    )

    absolute_timeout_seconds = int(
        app.config[
            "SESSION_ABSOLUTE_TIMEOUT_SECONDS"
        ]
    )

    if (
        current_time - session_last_activity_at
        >= idle_timeout_seconds
        or current_time - session_started_at
        >= absolute_timeout_seconds
    ):
        return expire_authenticated_session()

    manual_activity_endpoints = {
        "session_heartbeat",
        "session_expired",
        "set_session_timeout_mode",
    }

    if (
        request.endpoint
        not in manual_activity_endpoints
    ):
        session[
            "session_last_activity_at"
        ] = current_time

    return None


# =========================================================
# Email-code helpers
# =========================================================

def create_and_send_registration_code(
    user_id: int,
    email: str,
) -> None:
    verification_code = generate_otp_code()

    expires_at = (
        time.time()
        + int(app.config["OTP_EXPIRY_SECONDS"])
    )

    set_registration_otp(
        user_id,
        hash_otp_code(
            verification_code,
            app.config["SECRET_KEY"],
        ),
        expires_at,
    )

    try:
        send_verification_code(
            recipient_email=email,
            verification_code=verification_code,
            purpose="registration",
        )

    except EmailDeliveryError:
        set_registration_otp(
            user_id,
            "",
            0.0,
        )
        raise


def create_and_send_login_code(
    user_id: int,
    email: str,
) -> None:
    verification_code = generate_otp_code()

    expires_at = (
        time.time()
        + int(app.config["OTP_EXPIRY_SECONDS"])
    )

    set_login_otp(
        user_id,
        hash_otp_code(
            verification_code,
            app.config["SECRET_KEY"],
        ),
        expires_at,
    )

    try:
        send_verification_code(
            recipient_email=email,
            verification_code=verification_code,
            purpose="login",
        )

    except EmailDeliveryError:
        clear_login_otp(user_id)
        raise


def create_and_send_password_reset_code(
    user_id: int,
    email: str,
) -> None:
    verification_code = generate_otp_code()

    expires_at = (
        time.time()
        + int(
            app.config[
                "PASSWORD_RESET_EXPIRY_SECONDS"
            ]
        )
    )

    set_password_reset_otp(
        user_id,
        hash_otp_code(
            verification_code,
            app.config["SECRET_KEY"],
        ),
        expires_at,
    )

    try:
        send_verification_code(
            recipient_email=email,
            verification_code=verification_code,
            purpose="password_reset",
        )

    except EmailDeliveryError:
        clear_password_reset_otp(user_id)
        raise


def create_and_send_password_change_code(
    user_id: int,
    email: str,
    pending_password_hash: str,
) -> None:
    verification_code = generate_otp_code()

    expires_at = (
        time.time()
        + int(
            app.config[
                "PASSWORD_CHANGE_EXPIRY_SECONDS"
            ]
        )
    )

    set_password_change_request(
        user_id,
        pending_password_hash,
        hash_otp_code(
            verification_code,
            app.config["SECRET_KEY"],
        ),
        expires_at,
    )

    try:
        send_verification_code(
            recipient_email=email,
            verification_code=verification_code,
            purpose="password_change",
        )

    except EmailDeliveryError:
        clear_password_change_request(user_id)
        raise


# =========================================================
# Account-deletion helpers
# =========================================================

def clear_pending_account_deletion() -> None:
    deletion_keys = (
        "pending_delete_user_id",
        "delete_otp_hash",
        "delete_otp_expires_at",
        "delete_otp_attempts",
        "delete_otp_sent_at",
    )

    for key in deletion_keys:
        session.pop(
            key,
            None,
        )


def create_and_send_delete_code(
    user_id: int,
    email: str,
) -> None:
    verification_code = generate_otp_code()
    current_time = time.time()

    session[
        "pending_delete_user_id"
    ] = user_id

    session[
        "delete_otp_hash"
    ] = hash_otp_code(
        verification_code,
        app.config["SECRET_KEY"],
    )

    session[
        "delete_otp_expires_at"
    ] = (
        current_time
        + int(app.config["OTP_EXPIRY_SECONDS"])
    )

    session[
        "delete_otp_attempts"
    ] = 0

    session[
        "delete_otp_sent_at"
    ] = current_time

    try:
        send_verification_code(
            recipient_email=email,
            verification_code=verification_code,
            purpose="delete_account",
        )

    except EmailDeliveryError:
        clear_pending_account_deletion()
        raise


# =========================================================
# Route protection
# =========================================================

def login_required(
    view_function: Callable[..., Any],
) -> Callable[..., Any]:
    @wraps(view_function)
    def wrapped_view(
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        user_id = session.get(
            "authenticated_user_id"
        )

        if not user_id:
            flash(
                "Please log in to access this page.",
                "error",
            )

            return redirect(
                url_for("login")
            )

        user = get_user_by_id(
            int(user_id)
        )

        if user is None:
            session.clear()

            flash(
                "Your session is no longer valid. "
                "Please log in again.",
                "error",
            )

            return redirect(
                url_for("login")
            )

        return view_function(
            *args,
            user=user,
            **kwargs,
        )

    return wrapped_view


# =========================================================
# Registration
# =========================================================

@app.route(
    "/",
    methods=["GET", "POST"],
)
@limiter.limit(
    "5 per minute",
    methods=["POST"],
)
def register() -> str | Response:
    errors: list[str] = []

    email = ""
    username = ""
    password_result = None
    captcha_failed = False

    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        human_check = request.form.get(
            "human_check",
            "",
        )

        captcha_answer = request.form.get(
            "captcha_answer",
            "",
        ).strip()

        errors.extend(
            validate_email_address(email)
        )

        errors.extend(
            validate_username(username)
        )

        password_result = (
            evaluate_password_strength(
                password,
                username,
            )
        )

        if not password_result["is_valid"]:
            errors.extend(
                password_result["feedback"]
            )

        if password != confirm_password:
            errors.append(
                "The password and confirmation do not match."
            )

        captcha_verified_at = session.pop(
            "captcha_verified_at",
            0,
        )

        expected_captcha_hash = session.pop(
            "captcha_answer_hash",
            "",
        )

        captcha_created_at = session.pop(
            "captcha_created_at",
            0,
        )

        if human_check != "yes":
            errors.append(
                "Confirm that you are not a robot."
            )
            captcha_failed = True

        else:
            current_time = time.time()

            popup_verification_valid = (
                bool(captcha_verified_at)
                and (
                    current_time
                    - float(
                        captcha_verified_at
                        or 0
                    )
                    <= CAPTCHA_EXPIRY_SECONDS
                )
            )

            direct_verification_valid = False

            if (
                not popup_verification_valid
                and expected_captcha_hash
                and captcha_created_at
            ):
                captcha_age = (
                    current_time
                    - float(
                        captcha_created_at
                        or 0
                    )
                )

                direct_verification_valid = (
                    captcha_age
                    <= CAPTCHA_EXPIRY_SECONDS
                    and verify_captcha_answer(
                        captcha_answer,
                        expected_captcha_hash,
                        app.config["SECRET_KEY"],
                    )
                )

            if not (
                popup_verification_valid
                or direct_verification_valid
            ):
                if (
                    captcha_verified_at
                    and not popup_verification_valid
                ):
                    errors.append(
                        "The verified CAPTCHA has expired. "
                        "Complete a new CAPTCHA."
                    )

                elif (
                    expected_captcha_hash
                    and captcha_created_at
                    and (
                        current_time
                        - float(
                            captcha_created_at
                            or 0
                        )
                        > CAPTCHA_EXPIRY_SECONDS
                    )
                ):
                    errors.append(
                        "The CAPTCHA has expired. "
                        "Complete a new CAPTCHA."
                    )

                elif expected_captcha_hash:
                    errors.append(
                        "The CAPTCHA answer is incorrect."
                    )

                else:
                    errors.append(
                        "Complete and verify the CAPTCHA "
                        "before creating the account."
                    )

                captcha_failed = True

        if captcha_failed:
            record_security_event(
                event_type="CAPTCHA_FAILURE",
                outcome="FAILURE",
                username=(
                    username
                    or None
                ),
            )

        if (
            not errors
            and email_exists(email)
        ):
            errors.append(
                "This email address is already registered."
            )

        if (
            not errors
            and username_exists(username)
        ):
            errors.append(
                "This username is already registered."
            )

        if errors:
            record_security_event(
                event_type="REGISTRATION_FAILURE",
                outcome="FAILURE",
                username=(
                    username
                    or None
                ),
            )

        if not errors:
            protected_password = hash_password(
                password
            )

            registration_code = generate_otp_code()

            registration_expires_at = (
                time.time()
                + int(
                    app.config[
                        "OTP_EXPIRY_SECONDS"
                    ]
                )
            )

            protected_registration_code = (
                hash_otp_code(
                    registration_code,
                    app.config["SECRET_KEY"],
                )
            )

            try:
                user_id = create_user(
                    email=email,
                    username=username,
                    password_hash=protected_password,
                    registration_otp_hash=(
                        protected_registration_code
                    ),
                    registration_otp_expires_at=(
                        registration_expires_at
                    ),
                )

            except sqlite3.IntegrityError:
                errors.append(
                    "The email address or username "
                    "is already registered."
                )

            except Exception:
                app.logger.exception(
                    "Account creation failed."
                )

                errors.append(
                    "The account could not be created."
                )

            else:
                record_security_event(
                    event_type="REGISTRATION_SUCCESS",
                    outcome="SUCCESS",
                    user_id=user_id,
                    username=username,
                )

                session.clear()

                session[
                    "pending_registration_user_id"
                ] = user_id

                try:
                    send_verification_code(
                        recipient_email=email,
                        verification_code=registration_code,
                        purpose="registration",
                    )

                except EmailDeliveryError:
                    set_registration_otp(
                        user_id,
                        "",
                        0.0,
                    )

                    flash(
                        "The account was created, but the "
                        "verification email could not be delivered.",
                        "error",
                    )

                else:
                    flash(
                        "A six-digit verification code "
                        "was sent to your email.",
                        "success",
                    )

                return redirect(
                    url_for(
                        "verify_registration"
                    )
                )

    return render_template(
        "register.html",
        errors=errors,
        email=email,
        username=username,
        password_result=password_result,
    )


@app.route("/captcha-image")
@limiter.limit("30 per minute")
def captcha_image() -> Response:
    # Loading a new image invalidates any earlier verification.
    session.pop(
        "captcha_verified_at",
        None,
    )

    code, image_bytes = generate_captcha()

    session[
        "captcha_answer_hash"
    ] = hash_captcha_answer(
        code,
        app.config["SECRET_KEY"],
    )

    session[
        "captcha_created_at"
    ] = time.time()

    response = send_file(
        io.BytesIO(image_bytes),
        mimetype="image/png",
        download_name="captcha.png",
    )

    response.headers[
        "Cache-Control"
    ] = (
        "no-store, no-cache, "
        "must-revalidate, max-age=0"
    )

    response.headers[
        "Pragma"
    ] = "no-cache"

    response.headers[
        "Expires"
    ] = "0"

    return response


@app.route(
    "/verify-captcha",
    methods=["POST"],
)
@limiter.limit(
    "20 per minute",
    methods=["POST"],
)
def verify_captcha() -> Response:
    """
    Verify the popup CAPTCHA on the Flask server.

    The challenge is consumed after one verification attempt,
    whether the submitted answer is correct or incorrect.
    """
    submitted_answer = request.form.get(
        "captcha_answer",
        "",
    ).strip()

    expected_captcha_hash = session.pop(
        "captcha_answer_hash",
        "",
    )

    captcha_created_at = session.pop(
        "captcha_created_at",
        0,
    )

    session.pop(
        "captcha_verified_at",
        None,
    )

    if not re.fullmatch(
        r"[A-Za-z0-9]{6}",
        submitted_answer,
    ):
        return jsonify(
            {
                "success": False,
                "message": (
                    "Enter all six CAPTCHA characters."
                ),
                "refresh_required": False,
            }
        ), 400

    if not expected_captcha_hash:
        return jsonify(
            {
                "success": False,
                "message": (
                    "The CAPTCHA is unavailable. "
                    "Generate a new CAPTCHA."
                ),
                "refresh_required": True,
            }
        ), 400

    captcha_age = (
        time.time()
        - float(
            captcha_created_at
            or 0
        )
    )

    if captcha_age > CAPTCHA_EXPIRY_SECONDS:
        record_security_event(
            event_type="CAPTCHA_EXPIRED",
            outcome="FAILURE",
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "The CAPTCHA has expired. "
                    "A new challenge has been generated."
                ),
                "refresh_required": True,
            }
        ), 400

    if not verify_captcha_answer(
        submitted_answer,
        expected_captcha_hash,
        app.config["SECRET_KEY"],
    ):
        record_security_event(
            event_type="CAPTCHA_FAILURE",
            outcome="FAILURE",
        )

        return jsonify(
            {
                "success": False,
                "message": (
                    "The CAPTCHA answer is incorrect. "
                    "Try the new challenge."
                ),
                "refresh_required": True,
            }
        ), 400

    session[
        "captcha_verified_at"
    ] = time.time()

    record_security_event(
        event_type="CAPTCHA_SUCCESS",
        outcome="SUCCESS",
    )

    return jsonify(
        {
            "success": True,
            "message": (
                "Human verification completed successfully."
            ),
            "refresh_required": False,
        }
    )


# =========================================================
# Registration verification
# =========================================================

@app.route(
    "/verify-registration",
    methods=["GET", "POST"],
)
@limiter.limit(
    "10 per 5 minutes",
    methods=["POST"],
)
def verify_registration() -> str | Response:
    user_id = session.get(
        "pending_registration_user_id"
    )

    if not user_id:
        flash(
            "Start by creating an account.",
            "error",
        )
        return redirect(
            url_for("register")
        )

    user = get_user_by_id(
        int(user_id)
    )

    if user is None:
        session.pop(
            "pending_registration_user_id",
            None,
        )

        flash(
            "The pending account could not be found.",
            "error",
        )

        return redirect(
            url_for("register")
        )

    if user["email_verified"]:
        session.pop(
            "pending_registration_user_id",
            None,
        )

        flash(
            "The email address is already verified.",
            "success",
        )

        return redirect(
            url_for("login")
        )

    errors: list[str] = []

    if request.method == "POST":
        submitted_code = request.form.get(
            "verification_code",
            "",
        )

        if (
            int(
                user[
                    "registration_otp_attempts"
                ]
            )
            >= int(
                app.config[
                    "OTP_MAX_ATTEMPTS"
                ]
            )
        ):
            errors.append(
                "Too many incorrect attempts. "
                "Request a new code."
            )

        elif not user[
            "registration_otp_hash"
        ]:
            errors.append(
                "No active verification code exists."
            )

        elif (
            not user[
                "registration_otp_expires_at"
            ]
            or time.time()
            > float(
                user[
                    "registration_otp_expires_at"
                ]
            )
        ):
            errors.append(
                "The verification code has expired."
            )

        elif verify_otp_code(
            submitted_code,
            user[
                "registration_otp_hash"
            ],
            app.config["SECRET_KEY"],
        ):
            mark_email_verified(
                int(user["user_id"])
            )

            record_security_event(
                event_type=(
                    "EMAIL_VERIFICATION_SUCCESS"
                ),
                outcome="SUCCESS",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

            session.pop(
                "pending_registration_user_id",
                None,
            )

            flash(
                "Your email was verified. "
                "You can now log in.",
                "success",
            )

            return redirect(
                url_for("login")
            )

        else:
            increment_registration_otp_attempts(
                int(user["user_id"])
            )

            remaining_attempts = max(
                0,
                int(
                    app.config[
                        "OTP_MAX_ATTEMPTS"
                    ]
                )
                - int(
                    user[
                        "registration_otp_attempts"
                    ]
                )
                - 1,
            )

            errors.append(
                "The verification code is incorrect. "
                f"{remaining_attempts} attempt(s) remain."
            )

        if errors:
            record_security_event(
                event_type=(
                    "EMAIL_VERIFICATION_FAILURE"
                ),
                outcome="FAILURE",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

    return render_template(
        "verify_code.html",
        title="Verify Your Email",
        description=(
            "Enter the six-digit code sent to "
            f"{user['email']}."
        ),
        errors=errors,
        resend_endpoint=(
            "resend_registration_code"
        ),
        back_endpoint="register",
        button_text="Verify Email",
    )


@app.route(
    "/resend-registration-code",
    methods=["POST"],
)
@limiter.limit("3 per 10 minutes")
def resend_registration_code() -> Response:
    user_id = session.get(
        "pending_registration_user_id"
    )

    if not user_id:
        flash(
            "No pending registration was found.",
            "error",
        )
        return redirect(
            url_for("register")
        )

    user = get_user_by_id(
        int(user_id)
    )

    if user is None:
        session.pop(
            "pending_registration_user_id",
            None,
        )
        return redirect(
            url_for("register")
        )

    wait_seconds = get_resend_wait_seconds(
        user[
            "registration_otp_expires_at"
        ]
    )

    if wait_seconds > 0:
        flash(
            f"Please wait {wait_seconds} seconds.",
            "error",
        )
        return redirect(
            url_for(
                "verify_registration"
            )
        )

    try:
        create_and_send_registration_code(
            int(user["user_id"]),
            user["email"],
        )

    except EmailDeliveryError:
        flash(
            "The verification email could not be sent.",
            "error",
        )

    else:
        flash(
            "A new verification code was sent.",
            "success",
        )

    return redirect(
        url_for(
            "verify_registration"
        )
    )


# =========================================================
# Login and account lockout
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
@limiter.limit(
    get_login_rapid_request_limit,
    methods=["POST"],
)
def login() -> str | Response:
    errors: list[str] = []
    identity = ""
    lockout_remaining_seconds = 0

    if request.method == "POST":
        identity = request.form.get(
            "identity",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        if SQL_INJECTION_PATTERN.search(identity):
            record_security_event(
                event_type=(
                    "SQL_INJECTION_INPUT_REJECTED"
                ),
                outcome="FAILURE",
                username=(
                    identity[:50]
                    or None
                ),
            )

            errors.append(
                "Potential SQL injection input was "
                "detected and rejected."
            )

            user = None

        else:
            user = get_user_by_identity(
                identity
            )

        current_time = time.time()

        if user is not None:
            locked_until = float(
                user["locked_until"]
                or 0
            )

            if locked_until > current_time:
                lockout_remaining_seconds = max(
                    1,
                    math.ceil(
                        locked_until
                        - current_time
                    ),
                )

                record_security_event(
                    event_type="LOCKED_LOGIN_ATTEMPT",
                    outcome="FAILURE",
                    user_id=int(
                        user["user_id"]
                    ),
                    username=user["username"],
                )

                errors.append(
                    "Login is temporarily unavailable. "
                    "Please wait and try again."
                )

            elif locked_until:
                clear_login_lockout(
                    int(user["user_id"])
                )

                record_security_event(
                    event_type="ACCOUNT_UNLOCKED",
                    outcome="INFO",
                    user_id=int(
                        user["user_id"]
                    ),
                    username=user["username"],
                )

                user = get_user_by_id(
                    int(user["user_id"])
                )

        if (
            not errors
            and (
                user is None
                or not verify_password(
                    user["password_hash"],
                    password,
                )
            )
        ):
            if user is not None:
                lockout_seconds = (
                    int(
                        app.config[
                            "LOGIN_LOCKOUT_DEMO_SECONDS"
                        ]
                    )
                    if bool(
                        user["lockout_demo_mode"]
                    )
                    else int(
                        app.config[
                            "LOGIN_LOCKOUT_STANDARD_SECONDS"
                        ]
                    )
                )

                _, locked_until = (
                    register_failed_login_attempt(
                        user_id=int(
                            user["user_id"]
                        ),
                        max_attempts=int(
                            app.config[
                                "LOGIN_LOCKOUT_MAX_ATTEMPTS"
                            ]
                        ),
                        lockout_seconds=lockout_seconds,
                        current_time=current_time,
                    )
                )

                if locked_until is not None:
                    lockout_remaining_seconds = (
                        lockout_seconds
                    )

                    record_security_event(
                        event_type="ACCOUNT_LOCKED",
                        outcome="FAILURE",
                        user_id=int(
                            user["user_id"]
                        ),
                        username=user["username"],
                    )

                    send_security_notification_safely(
                        recipient_email=user["email"],
                        event_title=(
                            "Account temporarily locked"
                        ),
                        event_description=(
                            "Your account was temporarily locked "
                            "after repeated incorrect password attempts."
                        ),
                    )

                    errors.append(
                        "Login is temporarily unavailable. "
                        "Please wait and try again."
                    )

                else:
                    record_security_event(
                        event_type=(
                            "LOGIN_PASSWORD_FAILURE"
                        ),
                        outcome="FAILURE",
                        user_id=int(
                            user["user_id"]
                        ),
                        username=user["username"],
                    )

                    errors.append(
                        "The username/email or password "
                        "is incorrect."
                    )

            else:
                record_security_event(
                    event_type=(
                        "LOGIN_PASSWORD_FAILURE"
                    ),
                    outcome="FAILURE",
                )

                errors.append(
                    "The username/email or password "
                    "is incorrect."
                )

        elif not errors and not user[
            "email_verified"
        ]:
            session.clear()

            session[
                "pending_registration_user_id"
            ] = int(
                user["user_id"]
            )

            flash(
                "Complete email verification "
                "before logging in.",
                "error",
            )

            return redirect(
                url_for(
                    "verify_registration"
                )
            )

        elif not errors:
            clear_login_lockout(
                int(user["user_id"])
            )

            try:
                create_and_send_login_code(
                    int(user["user_id"]),
                    user["email"],
                )

            except EmailDeliveryError:
                errors.append(
                    "The login code could not be emailed."
                )

            else:
                session.clear()

                session[
                    "pending_login_user_id"
                ] = int(
                    user["user_id"]
                )

                flash(
                    "A six-digit login code was "
                    "sent to your email.",
                    "success",
                )

                return redirect(
                    url_for("verify_login")
                )

    return render_template(
        "login.html",
        errors=errors,
        identity=identity,
        lockout_remaining_seconds=(
            lockout_remaining_seconds
        ),
    )


@app.route(
    "/verify-login",
    methods=["GET", "POST"],
)
@limiter.limit(
    "10 per 5 minutes",
    methods=["POST"],
)
def verify_login() -> str | Response:
    user_id = session.get(
        "pending_login_user_id"
    )

    if not user_id:
        flash(
            "Enter your username/email and "
            "password first.",
            "error",
        )
        return redirect(
            url_for("login")
        )

    user = get_user_by_id(
        int(user_id)
    )

    if user is None:
        session.pop(
            "pending_login_user_id",
            None,
        )
        return redirect(
            url_for("login")
        )

    errors: list[str] = []

    if request.method == "POST":
        submitted_code = request.form.get(
            "verification_code",
            "",
        )

        if (
            int(user["login_otp_attempts"])
            >= int(
                app.config[
                    "OTP_MAX_ATTEMPTS"
                ]
            )
        ):
            errors.append(
                "Too many incorrect attempts. "
                "Request a new login code."
            )

        elif not user["login_otp_hash"]:
            errors.append(
                "No active login code exists."
            )

        elif (
            not user["login_otp_expires_at"]
            or time.time()
            > float(
                user["login_otp_expires_at"]
            )
        ):
            errors.append(
                "The login code has expired."
            )

        elif verify_otp_code(
            submitted_code,
            user["login_otp_hash"],
            app.config["SECRET_KEY"],
        ):
            clear_login_otp(
                int(user["user_id"])
            )

            clear_login_lockout(
                int(user["user_id"])
            )

            update_last_login(
                int(user["user_id"])
            )

            record_security_event(
                event_type="LOGIN_SUCCESS",
                outcome="SUCCESS",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

            send_security_notification_safely(
                recipient_email=user["email"],
                event_title="Successful login",
                event_description=(
                    "A successful login to your account "
                    "was completed using password and email code."
                ),
            )

            initialise_authenticated_session(
                int(user["user_id"])
            )

            return redirect(
                url_for("dashboard")
            )

        else:
            increment_login_otp_attempts(
                int(user["user_id"])
            )

            remaining_attempts = max(
                0,
                int(
                    app.config[
                        "OTP_MAX_ATTEMPTS"
                    ]
                )
                - int(
                    user["login_otp_attempts"]
                )
                - 1,
            )

            errors.append(
                "The login code is incorrect. "
                f"{remaining_attempts} attempt(s) remain."
            )

        if errors:
            record_security_event(
                event_type="LOGIN_OTP_FAILURE",
                outcome="FAILURE",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

    return render_template(
        "verify_code.html",
        title="Two-Step Login Verification",
        description=(
            "Enter the six-digit login code sent to "
            f"{user['email']}."
        ),
        errors=errors,
        resend_endpoint="resend_login_code",
        back_endpoint="login",
        button_text="Complete Login",
    )


@app.route(
    "/resend-login-code",
    methods=["POST"],
)
@limiter.limit("3 per 10 minutes")
def resend_login_code() -> Response:
    user_id = session.get(
        "pending_login_user_id"
    )

    if not user_id:
        flash(
            "No pending login was found.",
            "error",
        )
        return redirect(
            url_for("login")
        )

    user = get_user_by_id(
        int(user_id)
    )

    if user is None:
        session.pop(
            "pending_login_user_id",
            None,
        )
        return redirect(
            url_for("login")
        )

    wait_seconds = get_resend_wait_seconds(
        user["login_otp_expires_at"]
    )

    if wait_seconds > 0:
        flash(
            f"Please wait {wait_seconds} seconds.",
            "error",
        )
        return redirect(
            url_for("verify_login")
        )

    try:
        create_and_send_login_code(
            int(user["user_id"]),
            user["email"],
        )

    except EmailDeliveryError:
        flash(
            "The login code could not be sent.",
            "error",
        )

    else:
        flash(
            "A new login code was sent.",
            "success",
        )

    return redirect(
        url_for("verify_login")
    )


# =========================================================
# Forgotten-password reset
# =========================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"],
)
@limiter.limit(
    "5 per 10 minutes",
    methods=["POST"],
)
def forgot_password() -> str | Response:
    errors: list[str] = []
    email = ""

    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        errors.extend(
            validate_email_address(email)
        )

        if not errors:
            user = get_user_by_email(
                email
            )

            # The visible wording is generic to reduce
            # account-enumeration information.
            generic_message = (
                "If a verified account exists for that email, "
                "a password-reset code has been sent."
            )

            if (
                user is not None
                and bool(
                    user["email_verified"]
                )
            ):
                try:
                    create_and_send_password_reset_code(
                        int(user["user_id"]),
                        user["email"],
                    )

                except EmailDeliveryError:
                    app.logger.exception(
                        "Password-reset email delivery failed."
                    )

                else:
                    record_security_event(
                        event_type=(
                            "PASSWORD_RESET_REQUEST"
                        ),
                        outcome="INFO",
                        user_id=int(
                            user["user_id"]
                        ),
                        username=user["username"],
                    )

                    session.clear()

                    session[
                        "pending_password_reset_user_id"
                    ] = int(
                        user["user_id"]
                    )

                    flash(
                        generic_message,
                        "success",
                    )

                    return redirect(
                        url_for(
                            "reset_password"
                        )
                    )

            flash(
                generic_message,
                "success",
            )

            return redirect(
                url_for("login")
            )

    return render_template(
        "forgot_password.html",
        errors=errors,
        email=email,
    )


@app.route(
    "/reset-password",
    methods=["GET", "POST"],
)
@limiter.limit(
    "10 per 10 minutes",
    methods=["POST"],
)
def reset_password() -> str | Response:
    user_id = session.get(
        "pending_password_reset_user_id"
    )

    if not user_id:
        flash(
            "Request a new password-reset code first.",
            "error",
        )
        return redirect(
            url_for("forgot_password")
        )

    user = get_user_by_id(
        int(user_id)
    )

    if user is None:
        session.clear()
        return redirect(
            url_for("forgot_password")
        )

    errors: list[str] = []
    password_result = None

    if request.method == "POST":
        submitted_code = request.form.get(
            "verification_code",
            "",
        ).strip()

        new_password = request.form.get(
            "new_password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        password_result = (
            evaluate_password_strength(
                new_password,
                user["username"],
            )
        )

        if not password_result["is_valid"]:
            errors.extend(
                password_result["feedback"]
            )

        if new_password != confirm_password:
            errors.append(
                "The new passwords do not match."
            )

        if verify_password(
            user["password_hash"],
            new_password,
        ):
            errors.append(
                "The new password must differ "
                "from the current password."
            )

        if (
            int(
                user[
                    "password_reset_otp_attempts"
                ]
            )
            >= int(
                app.config[
                    "OTP_MAX_ATTEMPTS"
                ]
            )
        ):
            errors.append(
                "Too many incorrect reset-code attempts. "
                "Request a new code."
            )

        elif not user[
            "password_reset_otp_hash"
        ]:
            errors.append(
                "No active password-reset code exists."
            )

        elif (
            not user[
                "password_reset_otp_expires_at"
            ]
            or time.time()
            > float(
                user[
                    "password_reset_otp_expires_at"
                ]
            )
        ):
            errors.append(
                "The password-reset code has expired."
            )

        elif not verify_otp_code(
            submitted_code,
            user[
                "password_reset_otp_hash"
            ],
            app.config["SECRET_KEY"],
        ):
            increment_password_reset_otp_attempts(
                int(user["user_id"])
            )

            errors.append(
                "The password-reset code is incorrect."
            )

            record_security_event(
                event_type=(
                    "PASSWORD_RESET_CODE_FAILURE"
                ),
                outcome="FAILURE",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

        if not errors:
            update_password(
                int(user["user_id"]),
                hash_password(
                    new_password
                ),
            )

            record_security_event(
                event_type=(
                    "PASSWORD_RESET_SUCCESS"
                ),
                outcome="SUCCESS",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

            send_security_notification_safely(
                recipient_email=user["email"],
                event_title="Password reset completed",
                event_description=(
                    "Your account password was reset successfully. "
                    "Existing login codes and account lockout values "
                    "were invalidated."
                ),
            )

            session.clear()

            flash(
                "Your password was reset successfully. "
                "Log in using the new password.",
                "success",
            )

            return redirect(
                url_for("login")
            )

    return render_template(
        "reset_password.html",
        user=user,
        errors=errors,
        password_result=password_result,
    )


@app.route(
    "/resend-password-reset-code",
    methods=["POST"],
)
@limiter.limit("3 per 10 minutes")
def resend_password_reset_code() -> Response:
    user_id = session.get(
        "pending_password_reset_user_id"
    )

    if not user_id:
        return redirect(
            url_for("forgot_password")
        )

    user = get_user_by_id(
        int(user_id)
    )

    if user is None:
        session.clear()
        return redirect(
            url_for("forgot_password")
        )

    wait_seconds = get_resend_wait_seconds(
        user[
            "password_reset_otp_expires_at"
        ],
        int(
            app.config[
                "PASSWORD_RESET_EXPIRY_SECONDS"
            ]
        ),
    )

    if wait_seconds > 0:
        flash(
            f"Please wait {wait_seconds} seconds.",
            "error",
        )
        return redirect(
            url_for("reset_password")
        )

    try:
        create_and_send_password_reset_code(
            int(user["user_id"]),
            user["email"],
        )

    except EmailDeliveryError:
        flash(
            "The new reset code could not be sent.",
            "error",
        )

    else:
        flash(
            "A new password-reset code was sent.",
            "success",
        )

    return redirect(
        url_for("reset_password")
    )


# =========================================================
# Dashboard and security controls
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard(
    user: Any,
) -> str:
    current_time = time.time()

    password_change_locked_until = float(
        user[
            "password_change_locked_until"
        ]
        or 0
    )

    if (
        password_change_locked_until
        and password_change_locked_until
        <= current_time
    ):
        clear_password_change_lockout(
            int(
                user["user_id"]
            )
        )

        record_security_event(
            event_type=(
                "PASSWORD_CHANGE_UNLOCKED"
            ),
            outcome="INFO",
            user_id=int(
                user["user_id"]
            ),
            username=user["username"],
        )

        refreshed_user = get_user_by_id(
            int(
                user["user_id"]
            )
        )

        if refreshed_user is not None:
            user = refreshed_user

        password_change_locked_until = 0

    password_change_remaining_seconds = max(
        0,
        math.ceil(
            password_change_locked_until
            - current_time
        ),
    )

    password_change_max_attempts = int(
        app.config[
            "PASSWORD_CHANGE_MAX_CURRENT_ATTEMPTS"
        ]
    )

    password_change_attempts_remaining = (
        0
        if password_change_remaining_seconds > 0
        else max(
            0,
            password_change_max_attempts
            - int(
                user[
                    "password_change_current_attempts"
                ]
                or 0
            ),
        )
    )

    accounts = get_all_users()

    recent_activity = (
        get_recent_audit_logs(
            int(
                user["user_id"]
            ),
            limit=10,
        )
    )

    timeout_mode = (
        get_session_timeout_mode()
    )

    timeout_seconds = (
        get_session_idle_timeout_seconds()
    )

    last_activity_at = get_session_timestamp(
        "session_last_activity_at",
        current_time,
    )

    remaining_seconds = max(
        0,
        math.ceil(
            timeout_seconds
            - (
                current_time
                - last_activity_at
            )
        ),
    )

    countdown_minutes, countdown_seconds = divmod(
        remaining_seconds,
        60,
    )

    return render_template(
        "dashboard.html",
        user=user,
        accounts=accounts,
        recent_activity=recent_activity,

        session_timeout_mode=timeout_mode,
        session_timeout_seconds=timeout_seconds,
        session_remaining_seconds=remaining_seconds,

        session_countdown_display=(
            f"{countdown_minutes:02d}:"
            f"{countdown_seconds:02d}"
        ),

        lockout_demo_mode=bool(
            user["lockout_demo_mode"]
        ),

        password_change_locked=(
            password_change_remaining_seconds
            > 0
        ),

        password_change_remaining_seconds=(
            password_change_remaining_seconds
        ),

        password_change_attempts_remaining=(
            password_change_attempts_remaining
        ),

        password_change_max_attempts=(
            password_change_max_attempts
        ),
    )

@app.route(
    "/lockout-mode",
    methods=["POST"],
)
@login_required
@limiter.limit("60 per minute")
def change_lockout_mode(
    user: Any,
) -> Response:
    selected_mode = request.form.get(
        "lockout_mode",
        "",
    ).strip().lower()

    is_ajax_request = (
        request.headers.get(
            "X-Requested-With",
            "",
        )
        == "XMLHttpRequest"
    )

    if selected_mode not in {
        "standard",
        "demo",
    }:
        message = (
            "Select a valid lockout mode."
        )

        if is_ajax_request:
            return jsonify(
                {
                    "success": False,
                    "message": message,
                }
            ), 400

        flash(
            message,
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    current_mode = (
        "demo"
        if bool(
            user["lockout_demo_mode"]
        )
        else "standard"
    )

    if selected_mode == current_mode:
        if is_ajax_request:
            return jsonify(
                {
                    "success": True,
                    "lockout_mode": (
                        current_mode
                    ),
                    "message": (
                        "The selected lockout "
                        "mode is already active."
                    ),
                }
            )

        return redirect(
            url_for("dashboard")
        )

    demo_enabled = (
        selected_mode == "demo"
    )

    set_lockout_demo_mode(
        int(
            user["user_id"]
        ),
        demo_enabled,
    )

    record_security_event(
        event_type="LOCKOUT_MODE_CHANGED",
        outcome="INFO",
        user_id=int(
            user["user_id"]
        ),
        username=user["username"],
    )

    message = (
        "Demo lockout mode enabled."
        if demo_enabled
        else "Standard lockout mode enabled."
    )

    if is_ajax_request:
        return jsonify(
            {
                "success": True,
                "lockout_mode": selected_mode,
                "message": message,
            }
        )

    flash(
        message,
        "success",
    )

    return redirect(
        url_for("dashboard")
    )

# =========================================================
# Session-timeout controls
# =========================================================

@app.route(
    "/session-timeout-mode",
    methods=["POST"],
)
@login_required
@limiter.limit("60 per minute")
def set_session_timeout_mode(
    user: Any,
) -> Response:
    selected_mode = request.form.get(
        "timeout_mode",
        "",
    ).strip().lower()

    is_ajax_request = (
        request.headers.get(
            "X-Requested-With",
            "",
        )
        == "XMLHttpRequest"
    )

    if selected_mode not in {
        "standard",
        "demo",
    }:
        message = (
            "Select a valid session-timeout mode."
        )

        if is_ajax_request:
            return jsonify(
                {
                    "success": False,
                    "message": message,
                }
            ), 400

        flash(
            message,
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    current_mode = (
        get_session_timeout_mode()
    )

    if selected_mode == current_mode:
        timeout_seconds = (
            get_session_idle_timeout_seconds()
        )

        if is_ajax_request:
            return jsonify(
                {
                    "success": True,
                    "timeout_mode": current_mode,
                    "timeout_seconds": timeout_seconds,
                    "remaining_seconds": timeout_seconds,
                    "message": (
                        "The selected mode is already active."
                    ),
                }
            )

        return redirect(
            url_for("dashboard")
        )

    current_time = time.time()

    session[
        "session_timeout_mode"
    ] = selected_mode

    session[
        "session_last_activity_at"
    ] = current_time

    record_security_event(
        event_type=(
            "SESSION_TIMEOUT_MODE_CHANGED"
        ),
        outcome="INFO",
        user_id=int(
            user["user_id"]
        ),
        username=user["username"],
    )

    timeout_seconds = (
        get_session_idle_timeout_seconds()
    )

    message = (
        "Demonstration mode enabled."
        if selected_mode == "demo"
        else "Standard timeout enabled."
    )

    if is_ajax_request:
        return jsonify(
            {
                "success": True,
                "timeout_mode": selected_mode,
                "timeout_seconds": timeout_seconds,
                "remaining_seconds": timeout_seconds,
                "message": message,
            }
        )

    flash(
        message,
        "success",
    )

    return redirect(
        url_for("dashboard")
    )


@app.route(
    "/session-heartbeat",
    methods=["POST"],
)
@login_required
@limiter.limit("120 per minute")
def session_heartbeat(
    user: Any,
) -> Response:
    session[
        "session_last_activity_at"
    ] = time.time()

    timeout_seconds = (
        get_session_idle_timeout_seconds()
    )

    return jsonify(
        {
            "success": True,
            "remaining_seconds": timeout_seconds,
            "timeout_mode": (
                get_session_timeout_mode()
            ),
        }
    )


@app.route(
    "/session-expired",
    methods=["POST"],
)
@login_required
def session_expired(
    user: Any,
) -> Response:
    return expire_authenticated_session()


# =========================================================
# Secure password change
# =========================================================
@app.route(
    "/change-password",
    methods=["GET", "POST"],
)
@login_required
@limiter.limit(
    "20 per 10 minutes",
    methods=["POST"],
)
def change_password(
    user: Any,
) -> str | Response:
    current_time = time.time()

    locked_until = float(
        user[
            "password_change_locked_until"
        ]
        or 0
    )

    if locked_until > current_time:
        remaining_seconds = max(
            1,
            math.ceil(
                locked_until
                - current_time
            ),
        )

        flash(
            "Password change is temporarily locked. "
            f"Try again in {remaining_seconds} second(s).",
            "error",
        )

        return redirect(
            url_for("dashboard")
        )

    if locked_until:
        clear_password_change_lockout(
            int(
                user["user_id"]
            )
        )

        record_security_event(
            event_type=(
                "PASSWORD_CHANGE_UNLOCKED"
            ),
            outcome="INFO",
            user_id=int(
                user["user_id"]
            ),
            username=user["username"],
        )

        refreshed_user = get_user_by_id(
            int(
                user["user_id"]
            )
        )

        if refreshed_user is not None:
            user = refreshed_user

    max_attempts = int(
        app.config[
            "PASSWORD_CHANGE_MAX_CURRENT_ATTEMPTS"
        ]
    )

    attempts_remaining = max(
        0,
        max_attempts
        - int(
            user[
                "password_change_current_attempts"
            ]
            or 0
        ),
    )

    errors: list[str] = []
    password_result = None

    if request.method == "POST":
        current_password = request.form.get(
            "current_password",
            "",
        )

        new_password = request.form.get(
            "new_password",
            "",
        )

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        current_password_is_valid = (
            verify_password(
                user["password_hash"],
                current_password,
            )
        )

        if not current_password_is_valid:
            cooldown_seconds = (
                int(
                    app.config[
                        "PASSWORD_CHANGE_DEMO_COOLDOWN_SECONDS"
                    ]
                )
                if bool(
                    user["lockout_demo_mode"]
                )
                else int(
                    app.config[
                        "PASSWORD_CHANGE_STANDARD_COOLDOWN_SECONDS"
                    ]
                )
            )

            (
                failed_attempts,
                new_locked_until,
            ) = (
                register_failed_password_change_attempt(
                    user_id=int(
                        user["user_id"]
                    ),
                    max_attempts=max_attempts,
                    cooldown_seconds=(
                        cooldown_seconds
                    ),
                    current_time=current_time,
                )
            )

            record_security_event(
                event_type=(
                    "PASSWORD_CHANGE_CURRENT_FAILURE"
                ),
                outcome="FAILURE",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

            if new_locked_until is not None:
                record_security_event(
                    event_type=(
                        "PASSWORD_CHANGE_LOCKED"
                    ),
                    outcome="FAILURE",
                    user_id=int(
                        user["user_id"]
                    ),
                    username=user["username"],
                )

                send_security_notification_safely(
                    recipient_email=(
                        user["email"]
                    ),
                    event_title=(
                        "Password change "
                        "temporarily locked"
                    ),
                    event_description=(
                        "The password-change feature "
                        "was temporarily locked after "
                        "repeated incorrect current-"
                        "password attempts."
                    ),
                )

                flash(
                    "Password change has been "
                    "temporarily locked after too "
                    "many incorrect current-password "
                    "attempts.",
                    "error",
                )

                return redirect(
                    url_for("dashboard")
                )

            attempts_remaining = max(
                0,
                max_attempts
                - failed_attempts,
            )

            errors.append(
                "The current password is incorrect. "
                f"{attempts_remaining} attempt(s) remain."
            )

        else:
            clear_password_change_lockout(
                int(
                    user["user_id"]
                )
            )

            attempts_remaining = max_attempts

            password_result = (
                evaluate_password_strength(
                    new_password,
                    user["username"],
                )
            )

            if not password_result[
                "is_valid"
            ]:
                errors.extend(
                    password_result[
                        "feedback"
                    ]
                )

            if (
                new_password
                != confirm_password
            ):
                errors.append(
                    "The new passwords do not match."
                )

            if verify_password(
                user["password_hash"],
                new_password,
            ):
                errors.append(
                    "The new password must differ "
                    "from the current password."
                )

            if not errors:
                pending_password_hash = (
                    hash_password(
                        new_password
                    )
                )

                try:
                    create_and_send_password_change_code(
                        int(
                            user["user_id"]
                        ),
                        user["email"],
                        pending_password_hash,
                    )

                except EmailDeliveryError:
                    errors.append(
                        "The password-change code "
                        "could not be sent."
                    )

                else:
                    record_security_event(
                        event_type=(
                            "PASSWORD_CHANGE_REQUEST"
                        ),
                        outcome="INFO",
                        user_id=int(
                            user["user_id"]
                        ),
                        username=user["username"],
                    )

                    flash(
                        "A password-change "
                        "verification code was sent "
                        "to your email.",
                        "success",
                    )

                    return redirect(
                        url_for(
                            "verify_password_change"
                        )
                    )

    return render_template(
        "change_password.html",
        user=user,
        errors=errors,
        password_result=password_result,

        change_password_attempts_remaining=(
            attempts_remaining
        ),

        change_password_max_attempts=(
            max_attempts
        ),
    )


@app.route(
    "/verify-password-change",
    methods=["GET", "POST"],
)
@login_required
@limiter.limit(
    "5 per 10 minutes",
    methods=["POST"],
)
def verify_password_change(
    user: Any,
) -> str | Response:
    user = get_user_by_id(
        int(user["user_id"])
    )

    if (
        user is None
        or not user[
            "pending_password_hash"
        ]
    ):
        flash(
            "Start the password-change process again.",
            "error",
        )
        return redirect(
            url_for("change_password")
        )

    errors: list[str] = []

    if request.method == "POST":
        submitted_code = request.form.get(
            "verification_code",
            "",
        ).strip()

        if (
            int(
                user[
                    "password_change_otp_attempts"
                ]
            )
            >= int(
                app.config[
                    "OTP_MAX_ATTEMPTS"
                ]
            )
        ):
            errors.append(
                "Too many incorrect code attempts."
            )

        elif not user[
            "password_change_otp_hash"
        ]:
            errors.append(
                "No active password-change code exists."
            )

        elif (
            not user[
                "password_change_otp_expires_at"
            ]
            or time.time()
            > float(
                user[
                    "password_change_otp_expires_at"
                ]
            )
        ):
            errors.append(
                "The password-change code has expired."
            )

        elif verify_otp_code(
            submitted_code,
            user[
                "password_change_otp_hash"
            ],
            app.config["SECRET_KEY"],
        ):
            changed = (
                apply_pending_password_change(
                    int(user["user_id"])
                )
            )

            if not changed:
                errors.append(
                    "The password change could not be completed."
                )

            else:
                record_security_event(
                    event_type=(
                        "PASSWORD_CHANGE_SUCCESS"
                    ),
                    outcome="SUCCESS",
                    user_id=int(
                        user["user_id"]
                    ),
                    username=user["username"],
                )

                send_security_notification_safely(
                    recipient_email=user["email"],
                    event_title=(
                        "Password changed successfully"
                    ),
                    event_description=(
                        "Your account password was changed "
                        "after current-password and email-code "
                        "verification."
                    ),
                )

                session.clear()

                flash(
                    "Your password was changed successfully. "
                    "Log in again using the new password.",
                    "success",
                )

                return redirect(
                    url_for("login")
                )

        else:
            increment_password_change_otp_attempts(
                int(user["user_id"])
            )

            errors.append(
                "The password-change code is incorrect."
            )

            record_security_event(
                event_type=(
                    "PASSWORD_CHANGE_CODE_FAILURE"
                ),
                outcome="FAILURE",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

    return render_template(
        "verify_password_change.html",
        user=user,
        errors=errors,
    )


@app.route(
    "/resend-password-change-code",
    methods=["POST"],
)
@login_required
@limiter.limit("3 per 10 minutes")
def resend_password_change_code(
    user: Any,
) -> Response:
    user = get_user_by_id(
        int(user["user_id"])
    )

    if (
        user is None
        or not user[
            "pending_password_hash"
        ]
    ):
        return redirect(
            url_for("change_password")
        )

    wait_seconds = get_resend_wait_seconds(
        user[
            "password_change_otp_expires_at"
        ],
        int(
            app.config[
                "PASSWORD_CHANGE_EXPIRY_SECONDS"
            ]
        ),
    )

    if wait_seconds > 0:
        flash(
            f"Please wait {wait_seconds} seconds.",
            "error",
        )
        return redirect(
            url_for(
                "verify_password_change"
            )
        )

    try:
        create_and_send_password_change_code(
            int(user["user_id"]),
            user["email"],
            user["pending_password_hash"],
        )

    except EmailDeliveryError:
        flash(
            "The new password-change code could not be sent.",
            "error",
        )

    else:
        flash(
            "A new password-change code was sent.",
            "success",
        )

    return redirect(
        url_for(
            "verify_password_change"
        )
    )


@app.route(
    "/cancel-password-change",
    methods=["POST"],
)
@login_required
def cancel_password_change(
    user: Any,
) -> Response:
    clear_password_change_request(
        int(user["user_id"])
    )

    flash(
        "Password change was cancelled.",
        "success",
    )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# Account deletion
# =========================================================

@app.route(
    "/delete-account",
    methods=["GET", "POST"],
)
@login_required
@limiter.limit(
    "5 per 10 minutes",
    methods=["POST"],
)
def delete_account(
    user: Any,
) -> str | Response:
    errors: list[str] = []

    if request.method == "POST":
        current_password = request.form.get(
            "current_password",
            "",
        )

        if not verify_password(
            user["password_hash"],
            current_password,
        ):
            errors.append(
                "The current password is incorrect."
            )

            record_security_event(
                event_type=(
                    "ACCOUNT_DELETION_PASSWORD_FAILURE"
                ),
                outcome="FAILURE",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

        else:
            try:
                create_and_send_delete_code(
                    int(user["user_id"]),
                    user["email"],
                )

            except EmailDeliveryError:
                errors.append(
                    "The account-deletion code could not be sent."
                )

            else:
                record_security_event(
                    event_type=(
                        "ACCOUNT_DELETION_REQUEST"
                    ),
                    outcome="INFO",
                    user_id=int(
                        user["user_id"]
                    ),
                    username=user["username"],
                )

                send_security_notification_safely(
                    recipient_email=user["email"],
                    event_title=(
                        "Account deletion requested"
                    ),
                    event_description=(
                        "A request to permanently delete "
                        "your account was started."
                    ),
                )

                flash(
                    "A six-digit account-deletion code "
                    "was sent to your email.",
                    "success",
                )

                return redirect(
                    url_for(
                        "confirm_delete_account"
                    )
                )

    return render_template(
        "delete_account.html",
        user=user,
        errors=errors,
    )


@app.route(
    "/confirm-delete-account",
    methods=["GET", "POST"],
)
@login_required
@limiter.limit(
    "10 per 10 minutes",
    methods=["POST"],
)
def confirm_delete_account(
    user: Any,
) -> str | Response:
    pending_user_id = session.get(
        "pending_delete_user_id"
    )

    if (
        not pending_user_id
        or int(pending_user_id)
        != int(user["user_id"])
    ):
        clear_pending_account_deletion()

        flash(
            "Begin the account-deletion process again.",
            "error",
        )

        return redirect(
            url_for("delete_account")
        )

    errors: list[str] = []

    if request.method == "POST":
        submitted_code = request.form.get(
            "verification_code",
            "",
        ).strip()

        confirmation_text = request.form.get(
            "confirmation_text",
            "",
        ).strip()

        deletion_confirmed = request.form.get(
            "deletion_confirmed",
            "",
        )

        stored_code_hash = session.get(
            "delete_otp_hash",
            "",
        )

        expires_at = get_session_timestamp(
            "delete_otp_expires_at",
            0.0,
        )

        attempts = int(
            session.get(
                "delete_otp_attempts",
                0,
            )
            or 0
        )

        if deletion_confirmed != "yes":
            errors.append(
                "Confirm that the deletion is permanent."
            )

        if confirmation_text != "DELETE":
            errors.append(
                'Type "DELETE" exactly.'
            )

        if (
            attempts
            >= int(
                app.config[
                    "OTP_MAX_ATTEMPTS"
                ]
            )
        ):
            errors.append(
                "Too many incorrect code attempts."
            )

        elif not stored_code_hash:
            errors.append(
                "No active deletion code exists."
            )

        elif time.time() > expires_at:
            errors.append(
                "The deletion code has expired."
            )

        elif not verify_otp_code(
            submitted_code,
            stored_code_hash,
            app.config["SECRET_KEY"],
        ):
            session[
                "delete_otp_attempts"
            ] = attempts + 1

            errors.append(
                "The account-deletion code is incorrect."
            )

            record_security_event(
                event_type=(
                    "ACCOUNT_DELETION_CODE_FAILURE"
                ),
                outcome="FAILURE",
                user_id=int(
                    user["user_id"]
                ),
                username=user["username"],
            )

        if not errors:
            deletion_user_id = int(
                user["user_id"]
            )

            deletion_username = str(
                user["username"]
            )

            account_deleted = delete_user(
                deletion_user_id
            )

            if account_deleted:
                record_security_event(
                    event_type="ACCOUNT_DELETED",
                    outcome="SUCCESS",
                    user_id=None,
                    username=deletion_username,
                )

            session.clear()

            if account_deleted:
                flash(
                    "Your account was permanently deleted.",
                    "success",
                )
                return redirect(
                    url_for("register")
                )

            flash(
                "The account could not be deleted.",
                "error",
            )
            return redirect(
                url_for("login")
            )

    return render_template(
        "confirm_delete.html",
        user=user,
        errors=errors,
    )


@app.route(
    "/resend-delete-code",
    methods=["POST"],
)
@login_required
@limiter.limit("3 per 10 minutes")
def resend_delete_code(
    user: Any,
) -> Response:
    pending_user_id = session.get(
        "pending_delete_user_id"
    )

    if (
        not pending_user_id
        or int(pending_user_id)
        != int(user["user_id"])
    ):
        return redirect(
            url_for("delete_account")
        )

    sent_at = get_session_timestamp(
        "delete_otp_sent_at",
        0.0,
    )

    wait_seconds = max(
        0,
        math.ceil(
            (
                sent_at
                + int(
                    app.config[
                        "OTP_RESEND_WAIT_SECONDS"
                    ]
                )
            )
            - time.time()
        ),
    )

    if wait_seconds > 0:
        flash(
            f"Please wait {wait_seconds} seconds.",
            "error",
        )
        return redirect(
            url_for(
                "confirm_delete_account"
            )
        )

    try:
        create_and_send_delete_code(
            int(user["user_id"]),
            user["email"],
        )

    except EmailDeliveryError:
        flash(
            "The new deletion code could not be sent.",
            "error",
        )

    else:
        flash(
            "A new deletion code was sent.",
            "success",
        )

    return redirect(
        url_for(
            "confirm_delete_account"
        )
    )


@app.route(
    "/cancel-account-deletion",
    methods=["POST"],
)
@login_required
def cancel_account_deletion(
    user: Any,
) -> Response:
    clear_pending_account_deletion()

    record_security_event(
        event_type=(
            "ACCOUNT_DELETION_CANCELLED"
        ),
        outcome="INFO",
        user_id=int(
            user["user_id"]
        ),
        username=user["username"],
    )

    flash(
        "Account deletion was cancelled.",
        "success",
    )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# Logout
# =========================================================

@app.route(
    "/logout",
    methods=["POST"],
)
@login_required
def logout(
    user: Any,
) -> Response:
    record_security_event(
        event_type="LOGOUT",
        outcome="SUCCESS",
        user_id=int(
            user["user_id"]
        ),
        username=user["username"],
    )

    session.clear()

    flash(
        "You have logged out securely.",
        "success",
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# Error handling
# =========================================================

@app.errorhandler(429)
def handle_rate_limit(
    error: Exception,
) -> Response:
    """
    Display an accurate countdown until the active
    Flask-Limiter window resets.
    """
    current_limit = limiter.current_limit

    reset_at = getattr(
        current_limit,
        "reset_at",
        None,
    )

    if reset_at is not None:
        retry_after_seconds = max(
            1,
            math.ceil(
                float(reset_at)
                - time.time()
            ),
        )

    else:
        retry_after_seconds = int(
            app.config[
                "LOGIN_RAPID_REQUEST_WINDOW_SECONDS"
            ]
        )

    is_ajax_request = (
        request.headers.get(
            "X-Requested-With",
            "",
        )
        == "XMLHttpRequest"
    )

    if is_ajax_request:
        response = jsonify(
            {
                "success": False,
                "message": (
                    "Rapid-request protection is active. "
                    "Please wait before trying again."
                ),
                "retry_after_seconds": (
                    retry_after_seconds
                ),
            }
        )

        response.status_code = 429

        response.headers[
            "Retry-After"
        ] = str(
            retry_after_seconds
        )

        return response

    response = app.make_response(
        (
            render_template(
                "error.html",
                title="Rapid Request Protection",
                message=(
                    "Too many requests were submitted "
                    "in a short period. Access is "
                    "temporarily limited."
                ),
                retry_after_seconds=(
                    retry_after_seconds
                ),
                return_url=request.path,
            ),
            429,
        )
    )

    response.headers[
        "Retry-After"
    ] = str(
        retry_after_seconds
    )

    return response


@app.errorhandler(413)
def handle_large_request(
    error: Exception,
) -> tuple[str, int]:
    return render_template(
        "error.html",
        title="Request Too Large",
        message=(
            "The submitted request was too large."
        ),
    ), 413


@app.errorhandler(404)
def handle_not_found(
    error: Exception,
) -> tuple[str, int]:
    return render_template(
        "error.html",
        title="Page Not Found",
        message=(
            "The requested page could not be found."
        ),
    ), 404


@app.errorhandler(500)
def handle_internal_error(
    error: Exception,
) -> tuple[str, int]:
    app.logger.exception(
        "Unexpected server error."
    )

    return render_template(
        "error.html",
        title="System Error",
        message=(
            "An unexpected error occurred. "
            "Please try again."
        ),
    ), 500


# =========================================================
# Initialisation
# =========================================================

with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(
        debug=True,
    )