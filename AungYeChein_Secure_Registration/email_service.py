from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from flask import current_app


class EmailDeliveryError(Exception):
    """
    Raised when an application email cannot be delivered.
    """


ALLOWED_EMAIL_PURPOSES = {
    "registration",
    "login",
    "delete_account",
    "password_reset",
    "password_change",
    "test",
}


PURPOSE_NAMES = {
    "registration": "account registration",
    "login": "secure login",
    "delete_account": "account deletion",
    "password_reset": "password reset",
    "password_change": "password change",
    "test": "email service test",
}


PURPOSE_SUBJECTS = {
    "registration":
        "CET324 Account Registration Verification Code",
    "login":
        "CET324 Secure Login Verification Code",
    "delete_account":
        "CET324 Account Deletion Verification Code",
    "password_reset":
        "CET324 Password Reset Verification Code",
    "password_change":
        "CET324 Password Change Verification Code",
    "test":
        "CET324 Email Service Test Code",
}


def validate_mail_configuration() -> None:
    mail_server = current_app.config.get(
        "MAIL_SERVER",
        "",
    )

    mail_port = current_app.config.get(
        "MAIL_PORT",
        0,
    )

    username = current_app.config.get(
        "MAIL_USERNAME",
        "",
    )

    app_password = current_app.config.get(
        "MAIL_APP_PASSWORD",
        "",
    )

    if not mail_server:
        raise EmailDeliveryError(
            "MAIL_SERVER is missing from the configuration."
        )

    if not mail_port:
        raise EmailDeliveryError(
            "MAIL_PORT is missing from the configuration."
        )

    if not username:
        raise EmailDeliveryError(
            "MAIL_USERNAME is missing from the .env file."
        )

    if not app_password:
        raise EmailDeliveryError(
            "MAIL_APP_PASSWORD is missing from the .env file."
        )


def validate_email_purpose(
    purpose: str,
) -> None:
    if purpose not in ALLOWED_EMAIL_PURPOSES:
        raise ValueError(
            "Unsupported verification-email purpose."
        )


def build_verification_message(
    recipient_email: str,
    verification_code: str,
    purpose: str,
) -> EmailMessage:
    """
    Build a plain-text one-time-code email.
    """
    validate_email_purpose(
        purpose
    )

    recipient_email = (
        recipient_email.strip()
    )

    if not recipient_email:
        raise ValueError(
            "A recipient email address is required."
        )

    if (
        len(verification_code) != 6
        or not verification_code.isdigit()
    ):
        raise ValueError(
            "The verification code must contain "
            "exactly six digits."
        )

    sender_email = current_app.config[
        "MAIL_USERNAME"
    ]

    sender_name = current_app.config[
        "MAIL_SENDER_NAME"
    ]

    if purpose == "password_reset":
        expiry_seconds = current_app.config[
            "PASSWORD_RESET_EXPIRY_SECONDS"
        ]

    elif purpose == "password_change":
        expiry_seconds = current_app.config[
            "PASSWORD_CHANGE_EXPIRY_SECONDS"
        ]

    else:
        expiry_seconds = current_app.config[
            "OTP_EXPIRY_SECONDS"
        ]

    expiry_minutes = max(
        1,
        int(expiry_seconds) // 60,
    )

    message = EmailMessage()

    message["Subject"] = (
        PURPOSE_SUBJECTS[purpose]
    )

    message["From"] = formataddr(
        (
            sender_name,
            sender_email,
        )
    )

    message["To"] = recipient_email

    message.set_content(
        f"""
CET324 Secure Registration System

Your verification code for {PURPOSE_NAMES[purpose]} is:

{verification_code}

This code expires in approximately {expiry_minutes} minute(s)
and can only be used once.

Do not share this code with anyone.

If you did not request this action, ignore this email and
consider changing your password.
""".strip()
    )

    return message


def build_security_notification_message(
    recipient_email: str,
    event_title: str,
    event_details: str,
) -> EmailMessage:
    """
    Build a notification for a security-sensitive account event.

    The details must never contain passwords, OTPs, CAPTCHA
    answers, session tokens or email credentials.
    """
    recipient_email = (
        recipient_email.strip()
    )

    event_title = (
        event_title.strip()[:100]
        or "Security event"
    )

    event_details = (
        event_details.strip()[:1200]
        or "A security-sensitive account event occurred."
    )

    if not recipient_email:
        raise ValueError(
            "A recipient email address is required."
        )

    sender_email = current_app.config[
        "MAIL_USERNAME"
    ]

    sender_name = current_app.config[
        "MAIL_SENDER_NAME"
    ]

    message = EmailMessage()

    message["Subject"] = (
        f"CET324 Security Alert: {event_title}"
    )

    message["From"] = formataddr(
        (
            sender_name,
            sender_email,
        )
    )

    message["To"] = recipient_email

    message.set_content(
        f"""
CET324 Secure Registration System

Security event: {event_title}

{event_details}

If you recognise this activity, no action is required.
If you do not recognise it, reset your password immediately.

This message never contains your password or verification code.
""".strip()
    )

    return message


def _send_message(
    message: EmailMessage,
) -> None:
    """
    Send a prepared message using an encrypted SMTP connection.
    """
    validate_mail_configuration()

    mail_server = current_app.config[
        "MAIL_SERVER"
    ]

    mail_port = current_app.config[
        "MAIL_PORT"
    ]

    mail_username = current_app.config[
        "MAIL_USERNAME"
    ]

    mail_password = current_app.config[
        "MAIL_APP_PASSWORD"
    ]

    mail_use_ssl = current_app.config.get(
        "MAIL_USE_SSL",
        True,
    )

    timeout_seconds = current_app.config.get(
        "MAIL_TIMEOUT_SECONDS",
        20,
    )

    ssl_context = ssl.create_default_context()

    try:
        if mail_use_ssl:
            with smtplib.SMTP_SSL(
                host=mail_server,
                port=mail_port,
                context=ssl_context,
                timeout=timeout_seconds,
            ) as smtp_connection:
                smtp_connection.login(
                    mail_username,
                    mail_password,
                )

                smtp_connection.send_message(
                    message
                )

        else:
            with smtplib.SMTP(
                host=mail_server,
                port=mail_port,
                timeout=timeout_seconds,
            ) as smtp_connection:
                smtp_connection.ehlo()

                smtp_connection.starttls(
                    context=ssl_context
                )

                smtp_connection.ehlo()

                smtp_connection.login(
                    mail_username,
                    mail_password,
                )

                smtp_connection.send_message(
                    message
                )

    except smtplib.SMTPAuthenticationError as error:
        current_app.logger.exception(
            "SMTP authentication failed."
        )

        raise EmailDeliveryError(
            "Email authentication failed. Check the sender "
            "email address and Gmail app password."
        ) from error

    except smtplib.SMTPRecipientsRefused as error:
        current_app.logger.exception(
            "The recipient email address was refused."
        )

        raise EmailDeliveryError(
            "The recipient email address was refused."
        ) from error

    except smtplib.SMTPSenderRefused as error:
        current_app.logger.exception(
            "The sender email address was refused."
        )

        raise EmailDeliveryError(
            "The sender email address was refused."
        ) from error

    except (
        smtplib.SMTPException,
        OSError,
        TimeoutError,
    ) as error:
        current_app.logger.exception(
            "The email could not be delivered."
        )

        raise EmailDeliveryError(
            "The email could not be sent."
        ) from error


def send_verification_code(
    recipient_email: str,
    verification_code: str,
    purpose: str = "login",
) -> None:
    validate_mail_configuration()
    validate_email_purpose(
        purpose
    )

    message = build_verification_message(
        recipient_email=recipient_email,
        verification_code=verification_code,
        purpose=purpose,
    )

    _send_message(
        message
    )


def send_security_notification(
    recipient_email: str,
    event_title: str,
    event_details: str,
) -> None:
    """
    Send a security notification that contains no secret values.
    """
    validate_mail_configuration()

    message = (
        build_security_notification_message(
            recipient_email=recipient_email,
            event_title=event_title,
            event_details=event_details,
        )
    )

    _send_message(
        message
    )