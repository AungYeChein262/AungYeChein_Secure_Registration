from __future__ import annotations

import hashlib
import hmac
import secrets


OTP_LENGTH = 6


def generate_otp_code() -> str:
    """
    Generate a cryptographically secure six-digit code.

    Leading zeroes are retained, for example: 038491.
    """
    number = secrets.randbelow(1_000_000)

    return f"{number:06d}"


def normalise_otp_code(code: str) -> str:
    """
    Remove spaces from a submitted verification code.
    """
    return "".join(code.split())


def is_valid_otp_format(code: str) -> bool:
    """
    Confirm that the code contains exactly six digits.
    """
    normalised_code = normalise_otp_code(code)

    return (
        len(normalised_code) == OTP_LENGTH
        and normalised_code.isdigit()
    )


def hash_otp_code(
    code: str,
    secret_key: str,
) -> str:
    """
    Protect a verification code using HMAC-SHA256.

    The readable code should not be stored in the database
    or session.
    """
    normalised_code = normalise_otp_code(code)

    return hmac.new(
        secret_key.encode("utf-8"),
        normalised_code.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_otp_code(
    submitted_code: str,
    expected_hash: str,
    secret_key: str,
) -> bool:
    """
    Securely compare a submitted code with its stored hash.
    """
    if not expected_hash:
        return False

    if not is_valid_otp_format(submitted_code):
        return False

    submitted_hash = hash_otp_code(
        submitted_code,
        secret_key,
    )

    return hmac.compare_digest(
        submitted_hash,
        expected_hash,
    )