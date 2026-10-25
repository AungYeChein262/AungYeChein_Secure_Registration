from __future__ import annotations

import re
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


# PasswordHasher uses Argon2id and generates a random salt automatically.
password_hasher = PasswordHasher()


# A small demonstration list of passwords that should never be accepted.
COMMON_PASSWORDS = {
    "123456",
    "12345678",
    "123456789",
    "password",
    "password1",
    "qwerty",
    "qwerty123",
    "admin",
    "administrator",
    "letmein",
    "welcome",
    "welcome123",
    "iloveyou",
    "abc123",
    "monkey",
    "dragon",
    "football",
}


OBVIOUS_SEQUENCES = {
    "012345",
    "123456",
    "234567",
    "345678",
    "456789",
    "987654",
    "876543",
    "765432",
    "abcdef",
    "bcdefg",
    "qwerty",
    "asdfgh",
    "zxcvbn",
}


def contains_obvious_sequence(password: str) -> bool:
    """
    Return True when the password contains a predictable sequence.
    """
    password_lower = password.lower()

    return any(
        sequence in password_lower
        for sequence in OBVIOUS_SEQUENCES
    )


def contains_repeated_characters(password: str) -> bool:
    """
    Detect four or more identical consecutive characters,
    such as aaaa or 1111.
    """
    return re.search(r"(.)\1{3,}", password) is not None


def evaluate_password_strength(
    password: str,
    username: str = "",
) -> dict[str, Any]:
    """
    Calculate password strength and return detailed feedback.

    Strength is scored from 0 to 8:
        0-2 = Weak
        3-4 = Fair
        5-6 = Good
        7-8 = Strong

    A password must also satisfy every mandatory requirement
    before it can be accepted.
    """

    username_lower = username.strip().lower()
    password_lower = password.lower()

    has_minimum_length = len(password) >= 12
    has_acceptable_length = len(password) <= 128
    has_lowercase = bool(re.search(r"[a-z]", password))
    has_uppercase = bool(re.search(r"[A-Z]", password))
    has_number = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    is_common = password_lower in COMMON_PASSWORDS
    has_sequence = contains_obvious_sequence(password)
    has_repetition = contains_repeated_characters(password)

    contains_username = (
        len(username_lower) >= 3
        and username_lower in password_lower
    )

    has_outer_spaces = password != password.strip()

    requirements = {
        "minimum_length": has_minimum_length,
        "maximum_length": has_acceptable_length,
        "lowercase": has_lowercase,
        "uppercase": has_uppercase,
        "number": has_number,
        "special_character": has_special,
        "not_common": not is_common,
        "no_sequence": not has_sequence,
        "no_repetition": not has_repetition,
        "no_username": not contains_username,
        "no_outer_spaces": not has_outer_spaces,
    }

    score = 0

    # Length contributes up to three points.
    if len(password) >= 8:
        score += 1

    if len(password) >= 12:
        score += 1

    if len(password) >= 16:
        score += 1

    # Character variety contributes up to four points.
    score += int(has_lowercase)
    score += int(has_uppercase)
    score += int(has_number)
    score += int(has_special)

    character_types = sum(
        [
            has_lowercase,
            has_uppercase,
            has_number,
            has_special,
        ]
    )

    # Award an additional point for using all four character types.
    if character_types == 4:
        score += 1

    # Apply deductions for predictable patterns.
    if is_common:
        score -= 4

    if contains_username:
        score -= 2

    if has_sequence:
        score -= 2

    if has_repetition:
        score -= 1

    score = max(0, min(score, 8))

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Fair"
    elif score <= 6:
        strength = "Good"
    else:
        strength = "Strong"

    feedback: list[str] = []

    if not has_minimum_length:
        feedback.append("Use at least 12 characters.")

    if not has_acceptable_length:
        feedback.append("Use no more than 128 characters.")

    if not has_lowercase:
        feedback.append("Add a lowercase letter.")

    if not has_uppercase:
        feedback.append("Add an uppercase letter.")

    if not has_number:
        feedback.append("Add a number.")

    if not has_special:
        feedback.append("Add a special character.")

    if is_common:
        feedback.append("Do not use a commonly used password.")

    if contains_username:
        feedback.append("Do not include the username in the password.")

    if has_sequence:
        feedback.append("Avoid predictable sequences such as 123456 or qwerty.")

    if has_repetition:
        feedback.append("Avoid repeating the same character four or more times.")

    if has_outer_spaces:
        feedback.append("Remove spaces from the beginning or end.")

    is_valid = all(requirements.values())

    if is_valid:
        feedback.append("The password meets all security requirements.")

    return {
        "score": score,
        "maximum_score": 8,
        "strength": strength,
        "is_valid": is_valid,
        "requirements": requirements,
        "feedback": feedback,
    }


def hash_password(password: str) -> str:
    """
    Convert a readable password into an Argon2id password hash.
    """
    if not password:
        raise ValueError("The password cannot be empty.")

    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """
    Check whether a password matches an existing Argon2 hash.
    """
    try:
        return password_hasher.verify(password_hash, password)
    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
    ):
        return False