from __future__ import annotations

import hashlib
import hmac
import io
import secrets
import string
from pathlib import Path

from PIL import (
    Image,
    ImageDraw,
    ImageFilter,
    ImageFont,
)


# CAPTCHA answers remain valid for three minutes.
CAPTCHA_EXPIRY_SECONDS = 180

# Avoid characters that are easy to confuse.
CAPTCHA_CHARACTERS = (
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "23456789"
)

CAPTCHA_LENGTH = 6
CAPTCHA_WIDTH = 260
CAPTCHA_HEIGHT = 90


_random = secrets.SystemRandom()


def _load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Load a readable font without depending on one specific computer."""
    possible_font_paths = (
        Path("C:/Windows/Fonts/arialbd.ttf"),
        Path("C:/Windows/Fonts/Arial.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    )

    for font_path in possible_font_paths:
        if font_path.exists():
            try:
                return ImageFont.truetype(
                    str(font_path),
                    size=size,
                )
            except OSError:
                continue

    return ImageFont.load_default()


def _normalise_captcha_answer(answer: str) -> str:
    """Normalise user input before hashing or comparison."""
    return "".join(
        answer.strip().upper().split()
    )


def generate_captcha() -> tuple[str, bytes]:
    """
    Generate a random CAPTCHA code and return PNG image bytes.

    Returns:
        A tuple containing the plain CAPTCHA code and PNG bytes.
    """
    code = "".join(
        secrets.choice(CAPTCHA_CHARACTERS)
        for _ in range(CAPTCHA_LENGTH)
    )

    image = Image.new(
        "RGB",
        (CAPTCHA_WIDTH, CAPTCHA_HEIGHT),
        color=(246, 249, 253),
    )

    draw = ImageDraw.Draw(image)

    # Add a light background pattern.
    for _ in range(8):
        start = (
            _random.randrange(0, CAPTCHA_WIDTH),
            _random.randrange(0, CAPTCHA_HEIGHT),
        )
        end = (
            _random.randrange(0, CAPTCHA_WIDTH),
            _random.randrange(0, CAPTCHA_HEIGHT),
        )
        draw.line(
            (start, end),
            fill=(
                _random.randrange(150, 215),
                _random.randrange(165, 225),
                _random.randrange(180, 235),
            ),
            width=_random.randrange(1, 3),
        )

    for _ in range(140):
        x = _random.randrange(0, CAPTCHA_WIDTH)
        y = _random.randrange(0, CAPTCHA_HEIGHT)
        radius = _random.randrange(1, 3)

        draw.ellipse(
            (x, y, x + radius, y + radius),
            fill=(
                _random.randrange(120, 210),
                _random.randrange(130, 220),
                _random.randrange(150, 230),
            ),
        )

    font = _load_font(45)
    character_spacing = CAPTCHA_WIDTH / (CAPTCHA_LENGTH + 1)

    for index, character in enumerate(code, start=1):
        character_layer = Image.new(
            "RGBA",
            (70, 70),
            color=(0, 0, 0, 0),
        )
        character_draw = ImageDraw.Draw(character_layer)

        bounding_box = character_draw.textbbox(
            (0, 0),
            character,
            font=font,
        )

        text_width = bounding_box[2] - bounding_box[0]
        text_height = bounding_box[3] - bounding_box[1]

        character_draw.text(
            (
                (70 - text_width) / 2,
                (70 - text_height) / 2 - bounding_box[1],
            ),
            character,
            font=font,
            fill=(
                _random.randrange(20, 90),
                _random.randrange(35, 105),
                _random.randrange(70, 145),
                255,
            ),
        )

        angle = _random.randrange(-22, 23)

        try:
            resampling_filter = Image.Resampling.BICUBIC
        except AttributeError:
            resampling_filter = Image.BICUBIC

        character_layer = character_layer.rotate(
            angle,
            resample=resampling_filter,
            expand=True,
        )

        x_position = int(
            index * character_spacing
            - character_layer.width / 2
        )

        y_position = int(
            CAPTCHA_HEIGHT / 2
            - character_layer.height / 2
            + _random.randrange(-7, 8)
        )

        image.paste(
            character_layer,
            (x_position, y_position),
            character_layer,
        )

    image = image.filter(
        ImageFilter.SMOOTH
    )

    output = io.BytesIO()
    image.save(
        output,
        format="PNG",
        optimize=True,
    )

    return code, output.getvalue()


def hash_captcha_answer(
    answer: str,
    secret_key: str,
) -> str:
    """Create an HMAC hash of the CAPTCHA answer for session storage."""
    normalised_answer = _normalise_captcha_answer(
        answer
    )

    return hmac.new(
        key=secret_key.encode("utf-8"),
        msg=normalised_answer.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_captcha_answer(
    supplied_answer: str,
    expected_hash: str,
    secret_key: str,
) -> bool:
    """Safely compare the submitted CAPTCHA answer with the stored hash."""
    if not supplied_answer or not expected_hash:
        return False

    supplied_hash = hash_captcha_answer(
        supplied_answer,
        secret_key,
    )

    return hmac.compare_digest(
        supplied_hash,
        expected_hash,
    )