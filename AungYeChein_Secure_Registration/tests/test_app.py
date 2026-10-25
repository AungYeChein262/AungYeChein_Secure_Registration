from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import app as app_module
import database
from password_security import (
    evaluate_password_strength,
    hash_password,
    verify_password,
)


class SecureRegistrationAppTests(
    unittest.TestCase
):
    """
    Automated security and functionality tests.

    Every test uses:
    - A temporary SQLite database
    - Disabled CSRF protection
    - Disabled rate limiting
    - Mock email delivery
    """

    TEST_PASSWORD = "Violet!Cedar9Orbit"
    SECOND_PASSWORD = "Copper#Falcon8Meadow"
    THIRD_PASSWORD = "Harbour$Quartz6Forest"

    CAPTCHA_ANSWER = "AB12CD"

    def setUp(self) -> None:
        """
        Prepare a clean test application and database.
        """
        self.temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        self.database_path = (
            Path(
                self.temporary_directory.name
            )
            / "test_users.db"
        )

        app_module.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            RATELIMIT_ENABLED=False,
            SECRET_KEY=(
                "test-secret-key-"
                "used-only-for-automated-tests"
            ),
            DATABASE_PATH=self.database_path,

            OTP_EXPIRY_SECONDS=300,
            OTP_MAX_ATTEMPTS=5,
            OTP_RESEND_WAIT_SECONDS=0,

            LOGIN_LOCKOUT_MAX_ATTEMPTS=5,
            LOGIN_LOCKOUT_STANDARD_SECONDS=300,
            LOGIN_LOCKOUT_DEMO_SECONDS=10,

            PASSWORD_RESET_EXPIRY_SECONDS=600,

            PASSWORD_CHANGE_EXPIRY_SECONDS=300,
            PASSWORD_CHANGE_MAX_CURRENT_ATTEMPTS=3,
            PASSWORD_CHANGE_STANDARD_COOLDOWN_SECONDS=300,
            PASSWORD_CHANGE_DEMO_COOLDOWN_SECONDS=10,

            SESSION_IDLE_TIMEOUT_STANDARD_SECONDS=900,
            SESSION_IDLE_TIMEOUT_DEMO_SECONDS=5,
            SESSION_ABSOLUTE_TIMEOUT_SECONDS=7200,
        )

        try:
            app_module.limiter.enabled = False
        except (
            AttributeError,
            TypeError,
        ):
            pass

        with app_module.app.app_context():
            database.init_db()

        self.client = (
            app_module.app.test_client()
        )

        self.sent_verification_codes: dict[
            str,
            list[dict[str, str]]
        ] = {}

        self.sent_notifications: list[
            dict[str, str]
        ] = []

        self.verification_email_patcher = (
            patch.object(
                app_module,
                "send_verification_code",
                side_effect=(
                    self._fake_send_verification_code
                ),
            )
        )

        self.notification_email_patcher = (
            patch.object(
                app_module,
                "send_security_notification",
                side_effect=(
                    self._fake_send_security_notification
                ),
            )
        )

        self.verification_email_patcher.start()
        self.notification_email_patcher.start()

    def tearDown(self) -> None:
        """
        Stop mocks and remove the temporary database.
        """
        self.verification_email_patcher.stop()
        self.notification_email_patcher.stop()

        self.temporary_directory.cleanup()

    # =====================================================
    # Mock email helpers
    # =====================================================

    def _fake_send_verification_code(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Capture OTPs instead of sending real emails.
        """
        recipient_email = kwargs.get(
            "recipient_email"
        )

        verification_code = kwargs.get(
            "verification_code"
        )

        purpose = kwargs.get(
            "purpose"
        )

        if recipient_email is None and args:
            recipient_email = args[0]

        if (
            verification_code is None
            and len(args) > 1
        ):
            verification_code = args[1]

        if purpose is None and len(args) > 2:
            purpose = args[2]

        safe_purpose = str(
            purpose or "unknown"
        )

        self.sent_verification_codes.setdefault(
            safe_purpose,
            [],
        ).append(
            {
                "recipient_email": str(
                    recipient_email or ""
                ),
                "verification_code": str(
                    verification_code or ""
                ),
            }
        )

    def _fake_send_security_notification(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Capture security notifications without Gmail.
        """
        recipient_email = kwargs.get(
            "recipient_email"
        )

        event_title = kwargs.get(
            "event_title"
        )

        event_details = kwargs.get(
            "event_details"
        )

        if recipient_email is None and args:
            recipient_email = args[0]

        if (
            event_title is None
            and len(args) > 1
        ):
            event_title = args[1]

        if (
            event_details is None
            and len(args) > 2
        ):
            event_details = args[2]

        self.sent_notifications.append(
            {
                "recipient_email": str(
                    recipient_email or ""
                ),
                "event_title": str(
                    event_title or ""
                ),
                "event_details": str(
                    event_details or ""
                ),
            }
        )

    def _latest_code(
        self,
        purpose: str,
    ) -> str:
        """
        Return the newest mocked OTP for a purpose.
        """
        messages = (
            self.sent_verification_codes.get(
                purpose,
                [],
            )
        )

        self.assertTrue(
            messages,
            (
                "No verification code was captured "
                f"for purpose: {purpose}"
            ),
        )

        return messages[-1][
            "verification_code"
        ]

    # =====================================================
    # Database and session helpers
    # =====================================================

    def _create_verified_user(
        self,
        email: str = "test@example.com",
        username: str = "test_user",
        password: str | None = None,
    ) -> int:
        """
        Create a verified account directly in the test DB.
        """
        selected_password = (
            password
            or self.TEST_PASSWORD
        )

        with app_module.app.app_context():
            user_id = database.create_user(
                email=email,
                username=username,
                password_hash=hash_password(
                    selected_password
                ),
                registration_otp_hash="",
                registration_otp_expires_at=0.0,
            )

            database.mark_email_verified(
                user_id
            )

            return user_id

    def _get_user_by_id(
        self,
        user_id: int,
    ) -> dict[str, Any] | None:
        """
        Retrieve a user as a normal dictionary.
        """
        with app_module.app.app_context():
            user = database.get_user_by_id(
                user_id
            )

            if user is None:
                return None

            return dict(user)

    def _get_user_by_identity(
        self,
        identity: str,
    ) -> dict[str, Any] | None:
        with app_module.app.app_context():
            user = database.get_user_by_identity(
                identity
            )

            if user is None:
                return None

            return dict(user)

    def _authenticate_session(
        self,
        user_id: int,
        timeout_mode: str = "standard",
        last_activity_at: float | None = None,
    ) -> None:
        """
        Create a valid authenticated browser session.
        """
        current_time = time.time()

        with self.client.session_transaction() as session:
            session.clear()

            session[
                "authenticated_user_id"
            ] = user_id

            session[
                "session_timeout_mode"
            ] = timeout_mode

            session[
                "session_started_at"
            ] = current_time

            session[
                "session_last_activity_at"
            ] = (
                last_activity_at
                if last_activity_at is not None
                else current_time
            )

    def _set_valid_captcha_session(
        self,
    ) -> None:
        """
        Put a valid CAPTCHA answer into the signed session.
        """
        protected_answer = (
            app_module.hash_captcha_answer(
                self.CAPTCHA_ANSWER,
                app_module.app.config[
                    "SECRET_KEY"
                ],
            )
        )

        with self.client.session_transaction() as session:
            session[
                "captcha_answer_hash"
            ] = protected_answer

            session[
                "captcha_created_at"
            ] = time.time()

    def _set_user_lockout_demo_mode(
        self,
        user_id: int,
        enabled: bool = True,
    ) -> None:
        with app_module.app.app_context():
            database.set_lockout_demo_mode(
                user_id,
                enabled,
            )

    def _set_database_value(
        self,
        user_id: int,
        column_name: str,
        value: Any,
    ) -> None:
        """
        Update a test-only database column.

        column_name is only used with fixed values written
        inside this test module.
        """
        allowed_columns = {
            "locked_until",
            "password_change_locked_until",
        }

        if column_name not in allowed_columns:
            raise ValueError(
                "Unsupported test column."
            )

        with app_module.app.app_context():
            connection = database.get_db()

            connection.execute(
                f"""
                UPDATE users
                SET {column_name} = ?
                WHERE user_id = ?
                """,
                (
                    value,
                    user_id,
                ),
            )

            connection.commit()

    def _audit_event_types(
        self,
        user_id: int,
    ) -> list[str]:
        with app_module.app.app_context():
            rows = (
                database.get_recent_audit_logs(
                    user_id,
                    limit=20,
                )
            )

            return [
                str(row["event_type"])
                for row in rows
            ]

    def _assert_redirect_path(
        self,
        response: Any,
        expected_path: str,
    ) -> None:
        self.assertEqual(
            response.status_code,
            302,
        )

        location = response.headers.get(
            "Location",
            "",
        )

        self.assertTrue(
            location.endswith(
                expected_path
            ),
            (
                f"Expected redirect ending with "
                f"{expected_path!r}, received "
                f"{location!r}."
            ),
        )

    # =====================================================
    # Database migration tests
    # =====================================================

    def test_database_contains_security_columns(
        self,
    ) -> None:
        """
        Confirm that all additional security columns exist.
        """
        with app_module.app.app_context():
            connection = database.get_db()

            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(users)"
                ).fetchall()
            }

        required_columns = {
            "failed_login_attempts",
            "locked_until",
            "lockout_demo_mode",
            "password_reset_otp_hash",
            "password_reset_otp_expires_at",
            "password_reset_otp_attempts",
            "password_change_otp_hash",
            "password_change_otp_expires_at",
            "password_change_otp_attempts",
            "pending_password_hash",
            "password_change_current_attempts",
            "password_change_locked_until",
        }

        self.assertTrue(
            required_columns.issubset(
                columns
            )
        )

    # =====================================================
    # Password-strength tests
    # =====================================================

    def test_password_strength_algorithm(
        self,
    ) -> None:
        weak_result = (
            evaluate_password_strength(
                "password",
                "test_user",
            )
        )

        strong_result = (
            evaluate_password_strength(
                self.TEST_PASSWORD,
                "test_user",
            )
        )

        self.assertFalse(
            weak_result["is_valid"]
        )

        self.assertTrue(
            weak_result["feedback"]
        )

        self.assertTrue(
            strong_result["is_valid"],
            strong_result["feedback"],
        )

    # =====================================================
    # Registration tests
    # =====================================================

    def test_registration_rejects_missing_captcha(
        self,
    ) -> None:
        response = self.client.post(
            "/",
            data={
                "email":
                    "captcha-test@example.com",

                "username":
                    "captcha_user",

                "password":
                    self.TEST_PASSWORD,

                "confirm_password":
                    self.TEST_PASSWORD,

                "human_check":
                    "",

                "captcha_answer":
                    "",
            },
            follow_redirects=True,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertIn(
            b"Confirm that you are not a robot",
            response.data,
        )

        user = self._get_user_by_identity(
            "captcha_user"
        )

        self.assertIsNone(user)

    def test_registration_and_email_verification(
        self,
    ) -> None:
        self._set_valid_captcha_session()

        registration_response = (
            self.client.post(
                "/",
                data={
                    "email":
                        "new-user@example.com",

                    "username":
                        "new_user",

                    "password":
                        self.TEST_PASSWORD,

                    "confirm_password":
                        self.TEST_PASSWORD,

                    "human_check":
                        "yes",

                    "captcha_answer":
                        self.CAPTCHA_ANSWER,
                },
                follow_redirects=False,
            )
        )

        self._assert_redirect_path(
            registration_response,
            "/verify-registration",
        )

        verification_code = (
            self._latest_code(
                "registration"
            )
        )

        verification_response = (
            self.client.post(
                "/verify-registration",
                data={
                    "verification_code":
                        verification_code,
                },
                follow_redirects=False,
            )
        )

        self._assert_redirect_path(
            verification_response,
            "/login",
        )

        user = self._get_user_by_identity(
            "new_user"
        )

        self.assertIsNotNone(user)

        assert user is not None

        self.assertEqual(
            int(user["email_verified"]),
            1,
        )

        audit_events = (
            self._audit_event_types(
                int(user["user_id"])
            )
        )

        self.assertIn(
            "REGISTRATION_SUCCESS",
            audit_events,
        )

        self.assertIn(
            "EMAIL_VERIFICATION_SUCCESS",
            audit_events,
        )

    def test_duplicate_email_is_rejected(
        self,
    ) -> None:
        self._create_verified_user(
            email="duplicate@example.com",
            username="first_user",
        )

        self._set_valid_captcha_session()

        response = self.client.post(
            "/",
            data={
                "email":
                    "duplicate@example.com",

                "username":
                    "second_user",

                "password":
                    self.TEST_PASSWORD,

                "confirm_password":
                    self.TEST_PASSWORD,

                "human_check":
                    "yes",

                "captcha_answer":
                    self.CAPTCHA_ANSWER,
            },
            follow_redirects=True,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertIn(
            b"already registered",
            response.data,
        )

    # =====================================================
    # Login and MFA tests
    # =====================================================

    def test_login_password_and_email_otp(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user()
        )

        password_response = (
            self.client.post(
                "/login",
                data={
                    "identity":
                        "test_user",

                    "password":
                        self.TEST_PASSWORD,
                },
                follow_redirects=False,
            )
        )

        self._assert_redirect_path(
            password_response,
            "/verify-login",
        )

        login_code = self._latest_code(
            "login"
        )

        otp_response = self.client.post(
            "/verify-login",
            data={
                "verification_code":
                    login_code,
            },
            follow_redirects=False,
        )

        self._assert_redirect_path(
            otp_response,
            "/dashboard",
        )

        dashboard_response = (
            self.client.get(
                "/dashboard"
            )
        )

        self.assertEqual(
            dashboard_response.status_code,
            200,
        )

        self.assertIn(
            b"test_user",
            dashboard_response.data,
        )

        with self.client.session_transaction() as session:
            self.assertEqual(
                session.get(
                    "authenticated_user_id"
                ),
                user_id,
            )

        audit_events = (
            self._audit_event_types(
                user_id
            )
        )

        self.assertIn(
            "LOGIN_SUCCESS",
            audit_events,
        )

        notification_titles = {
            notification[
                "event_title"
            ]
            for notification
            in self.sent_notifications
        }

        self.assertIn(
            "Successful login",
            notification_titles,
        )

    # =====================================================
    # Login account-lockout tests
    # =====================================================

    def test_login_lockout_after_five_failures(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user(
                username="locked_user",
                email="locked@example.com",
            )
        )

        self._set_user_lockout_demo_mode(
            user_id,
            True,
        )

        for attempt_number in range(1, 6):
            response = self.client.post(
                "/login",
                data={
                    "identity":
                        "locked_user",

                    "password":
                        "Incorrect!Password9",
                },
                follow_redirects=True,
            )

            self.assertEqual(
                response.status_code,
                200,
            )

            if attempt_number < 5:
                self.assertIn(
                    b"incorrect",
                    response.data.lower(),
                )

        self.assertIn(
            b"temporarily unavailable",
            response.data.lower(),
        )

        user = self._get_user_by_id(
            user_id
        )

        assert user is not None

        self.assertGreater(
            float(
                user["locked_until"]
                or 0
            ),
            time.time(),
        )

        locked_response = self.client.post(
            "/login",
            data={
                "identity":
                    "locked_user",

                "password":
                    self.TEST_PASSWORD,
            },
            follow_redirects=True,
        )

        self.assertIn(
            b"temporarily unavailable",
            locked_response.data.lower(),
        )

        self._set_database_value(
            user_id,
            "locked_until",
            time.time() - 1,
        )

        unlocked_response = self.client.post(
            "/login",
            data={
                "identity":
                    "locked_user",

                "password":
                    self.TEST_PASSWORD,
            },
            follow_redirects=False,
        )

        self._assert_redirect_path(
            unlocked_response,
            "/verify-login",
        )

        audit_events = (
            self._audit_event_types(
                user_id
            )
        )

        self.assertIn(
            "ACCOUNT_LOCKED",
            audit_events,
        )

        self.assertIn(
            "LOCKED_LOGIN_ATTEMPT",
            audit_events,
        )

        self.assertIn(
            "ACCOUNT_UNLOCKED",
            audit_events,
        )

    # =====================================================
    # Forgotten-password tests
    # =====================================================

    def test_forgotten_password_reset(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user(
                username="reset_user",
                email="reset@example.com",
            )
        )

        request_response = (
            self.client.post(
                "/forgot-password",
                data={
                    "email":
                        "reset@example.com",
                },
                follow_redirects=False,
            )
        )

        self._assert_redirect_path(
            request_response,
            "/reset-password",
        )

        reset_code = self._latest_code(
            "password_reset"
        )

        reset_response = self.client.post(
            "/reset-password",
            data={
                "verification_code":
                    reset_code,

                "new_password":
                    self.SECOND_PASSWORD,

                "confirm_password":
                    self.SECOND_PASSWORD,
            },
            follow_redirects=False,
        )

        self._assert_redirect_path(
            reset_response,
            "/login",
        )

        user = self._get_user_by_id(
            user_id
        )

        assert user is not None

        self.assertTrue(
            verify_password(
                user["password_hash"],
                self.SECOND_PASSWORD,
            )
        )

        self.assertFalse(
            verify_password(
                user["password_hash"],
                self.TEST_PASSWORD,
            )
        )

        audit_events = (
            self._audit_event_types(
                user_id
            )
        )

        self.assertIn(
            "PASSWORD_RESET_SUCCESS",
            audit_events,
        )

    # =====================================================
    # Password-change lockout tests
    # =====================================================

    def test_password_change_locks_after_three_failures(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user(
                username="change_user",
                email="change@example.com",
            )
        )

        self._set_user_lockout_demo_mode(
            user_id,
            True,
        )

        self._authenticate_session(
            user_id
        )

        first_response = self.client.post(
            "/change-password",
            data={
                "current_password":
                    "Wrong!Password1",

                "new_password":
                    self.SECOND_PASSWORD,

                "confirm_password":
                    self.SECOND_PASSWORD,
            },
            follow_redirects=True,
        )

        self.assertIn(
            b"2 attempt(s) remain",
            first_response.data,
        )

        second_response = self.client.post(
            "/change-password",
            data={
                "current_password":
                    "Wrong!Password2",

                "new_password":
                    self.SECOND_PASSWORD,

                "confirm_password":
                    self.SECOND_PASSWORD,
            },
            follow_redirects=True,
        )

        self.assertIn(
            b"1 attempt(s) remain",
            second_response.data,
        )

        third_response = self.client.post(
            "/change-password",
            data={
                "current_password":
                    "Wrong!Password3",

                "new_password":
                    self.SECOND_PASSWORD,

                "confirm_password":
                    self.SECOND_PASSWORD,
            },
            follow_redirects=False,
        )

        self._assert_redirect_path(
            third_response,
            "/dashboard",
        )

        user = self._get_user_by_id(
            user_id
        )

        assert user is not None

        locked_until = float(
            user[
                "password_change_locked_until"
            ]
            or 0
        )

        self.assertGreater(
            locked_until,
            time.time(),
        )

        blocked_response = self.client.get(
            "/change-password",
            follow_redirects=False,
        )

        self._assert_redirect_path(
            blocked_response,
            "/dashboard",
        )

        self._set_database_value(
            user_id,
            "password_change_locked_until",
            time.time() - 1,
        )

        unlocked_response = self.client.get(
            "/change-password",
            follow_redirects=False,
        )

        self.assertEqual(
            unlocked_response.status_code,
            200,
        )

        audit_events = (
            self._audit_event_types(
                user_id
            )
        )

        self.assertIn(
            "PASSWORD_CHANGE_LOCKED",
            audit_events,
        )

        self.assertIn(
            "PASSWORD_CHANGE_UNLOCKED",
            audit_events,
        )

    def test_secure_password_change_with_email_code(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user(
                username="secure_change",
                email=(
                    "secure-change@example.com"
                ),
            )
        )

        self._authenticate_session(
            user_id
        )

        request_response = self.client.post(
            "/change-password",
            data={
                "current_password":
                    self.TEST_PASSWORD,

                "new_password":
                    self.SECOND_PASSWORD,

                "confirm_password":
                    self.SECOND_PASSWORD,
            },
            follow_redirects=False,
        )

        self._assert_redirect_path(
            request_response,
            "/verify-password-change",
        )

        change_code = self._latest_code(
            "password_change"
        )

        verification_response = (
            self.client.post(
                "/verify-password-change",
                data={
                    "verification_code":
                        change_code,
                },
                follow_redirects=False,
            )
        )

        self._assert_redirect_path(
            verification_response,
            "/login",
        )

        user = self._get_user_by_id(
            user_id
        )

        assert user is not None

        self.assertTrue(
            verify_password(
                user["password_hash"],
                self.SECOND_PASSWORD,
            )
        )

        self.assertFalse(
            verify_password(
                user["password_hash"],
                self.TEST_PASSWORD,
            )
        )

        with self.client.session_transaction() as session:
            self.assertNotIn(
                "authenticated_user_id",
                session,
            )

        audit_events = (
            self._audit_event_types(
                user_id
            )
        )

        self.assertIn(
            "PASSWORD_CHANGE_SUCCESS",
            audit_events,
        )

    # =====================================================
    # Dashboard mode-switch endpoint tests
    # =====================================================

    def test_dashboard_security_mode_switches(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user(
                username="mode_user",
                email="mode@example.com",
            )
        )

        self._authenticate_session(
            user_id
        )

        ajax_headers = {
            "X-Requested-With":
                "XMLHttpRequest",

            "Accept":
                "application/json",
        }

        timeout_response = self.client.post(
            "/session-timeout-mode",
            data={
                "timeout_mode":
                    "demo",
            },
            headers=ajax_headers,
        )

        self.assertEqual(
            timeout_response.status_code,
            200,
        )

        timeout_data = (
            timeout_response.get_json()
        )

        self.assertTrue(
            timeout_data["success"]
        )

        self.assertEqual(
            timeout_data[
                "timeout_mode"
            ],
            "demo",
        )

        self.assertEqual(
            timeout_data[
                "timeout_seconds"
            ],
            5,
        )

        # Recreate a fresh standard session because the
        # previous request enabled a five-second timeout.
        self._authenticate_session(
            user_id
        )

        lockout_response = self.client.post(
            "/lockout-mode",
            data={
                "lockout_mode":
                    "demo",
            },
            headers=ajax_headers,
        )

        self.assertEqual(
            lockout_response.status_code,
            200,
        )

        lockout_data = (
            lockout_response.get_json()
        )

        self.assertTrue(
            lockout_data["success"]
        )

        self.assertEqual(
            lockout_data[
                "lockout_mode"
            ],
            "demo",
        )

        user = self._get_user_by_id(
            user_id
        )

        assert user is not None

        self.assertEqual(
            int(
                user["lockout_demo_mode"]
            ),
            1,
        )

    # =====================================================
    # Session-expiry tests
    # =====================================================

    def test_expired_session_returns_to_login(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user(
                username="timeout_user",
                email="timeout@example.com",
            )
        )

        self._authenticate_session(
            user_id=user_id,
            timeout_mode="demo",
            last_activity_at=(
                time.time() - 10
            ),
        )

        response = self.client.get(
            "/dashboard",
            follow_redirects=False,
        )

        self._assert_redirect_path(
            response,
            "/login",
        )

        with self.client.session_transaction() as session:
            self.assertNotIn(
                "authenticated_user_id",
                session,
            )

        audit_events = (
            self._audit_event_types(
                user_id
            )
        )

        self.assertIn(
            "SESSION_EXPIRED",
            audit_events,
        )

    # =====================================================
    # Account-deletion tests
    # =====================================================

    def test_secure_account_deletion(
        self,
    ) -> None:
        user_id = (
            self._create_verified_user(
                username="delete_user",
                email="delete@example.com",
            )
        )

        self._authenticate_session(
            user_id
        )

        request_response = self.client.post(
            "/delete-account",
            data={
                "current_password":
                    self.TEST_PASSWORD,
            },
            follow_redirects=False,
        )

        self._assert_redirect_path(
            request_response,
            "/confirm-delete-account",
        )

        deletion_code = self._latest_code(
            "delete_account"
        )

        confirmation_response = (
            self.client.post(
                "/confirm-delete-account",
                data={
                    "verification_code":
                        deletion_code,

                    "confirmation_text":
                        "DELETE",

                    "deletion_confirmed":
                        "yes",
                },
                follow_redirects=False,
            )
        )

        self._assert_redirect_path(
            confirmation_response,
            "/",
        )

        deleted_user = (
            self._get_user_by_id(
                user_id
            )
        )

        self.assertIsNone(
            deleted_user
        )

        with app_module.app.app_context():
            connection = database.get_db()

            deleted_event = (
                connection.execute(
                    """
                    SELECT event_type
                    FROM audit_logs
                    WHERE username_snapshot = ?
                      AND event_type = ?
                    ORDER BY audit_id DESC
                    LIMIT 1
                    """,
                    (
                        "delete_user",
                        "ACCOUNT_DELETED",
                    ),
                ).fetchone()
            )

        self.assertIsNotNone(
            deleted_event
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )