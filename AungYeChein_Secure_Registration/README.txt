# 🔐 CET324 Secure Registration Application

> A secure Flask web application developed for the **CET324 Advanced CyberSecurity** assignment at the University of Sunderland.

---

## 1. 📌 Project Overview

This project demonstrates secure account registration, authentication, password recovery, session protection, and account management.

### 1.1 Built With

- Python and Flask
- SQLite
- HTML, CSS and JavaScript
- Argon2id password hashing
- Gmail SMTP
- Flask-WTF and Flask-Limiter
- Pillow for CAPTCHA generation

---

## 2. 🛡️ Main Security Features

### 2.1 Registration Security
- Unique username and email validation
- Strong password assessment with feedback
- Argon2id password hashing
- Custom image CAPTCHA
- Email verification using a six-digit OTP

### 2.2 Login Security
- Login using username or email
- Email-based two-step verification
- Five-attempt account lockout
- Standard lockout: **5 minutes**
- Demo lockout: **10 seconds**
- Generic login error messages

### 2.3 Password Security
- Forgotten-password reset by email OTP
- Secure password change with current-password verification
- Three incorrect current-password attempts allowed
- Temporary password-change cooldown
- Standard cooldown: **5 minutes**
- Demo cooldown: **10 seconds**

### 2.4 Session Security
- Standard inactivity timeout: **15 minutes**
- Demo inactivity timeout: **5 seconds**
- Visible countdown timer
- Server-side session enforcement
- Maximum session lifetime: **2 hours**

### 2.5 Additional Security
- CSRF protection
- Rate limiting
- Security notification emails
- Private audit log
- Privacy-safe active-user directory
- Secure account deletion

---

## 3. 📁 Project Structure

```text
CET324_Secure_Registration/
│
├── app.py
├── config.py
├── database.py
├── password_security.py
├── captcha.py
├── otp_security.py
├── email_service.py
├── requirements.txt
├── README.md
├── .env.example
│
├── database/
│   └── users.db
│
├── templates/
│   ├── register.html
│   ├── login.html
│   ├── verify_code.html
│   ├── dashboard.html
│   ├── forgot_password.html
│   ├── reset_password.html
│   ├── change_password.html
│   ├── verify_password_change.html
│   ├── delete_account.html
│   ├── confirm_delete.html
│   └── error.html
│
├── static/
│   ├── css/
│   │   ├── style.css
│   │   └── security_features.css
│   └── js/
│       ├── registration.js
│       ├── session_timeout.js
│       └── login_lockout.js
│
└── tests/
    └── test_app.py
```

---

## 4. ⚙️ Installation (Important)

### 4.1 Create and Activate a Virtual Environment

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 4.2 Install Dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4.3 Create `.env`

Copy `.env.example` and rename the copy to `.env`.

The included `.env.example` contains:

```text
SECRET_KEY=

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=465
MAIL_USE_SSL=true
MAIL_USERNAME=
MAIL_APP_PASSWORD=
MAIL_SENDER_NAME=CET324 Secure Registration

OTP_EXPIRY_SECONDS=300
OTP_MAX_ATTEMPTS=5
OTP_RESEND_WAIT_SECONDS=60
```

> Keep the submitted `.env.example` blank. Do not include the completed `.env` file in the submission.

---

## 5. ⚙️ Email Configuration (Important)

To test the email features, copy `.env.example`, rename the copy to `.env`, and complete these three values:

```text
SECRET_KEY=
MAIL_USERNAME=
MAIL_APP_PASSWORD=
```

### 5.1 Generate the Secret Key (Important)

Run this command in PowerShell:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy the generated value into:

```text
SECRET_KEY=your-generated-secret-key
```

### 5.2 Add the Gmail Address (Important)

Enter the Gmail address that will send verification codes:

```text
MAIL_USERNAME=your-email@gmail.com
```

### 5.3 Create a Gmail App Password (Important)

1. Sign in to the Google Account used for the project.
2. Open **Google Account → Security**.
3. Enable **2-Step Verification**.
4. Open **App passwords**.
5. Create an App Password named `CET324 Flask`.
6. Copy the generated password into:

```text
MAIL_APP_PASSWORD=your-generated-app-password
```

Use the Google App Password, not the normal Gmail password. Keep the completed `.env` private.

All remaining session, lockout, OTP, and password-security settings use the default values defined in `config.py`.

---


## 6. 🧪 Run Automated Tests

```powershell
python -m py_compile tests\test_app.py
python -m unittest discover -s tests -p "test_*.py" -v
```

A successful test run ends with:

```text
OK
```

The tests use a temporary database and mocked email delivery, so they do not modify the real user database or send real emails.

---

## 7. 🔒 Security Design Summary

The application uses defence in depth by combining password controls, CAPTCHA, email verification, multi-factor login, rate limiting, lockout protection, session timeout, audit logging, and security notifications.

Important security checks are enforced on the Flask server. JavaScript is used mainly for visual feedback, animation, and countdown timers.

Passwords, OTPs, session tokens, and email credentials are never stored in the audit log.

---

## 8. 👤 Author

Module: CET324 Advanced CyberSecurity  
Institution: University of Sunderland  
Student Name:  Aung Ye Chein
Student ID: 250689794
