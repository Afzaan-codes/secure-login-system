# Secure Login System

A Flask web app demonstrating secure authentication.

## Features
- User registration and login
- Argon2 password hashing
- Input validation
- Parameterized SQLite queries to reduce SQL injection risk
- Session management and logout
- Optional TOTP-based 2FA

## Run
1. `python -m venv venv`
2. Windows: `venv\Scripts\activate`
3. `pip install -r requirements.txt`
4. `python app.py`
5. Open `http://127.0.0.1:5000`

For 2FA, log in and open `/setup-2fa`. Add the displayed secret to a TOTP authenticator app.
