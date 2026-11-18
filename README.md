# KaushalSetu Pro — Hardened Flask MVP

## Run in VS Code (Windows)
1. Extract the ZIP and open this folder in VS Code.
2. Open Terminal → New Terminal.
3. Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```
4. Install packages:
   ```powershell
   pip install -r requirements.txt
   ```
5. Start:
   ```powershell
   python app.py
   ```
6. Visit `http://127.0.0.1:5000`.
7. Check backend/database health at `http://127.0.0.1:5000/health`.

## Implemented backend
- Role-specific registration and login for SHGs, youth and employers.
- Werkzeug password hashing (passwords are not stored as plain text).
- Signed Flask sessions with HttpOnly and SameSite cookie settings.
- CSRF tokens on all POST forms.
- Role guards on protected actions.
- Parameterized SQL queries and SQLite foreign-key enforcement.
- Server-side input length and basic email validation.
- SHG order tracking and member earning records.
- Job posting, youth applications and employer application status updates.
- Transparent skill-overlap and text-location recommendation score.
- Health endpoint and baseline security response headers.

## Demo flow
1. Register an SHG account.
2. Add an order and member earning.
3. Post a temporary worker opportunity from the SHG dashboard.
4. Register a youth account with matching skills and location.
5. Review recommendations and apply.
6. Return to the SHG account and update the application.

## Important honesty / production checklist
This is a stronger hackathon prototype, not a fully production-audited service.
- The matching score is rules-based; it is not a trained machine-learning model.
- Location matching is text-based, not GPS distance.
- Earnings are bookkeeping records only; no bank/UPI transfer occurs.
- Add CSRF protection is implemented for HTML POST forms, but before public deployment also add automated tests, rate limiting, email verification, password reset, audit logging, backups, database migrations, HTTPS, production secret management, privacy consent, admin moderation and monitoring.
- For multiple concurrent production users, migrate SQLite to PostgreSQL/MySQL and use a production WSGI server.
- Set a strong `SECRET_KEY` environment variable before deployment. Set `COOKIE_SECURE=1` only when HTTPS is configured.
- Do not use Flask's development server for public deployment.
