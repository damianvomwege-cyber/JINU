# Points App (Teacher / Student)

Mini web app without email verification:
- Registration as `lehrer` or `schueler` (role values are stored in German for DB compatibility)
- Login / logout
- Only teachers can award student points

## Start

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Notes

- Email verification is intentionally disabled.
- Passwords are hashed in the database.
- For production: change `SECRET_KEY` and secure access to `app.db`.
