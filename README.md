# Points App (Teacher / Student)

Mini web app without email verification:
- Registration as `lehrer` or `schueler` (role values are stored in German for DB compatibility)
- Login / logout
- Only teachers can award student points
- Adult role (`erwachsene`) with chat access to teachers

## Start

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Vercel deploy

Deployment files are added:
- `vercel.json`
- `api/index.py`

Quick commands:

```bash
./scripts/start-local.ps1
./scripts/deploy-vercel.ps1
```

Notes:
- On Vercel, SQLite works only as ephemeral storage in `/tmp` (data can be reset). For persistent data, use a managed database later.
- Set `SECRET_KEY` and optional `DATABASE_PATH` in environment settings if needed.

## Notes

- Email verification is intentionally disabled.
- Passwords are hashed in the database.
- For production: change `SECRET_KEY` and secure access to `app.db`.
