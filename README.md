# SecureCampus Student Portal
Educational Flask + SQLite project with admin/student roles, student profile management, marks management, password hashing, audit logs and database backup.

## Run (Windows PowerShell)
```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py app.py
```
Open http://127.0.0.1:5000

Initial admin: `admin` / `Admin@12345`

Admin creates student accounts from Student Directory > Add Student. Students log in using credentials created by admin. Students can view marks and edit limited profile fields (name, email, phone). Only admin can edit student identity/academic details, change account status, and add/update/delete marks.

The database and Fernet key are created on first run. Back up `secret.key` securely; losing it makes encrypted values unreadable. This is a classroom prototype, not production-ready software. Use fake demo data only. For deployment, add HTTPS, CSRF protection, rate limiting, stronger secret management, password reset workflow, and tested backup/restore procedures.
