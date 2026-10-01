# CloudGuard – Software-Based Cloud Security Demonstrator

A ready-to-run Flask project for a school/college science exhibition.

## Features
- Username/password authentication
- Admin and student roles
- Failed-login detection
- Temporary account blocking after 5 failed attempts
- Fernet symmetric encryption for uploaded files
- Encrypted local "cloud" storage
- Role-based file access
- Security audit logs
- Controlled brute-force attack simulator
- Live security dashboard
- SQLite database
- No internet/cloud account required

## Requirements
- Python 3.10+ recommended
- pip

## Windows
Open Command Prompt in this folder:

```text
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:
http://127.0.0.1:5000

## Linux/macOS
```text
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## Demo accounts
Admin:
- Username: admin
- Password: admin123

Student:
- Username: student
- Password: student123

## Recommended exhibition sequence
1. Log in as student.
2. Upload a small text/PDF/image file.
3. Show that the file is stored in `storage/` as an `.enc` file.
4. Download it and explain that the application decrypts it only after authorization.
5. Log out and log in as admin.
6. Open Audit Logs.
7. Open Attack Simulator.
8. Simulate 5 failed attempts against `student`.
9. Return to Dashboard and show the failed/blocked counters.
10. Explain that this is a local simulation of cloud-security controls, not a production cloud service.

## Architecture

Browser
  -> Flask web application
  -> Authentication / RBAC
  -> Encryption layer
  -> SQLite metadata + audit logs
  -> Encrypted file storage

## Security note
This project is designed for demonstration and learning. It is not a production-ready cloud security system. Production systems should use HTTPS, strong password hashing such as Argon2/bcrypt, secure secret management, CSRF protection, cloud IAM, key management services, secure object storage, rate limiting, monitoring and hardened deployment.
