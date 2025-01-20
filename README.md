# Secure File Sharing System

A Flask-based secure file sharing system that enables secure file transfers between Operations Users and Client Users through encrypted URLs.

## Overview

The system provides two types of users with different capabilities:

### Operations User
- Can log in to the system
- Upload files (restricted to .pptx, .docx, and .xlsx formats)
- Secure file management

### Client User
- Can sign up (receives encrypted URL)
- Email verification required
- Can log in to the system
- View list of all uploaded files
- Download files through secure encrypted URLs

## Features

- **Secure Authentication**: JWT-based authentication system
- **Role-Based Access Control**: Different permissions for Operations and Client users
- **File Upload Restrictions**: Strict file type validation (.pptx, .docx, .xlsx)
- **Encrypted Download URLs**: Secure, user-specific download links
- **Email Verification**: Automated email verification system
- **Secure File Storage**: Encrypted file storage system
- **Access Control**: URL access restricted to authorized client users

## Technical Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy
- **Authentication**: JWT Tokens
- **File Storage**: Encrypted local storage
- **Email Service**: Flask-Mail

## API Endpoints

### Operations User
```
POST /api/ops/login
    - Login for operations users

POST /api/ops/upload
    - Upload files (pptx, docx, xlsx only)
```

### Client User
```
POST /api/client/signup
    - Register new client user
    - Returns encrypted URL

POST /api/client/verify-email
    - Email verification endpoint

POST /api/client/login
    - Client user login

GET /api/client/files
    - List all uploaded files

GET /api/client/download/{assignment_id}
    - Get encrypted download URL
```

## Sample Response

```json
{
    "download-link": "..../download-file/moiasnciaduasnduoadosnoadaosid",
    "message": "success"
}
```

## Setup Instructions

1. Clone the repository:
```bash
git clone https://github.com/agrawalchaitany/flask-secure-file-sharing.git
cd flask-secure-file-sharing
```

2. Set up virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # For Unix
venv\Scripts\activate     # For Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables (.env file):
```
SECRET_KEY=your-very-secret-key
SECURITY_PASSWORD_SALT=your_password_salt_here
DATABASE_URL=mysql+pymysql://root:123456789@localhost:3306/secure_file_sharing
JWT_SECRET_KEY=your_secret_key
MAIL_USERNAME=email_id@gmail.com
MAIL_PASSWORD=your_passward
UPLOAD_FOLDER=flask-secure-file-sharing\uploads
```

5. Initialize database:
```bash
flask db upgrade
```

6. Run the application:
```bash
python run.py
```


The test suite covers:
- User authentication
- File upload/download
- Email verification
- URL encryption
- Access control

## Production Deployment

1. Server Requirements:
   - Linux server (Ubuntu recommended)
   - Python 3.8+
   - Nginx
   - Gunicorn
   - SSL certificate

2. Deployment Steps:
   - Set up server environment
   - Configure Nginx and Gunicorn
   - Set up SSL certificate
   - Configure production database
   - Set up environment variables
   - Deploy using Git or Docker

3. Security Considerations:
   - Use production-grade database
   - Enable HTTPS
   - Set up firewall rules
   - Configure proper file permissions
   - Implement rate limiting
   - Set up regular backups

## Directory Structure
```
flask-secure-file-sharing/
├── app/
|   ├── templates/
│       ├── index.py
|       ├── files.py
│       ├── login.py
│       ├── upload.py
│       └── register.py
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── forms.py
│   
├── migrations/
├── uploads/
├── run.py
├── requirements.txt
└── README.md
```

