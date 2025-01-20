import os

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://root:123456789@localhost:3306/secure_file_sharing')
    SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Secret Key
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your_secret_key')

    # Mail Configuration (Optional)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'chaitanyagrawal1970@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'your_email_password')  # Secure email password storage

    # Optional: You can add an environment variable for the upload folder or other directories
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
