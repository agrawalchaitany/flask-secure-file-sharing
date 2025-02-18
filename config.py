import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://root:123456789@localhost:3306/secure_file_sharing')
    SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT', 'your-salt-here')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Secret Key
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your_secret_key')

    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWARD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')
    
    # Remove quotes if they exist in the environment variables
    if MAIL_USERNAME and MAIL_USERNAME.startswith('"') and MAIL_USERNAME.endswith('"'):
        MAIL_USERNAME = MAIL_USERNAME[1:-1]
    if MAIL_PASSWORD and MAIL_PASSWORD.startswith('"') and MAIL_PASSWORD.endswith('"'):
        MAIL_PASSWORD = MAIL_PASSWORD[1:-1]
    if MAIL_DEFAULT_SENDER and MAIL_DEFAULT_SENDER.startswith('"') and MAIL_DEFAULT_SENDER.endswith('"'):
        MAIL_DEFAULT_SENDER = MAIL_DEFAULT_SENDER[1:-1]

    # Upload folder configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
