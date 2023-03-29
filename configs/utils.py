import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'mysql://root:ayambawang@localhost/db_testing'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'your-jwt-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = 60  # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES = 86400  # 24 hours
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_SECURE = False  # Set to True in production when using HTTPS
    JWT_COOKIE_CSRF_PROTECT = False  # Set to True for CSRF protection
