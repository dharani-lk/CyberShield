"""
config.py
=========
Application configuration settings.
Separating config from code follows the 12-factor app methodology.
"""

import os
from pathlib import Path

# Base directory of the application
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base configuration class."""
    
    # Secret key for session management and CSRF protection
    # In production, use a strong random key from environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybershield-dev-key-change-in-production')
    
    # File upload settings
    UPLOAD_FOLDER = BASE_DIR / 'uploads'
    REPORTS_FOLDER = BASE_DIR / 'reports'
    HASHES_FOLDER = BASE_DIR / 'hashes'
    
    # Maximum file size: 16 MB
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # Allowed file extensions for upload
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
        'xls', 'xlsx', 'zip', 'py', 'js', 'html', 'css', 'json', 'xml'
    }
    
    # Application metadata
    APP_NAME = 'CyberShield Security Suite'
    APP_VERSION = '1.0.0'
    
    @classmethod
    def init_directories(cls):
        """Create necessary directories if they don't exist."""
        for folder in [cls.UPLOAD_FOLDER, cls.REPORTS_FOLDER, cls.HASHES_FOLDER]:
            folder.mkdir(parents=True, exist_ok=True)
