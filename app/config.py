import os
from datetime import timedelta

class Config:
    # Flask配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    
    # 数据库配置 - 使用SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 安全配置
    CHALLENGE_LIFETIME = timedelta(minutes=5)  # 挑战值有效期
    CHALLENGE_REQUEST_INTERVAL = 1  # 挑战请求间隔（秒）
    MAX_LOGIN_ATTEMPTS = 5  # 最大登录尝试次数
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=30)  # 账号锁定时间
    
    # RSA密钥配置
    RSA_KEY_SIZE = 2048
    
    # 密码策略
    PASSWORD_PATTERN = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$' 