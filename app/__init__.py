from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import logging
from logging.handlers import RotatingFileHandler
import os
from app.config import Config

# 初始化数据库
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # 初始化扩展
    db.init_app(app)
    
    # 配置日志
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/auth_system.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Authentication system startup')
    
    # 生成RSA密钥对
    from app.utils import generate_rsa_keys
    private_key, public_key = generate_rsa_keys()
    app.config['PRIVATE_KEY'] = private_key
    app.config['PUBLIC_KEY'] = public_key
    
    # 注册蓝图
    from app.routes import auth_bp
    app.register_blueprint(auth_bp)
    
    return app 