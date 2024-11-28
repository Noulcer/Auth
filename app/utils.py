import bcrypt
import secrets
import re
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import unpad
from base64 import b64decode
from datetime import datetime

from flask import current_app
from app.config import Config
from app.models import Challenge, User, LoginLog
from app import db

def generate_salt():
    """生成密码盐值"""
    return bcrypt.gensalt()

def hash_password(password, salt):
    """使用盐值对密码进行哈希"""
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def validate_password(password):
    """验证密码是否符合要求"""
    pattern = re.compile(Config.PASSWORD_PATTERN)
    return bool(pattern.match(password))

def validate_email(email):
    """验证邮箱格式"""
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return bool(pattern.match(email))

def generate_challenge():
    """生成随机挑战值"""
    return secrets.token_hex(64)

def create_challenge(email):
    """创建新的挑战值"""
    last_challenge = Challenge.query.filter_by(
        email=email,
        used=False
    ).order_by(Challenge.created_at.desc()).first()
    
    if last_challenge and (datetime.utcnow() - last_challenge.created_at).total_seconds() < Config.CHALLENGE_REQUEST_INTERVAL:
        return last_challenge.challenge_value
        
    challenge = Challenge(
        challenge_value=generate_challenge(),
        email=email
    )
    db.session.add(challenge)
    db.session.commit()
    return challenge.challenge_value

def generate_rsa_keys():
    """生成RSA密钥对"""
    key = RSA.generate(Config.RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def decrypt_aes(key, ciphertext_base64):
    """使用AES解密数据"""
    try:
        aes_key = bytes.fromhex(key.decode('utf-8'))
        ciphertext = base64.b64decode(ciphertext_base64)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print("AES解密数据：", pt.decode('utf-8'))
        return pt.decode('utf-8')
    except (ValueError, KeyError) as e:
        current_app.logger.error(f'AES解密错误: {str(e)}')
        raise

def decrypt_rsa(private_key, encrypted_data):
    """使用RSA解密数据"""
    try:
        key = RSA.import_key(private_key)
        cipher = PKCS1_v1_5.new(key)
        data = cipher.decrypt(b64decode(encrypted_data), None)
        print("RSA解密数据：", data)
        return data
    except Exception as e:
        current_app.logger.error(f'RSA解密错误: {str(e)}')
        raise

def generate_response(password_hash, challenge_value):
    """生成响应值"""
    combined = str(password_hash) + str(challenge_value)
    return hashlib.sha256(combined.encode()).hexdigest()

def verify_challenge_response(email, challenge_value, response_value):
    """验证响应值"""
    try:
        challenge = Challenge.query.filter_by(
            email=email,
            challenge_value=challenge_value,
            used=False
        ).first()
        
        if not challenge:
            return False
            
        if (datetime.utcnow() - challenge.created_at) > Config.CHALLENGE_LIFETIME:
            challenge.used = True
            db.session.commit()
            return False
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return False
        
        expected_response = generate_response(user.password_hash, challenge_value)
        
        challenge.used = True
        db.session.commit()
        
        return response_value == expected_response
    except Exception as e:
        current_app.logger.error(f'验证响应值失败: {str(e)}')
        return False

def log_login_attempt(email, ip_address, success):
    """记录登录尝试"""
    log = LoginLog(
        email=email,
        ip_address=ip_address,
        success=success
    )
    db.session.add(log)
    db.session.commit()

def check_account_lockout(email):
    """检查账号是否被锁定"""
    user = User.query.filter_by(email=email).first()
    if not user:
        return False
        
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
        
    return False

def update_login_attempts(email, success):
    """更新登录尝试次数"""
    user = User.query.filter_by(email=email).first()
    if not user:
        return
        
    if success:
        user.failed_attempts = 0
        user.locked_until = None
    else:
        user.failed_attempts += 1
        user.last_failed_attempt = datetime.utcnow()
        
        if user.failed_attempts >= Config.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.utcnow() + Config.ACCOUNT_LOCKOUT_DURATION
            
    db.session.commit()