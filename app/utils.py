import bcrypt
import secrets
import re
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from datetime import datetime

from flask import current_app
from app.config import Config
from app.models import Challenge, User, LoginLog
from app import db

def generate_salt():
    return bcrypt.gensalt()

def hash_password(password, salt):
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def generate_challenge():
    return secrets.token_hex(64)  # 生成64字节的随机挑战值

def validate_password(password):
    """验证密码是否符合要求"""
    pattern = re.compile(Config.PASSWORD_PATTERN)
    return bool(pattern.match(password))

def validate_email(email):
    """验证邮箱格式"""
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return bool(pattern.match(email))

def create_challenge(email):
    """创建新的挑战值"""
    # 检查是否超过请求频率限制
    last_challenge = Challenge.query.filter_by(
        email=email,
        used=False
    ).order_by(Challenge.created_at.desc()).first()
    
    if last_challenge and (datetime() - last_challenge.created_at).total_seconds() < Config.CHALLENGE_REQUEST_INTERVAL:
        return None
        
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

def generate_aes_key():
    """生成AES密钥"""
    return get_random_bytes(32)  # 256位密钥

def encrypt_aes(key, data):
    """使用AES加密数据"""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return {'iv': iv, 'ciphertext': ct}

def decrypt_aes(key, ciphertext_base64):
    """使用AES解密数据"""
    try:
        aes_key = bytes.fromhex(key.decode('utf-8')) # key为字节串形式，需要先转为普通字符串，然后解析为字节数据
        ciphertext = base64.b64decode(ciphertext_base64) # 密文为进行base64编码的字节数据，应当解码为字节数据
        print("ciphertext:", ciphertext)
        cipher = AES.new(aes_key, AES.MODE_ECB) 
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size) # 解密过程中，密文应当是字节数据
        return pt.decode('utf-8')
    except (ValueError, KeyError) as e:
        current_app.logger.error(f'AES解密错误: {str(e)}')
        raise

def encrypt_rsa(public_key, data):
    """使用RSA加密数据（用于加密AES密钥）"""
    key = RSA.import_key(public_key)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(data).decode('utf-8')

def decrypt_rsa(private_key, encrypted_data):
    """使用RSA解密数据（用于解密AES密钥）"""
    try:
        key = RSA.import_key(private_key)
        cipher = PKCS1_v1_5.new(key)
        print("encrypted_date:", encrypted_data)
        data = cipher.decrypt(b64decode(encrypted_data), None)
        print("解密数据：", data)
        return data
    except Exception as e:
        current_app.logger.error(f'RSA解密错误: {str(e)}')
        raise

def generate_response(password_hash, challenge_value):
    """生成响应值"""
    # 将密码哈希和挑战值拼接后再次哈希
    combined = str(password_hash) + str(challenge_value)
    return hashlib.sha256(combined.encode()).hexdigest()

def verify_challenge_response(email, challenge_value, response_value):
    """验证响应值"""
    try:
        # 获取未使用且未过期的挑战值
        challenge = Challenge.query.filter_by(
            email=email,
            challenge_value=challenge_value,
            used=False
        ).first()
        
        if not challenge:
            return False
            
        # 检查挑战值是否过期
        if (datetime() - challenge.created_at) > Config.CHALLENGE_LIFETIME:
            challenge.used = True
            db.session.commit()
            return False
        
        # 获取用户密码哈希
        user = User.query.filter_by(email=email).first()
        if not user:
            return False
        
        # 生成预期的响应值
        expected_response = generate_response(user.password_hash, challenge_value)
        
        # 标记挑战值为已使用
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
        
    # 检查是否被锁定
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
        
    return False

def update_login_attempts(email, success):
    """更新登录尝试次数"""
    user = User.query.filter_by(email=email).first()
    if not user:
        return
        
    if success:
        # 登录成功，重置失败次数
        user.failed_attempts = 0
        user.locked_until = None
    else:
        # 登录失败，增加失败次数
        user.failed_attempts += 1
        user.last_failed_attempt = datetime.utcnow()
        
        # 检查是否需要锁定账号
        if user.failed_attempts >= Config.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.utcnow() + Config.ACCOUNT_LOCKOUT_DURATION
            
    db.session.commit()