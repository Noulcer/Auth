from flask import Blueprint, json, request, jsonify, current_app, render_template
from app import db
from app.models import User
from app.utils import (validate_email, validate_password, generate_salt, 
                      hash_password, create_challenge, verify_challenge_response,
                      log_login_attempt, check_account_lockout, update_login_attempts,
                    decrypt_rsa, decrypt_aes)
from functools import wraps

auth_bp = Blueprint('auth', __name__)

def require_encryption(f):
    """确保请求数据使用混合加密"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            data = request.get_json()
            if not all(k in data for k in ('key', 'data')):
                return jsonify({'error': '需要加密数据'}), 400
                
            try:
                # 使用RSA解密AES密钥
                aes_key = decrypt_rsa(
                    current_app.config['PRIVATE_KEY'],
                    data['key']
                )
                
                # 使用AES解密数据
                decrypted_data = decrypt_aes(
                    aes_key,
                    data['data']
                )
                
                return f(decrypted_data, *args, **kwargs)
            except Exception as e:
                current_app.logger.error(f'解密失败: {str(e)}')
                return jsonify({'error': '数据解密失败'}), 400
        except Exception as e:
            current_app.logger.error(f'请求处理失败: {str(e)}')
            return jsonify({'error': '无效的请求数据'}), 400
    return decorated_function

@auth_bp.route('/register', methods=['POST'])
@require_encryption
def register(decrypted_data):
    """注册新用户"""
    try:
        data = json.loads(decrypted_data)
        email = data.get('email')
        password = data.get('password')
        
        # 验证邮箱格式
        if not validate_email(email):
            return jsonify({
                'status': 'error',
                'message': '邮箱格式不正确',
                'code': 'INVALID_EMAIL'
            }), 400
            
        # 检查邮箱是否已存在
        if User.query.filter_by(email=email).first():
            return jsonify({
                'status': 'error',
                'message': '该邮箱已被注册',
                'code': 'EMAIL_EXISTS'
            }), 400
            
        # 验证密码格式
        if not validate_password(password):
            return jsonify({
                'status': 'error',
                'message': '密码必须包含大小写字母、数字和特殊字符，且长度至少为8位',
                'code': 'INVALID_PASSWORD'
            }), 400
            
        # 创建新用户
        try:
            salt = generate_salt()
            password_hash = hash_password(password, salt).decode('utf-8')
            
            new_user = User(
                email=email,
                password_hash=password_hash,
                salt=salt.decode('utf-8')
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            current_app.logger.info(f'新用户注册成功: {email}')
            return jsonify({
                'status': 'success',
                'message': '注册成功'
            }), 201
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'创建用户失败: {str(e)}')
            return jsonify({
                'status': 'error',
                'message': '创建用户失败，请稍后重试',
                'code': 'CREATE_USER_FAILED'
            }), 500
            
    except json.JSONDecodeError as e:
        current_app.logger.error(f'JSON解析错误: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': '无效的请求数据格式',
            'code': 'INVALID_JSON'
        }), 400
    except Exception as e:
        current_app.logger.error(f'注册过程发生错误: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': '注册失败，请稍后重试',
            'code': 'REGISTRATION_FAILED'
        }), 500

@auth_bp.route('/login/step1', methods=['POST'])
@require_encryption
def login_step1(decrypted_data):
    """登录第一步：发送邮箱并获取挑战值和盐值"""
    try:
        data = json.loads(decrypted_data)
        email = data.get('email')
        
        if not email or not validate_email(email):
            return jsonify({
                'status': 'error',
                'message': '无效的邮箱',
                'code': 'INVALID_EMAIL'
            }), 400
            
        # 检查账号是否被锁定
        if check_account_lockout(email):
            return jsonify({
                'status': 'error',
                'message': '账号已被锁定，请稍后再试',
                'code': 'ACCOUNT_LOCKED'
            }), 403
            
        # 检查用户是否存在
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({
                'status': 'error',
                'message': '用户不存在',
                'code': 'USER_NOT_FOUND'
            }), 404
            
        # 生成挑战值
        challenge = create_challenge(email)
        if not challenge:
            return jsonify({
                'status': 'error',
                'message': '请求过于频繁，请稍后再试',
                'code': 'TOO_MANY_REQUESTS'
            }), 429
            
        return jsonify({
            'status': 'success',
            'challenge': challenge,
            'salt': user.salt  # 返回用户的盐值
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'登录步骤1失败: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': '服务器错误，请稍后重试',
            'code': 'SERVER_ERROR'
        }), 500

@auth_bp.route('/login/step2', methods=['POST'])
@require_encryption
def login_step2(decrypted_data):
    """登录第二步：验证响应值"""
    try:
        data = json.loads(decrypted_data)
        email = data.get('email')
        challenge_value = data.get('challenge')
        response_value = data.get('response')
        
        if not all([email, challenge_value, response_value]):
            return jsonify({
                'status': 'error',
                'message': '缺少必要参数',
                'code': 'MISSING_PARAMETERS'
            }), 400
            
        # 检查账号是否被锁定
        if check_account_lockout(email):
            return jsonify({
                'status': 'error',
                'message': '账号已被锁定，请稍后再试',
                'code': 'ACCOUNT_LOCKED'
            }), 403
            
        # 验证响应值
        if verify_challenge_response(email, challenge_value, response_value):
            # 登录成功
            update_login_attempts(email, success=True)
            log_login_attempt(email, request.remote_addr, success=True)
            return jsonify({
                'status': 'success',
                'message': '登录成功'
            }), 200
        else:
            # 登录失败
            update_login_attempts(email, success=False)
            log_login_attempt(email, request.remote_addr, success=False)
            return jsonify({
                'status': 'error',
                'message': '用户名或密码错误',
                'code': 'INVALID_CREDENTIALS'
            }), 401
            
    except Exception as e:
        current_app.logger.error(f'登录步骤2失败: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': '服务器错误，请稍后重试',
            'code': 'SERVER_ERROR'
        }), 500

@auth_bp.route('/public-key', methods=['GET'])
def get_public_key():
    """获取RSA公钥"""
    return jsonify({'public_key': current_app.config['PUBLIC_KEY'].decode()})

@auth_bp.route('/')
def index():
    return render_template('index.html') 