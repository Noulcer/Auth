let publicKey = null;
let currentChallenge = null;
let currentEmail = null;
let aesKey = null;
let currentSalt = null;

// 生成随机AES密钥
function generateAESKey() {
    return CryptoJS.lib.WordArray.random(16);
}

// AES加密
function encryptAES(data, key) {
    try {
        // 使用AES-ECB模式加密
        const encrypted = CryptoJS.AES.encrypt(
            data,
            key,
            {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.Pkcs7
            }
        );
        
        return encrypted.ciphertext.toString(CryptoJS.enc.Base64); // 密文本身为字节数据，应当编码返回
    } catch (error) {
        console.error('AES加密失败:', error);
        throw error;
    }
}

// RSA加密AES密钥
function encryptKey(key) {
    const encrypt = new JSEncrypt();
    encrypt.setPublicKey(publicKey);
    return encrypt.encrypt(key);
}

// 加密数据
async function encryptData(data) {
    try {
        // 生成AES密钥和IV
        if (!aesKey) {
            aesKey = generateAESKey();
        }
        // 使用AES加密数据
        const encryptedData = encryptAES(JSON.stringify(data), aesKey);
        
        // 使用RSA加密AES密钥
        const encryptedKey = encryptKey(aesKey.toString());
        
        return {
            key: encryptedKey,
            data: encryptedData
        };
    } catch (error) {
        console.error('加密错误:', error);
        throw error;
    }
}

// 发送请求的函数
async function sendEncryptedRequest(url, data) {
    if (!publicKey) {
        await fetchPublicKey();
    }
    const encrypted = await encryptData(data);
    return fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(encrypted)
    });
}

// 获取公钥
async function fetchPublicKey() {
    try {
        const response = await fetch('/public-key');
        const data = await response.json();
        publicKey = data.public_key;
    } catch (error) {
        console.error('获取公钥失败:', error);
        showError('login-email-error', '服务器连接失败');
    }
}

// 显示错误信息
function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    errorElement.textContent = message;
    errorElement.classList.add('show');
    setTimeout(() => {
        errorElement.classList.remove('show');
    }, 3000);
}

// 清除所有错误信息
function clearErrors() {
    const errors = document.getElementsByClassName('error-message');
    for (let error of errors) {
        error.textContent = '';
        error.classList.remove('show');
    }
}

// 显示切换标签
function showTab(tabName) {
    clearErrors();
    
    // 获取所有表单容器
    const loginStep1 = document.getElementById('login-step1');
    const loginStep2 = document.getElementById('login-step2');
    const registerForm = document.getElementById('register-form');
    
    // 移除所有active类
    [loginStep1, loginStep2, registerForm].forEach(container => {
        if (container) {
            container.style.display = 'none';
            container.classList.remove('active');
        }
    });
    
    // 更新标签样式
    const tabs = document.getElementsByClassName('tab-btn');
    for (let tab of tabs) {
        tab.classList.remove('active');
    }
    
    // 根据tabName激活对应的标签和表单
    if (tabName === 'login') {
        document.querySelector('.tab-btn:first-child').classList.add('active');
        loginStep1.style.display = 'block';
        setTimeout(() => {
            loginStep1.classList.add('active');
        }, 50);
    } else {
        document.querySelector('.tab-btn:last-child').classList.add('active');
        registerForm.style.display = 'block';
        setTimeout(() => {
            registerForm.classList.add('active');
        }, 50);
    }
}

// 返回登录第一步的函数，清除盐值
function backToStep1(event) {
    if (event) {
        event.preventDefault();
    }
    
    const step1Container = document.getElementById('login-step1');
    const step2Container = document.getElementById('login-step2');
    
    if (!step1Container || !step2Container) {
        console.error('找不到必要的DOM元素');
        return;
    }
    
    step2Container.style.display = 'none';
    step2Container.classList.remove('active');
    
    step1Container.style.display = 'block';
    setTimeout(() => {
        step1Container.classList.add('active');
    }, 50);
    
    document.getElementById('login-password').value = '';
    clearErrors();
    
    // 重置所有状态
    currentChallenge = null;
    currentEmail = null;
    currentSalt = null;
    
    document.getElementById('login-email').focus();
}

// 登录第一步
async function startLoginStep1() {
    const email = document.getElementById('login-email').value;
    clearErrors();
    
    if (!email) {
        showError('login-email-error', '请输入邮箱');
        return;
    }
    
    try {
        const response = await sendEncryptedRequest('/login/step1', {
            email: email
        });
        
        const data = await response.json();
        if (response.ok) {
            currentChallenge = data.challenge;
            currentEmail = email;
            currentSalt = data.salt;  // 保存盐值
            
            // 获取表单容器
            const step1Container = document.getElementById('login-step1');
            const step2Container = document.getElementById('login-step2');
            const emailDisplay = document.getElementById('login-email-display');
            
            if (!step1Container || !step2Container || !emailDisplay) {
                console.error('找不到必要的DOM元素');
                showError('login-email-error', '页面加载错误');
                return;
            }
            
            // 显示邮箱
            emailDisplay.textContent = email;
            
            // 切换表单
            step1Container.style.display = 'none';
            step1Container.classList.remove('active');
            
            step2Container.style.display = 'block';
            setTimeout(() => {
                step2Container.classList.add('active');
            }, 50);
            
            // 聚焦密码输入框
            document.getElementById('login-password').focus();
            
        } else {
            showError('login-email-error', data.message || '邮箱验证失败');
        }
    } catch (error) {
        console.error('登录步骤1失败:', error);
        showError('login-email-error', '服务器错误，请稍后重试');
    }
}

// 登录第二步
async function completeLogin() {
    const password = document.getElementById('login-password').value;
    clearErrors();
    
    if (!password) {
        showError('login-password-error', '请输入密码');
        return;
    }
    
    try {
        // 使用bcrypt.js的hashSync方法进行同步哈希
        const passwordHash = dcodeIO.bcrypt.hashSync(password, currentSalt);
        // 将密码哈希和挑战值拼接后再次哈希
        const response = CryptoJS.SHA256(passwordHash + currentChallenge).toString();
        
        const loginResponse = await sendEncryptedRequest('/login/step2', {
            email: currentEmail,
            challenge: currentChallenge,
            response: response
        });
        
        const data = await loginResponse.json();
        if (loginResponse.ok) {
            alert(data.message || '登录成功！');
            document.getElementById('login-password').value = '';
            backToStep1();
        } else {
            showError('login-password-error', data.message || '密码验证失败');
        }
    } catch (error) {
        console.error('登录失败:', error);
        showError('login-password-error', '服务器错误，请稍后重试');
    }
}

// handleError函数
function handleError(error) {
    // 根据错误代码显示对应的错误信息
    switch(error.code) {
        case 'INVALID_EMAIL':
            showError('register-email-error', error.message);
            break;
        case 'EMAIL_EXISTS':
            showError('register-email-error', error.message);
            break;
        case 'INVALID_PASSWORD':
            showError('register-password-error', error.message);
            break;
        case 'REGISTRATION_FAILED':
            showError('register-email-error', error.message);
            break;
        default:
            showError('register-email-error', error.message || '发生未知错误');
    }
}

// register函数
async function register() {
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;
    
    clearErrors();
    
    // 前端验证
    if (!email) {
        showError('register-email-error', '请输入邮箱');
        return;
    }
    
    // 验证邮箱格式
    const emailPattern = /^[\w\.-]+@[\w\.-]+\.\w+$/;
    if (!emailPattern.test(email)) {
        showError('register-email-error', '邮箱格式不正确');
        return;
    }
    
    if (!password) {
        showError('register-password-error', '请输入密码');
        return;
    }
    
    // 验证密码格式
    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[.@$!%*?&])[A-Za-z\d.@$!%*?&]{8,16}$/;
    if (!passwordPattern.test(password)) {
        showError('register-password-error', '密码不符合要求');
        return;
    }
    
    if (!confirmPassword) {
        showError('register-confirm-password-error', '请确认密码');
        return;
    }
    
    if (password !== confirmPassword) {
        showError('register-confirm-password-error', '两次输入的密码不一致');
        return;
    }
    
    if (!publicKey) {
        await fetchPublicKey();
    }

    try {
        const response = await sendEncryptedRequest('/register', {
            email: email,
            password: password
        });
        
        const data = await response.json();
        if (response.ok) {
            alert('注册成功！');
            // 清空表单
            document.getElementById('register-email').value = '';
            document.getElementById('register-password').value = '';
            document.getElementById('register-confirm-password').value = '';
            // 切换到登录页面
            showTab('login');
        } else {
            handleError(data);  // 传入完整的错误对象
        }
    } catch (error) {
        console.error('注册失败:', error);
        showError('register-email-error', '服务器错误，请稍后重试');
    }
}

// 页面加载时的初始化
document.addEventListener('DOMContentLoaded', function() {
    fetchPublicKey();
    
    // 根据当前URL判断显示哪个标签
    const hash = window.location.hash.slice(1);
    showTab(hash === 'register' ? 'register' : 'login');
    
    // 监听标签点击事件
    const tabs = document.getElementsByClassName('tab-btn');
    for (let tab of tabs) {
        tab.addEventListener('click', function() {
            const isLoginTab = this.querySelector('i').classList.contains('fa-sign-in-alt');
            const tabName = isLoginTab ? 'login' : 'register';
            window.location.hash = tabName;
            showTab(tabName);
        });
    }
}); 