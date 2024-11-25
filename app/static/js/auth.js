let publicKey = null;
let currentChallenge = null;
let currentEmail = null;

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

// RSA加密
function encryptData(data) {
    try {
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKey);
        const jsonStr = JSON.stringify(data);
        const encrypted = encrypt.encrypt(jsonStr);
        if (!encrypted) {
            throw new Error('加密失败');
        }
        return encrypted;
    } catch (error) {
        console.error('加密错误:', error);
        throw error;
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

// 返回登录第一步
function backToStep1() {
    document.getElementById('login-step1').style.display = 'block';
    document.getElementById('login-step2').style.display = 'none';
    currentChallenge = null;
    clearErrors();
}

// 登录第一步：发送邮箱获取挑战值
async function startLoginStep1() {
    const email = document.getElementById('login-email').value;
    clearErrors();
    
    if (!email) {
        showError('login-email-error', '请输入邮箱');
        return;
    }
    
    if (!publicKey) {
        await fetchPublicKey();
    }
    
    try {
        const encryptedEmail = encryptData({ email: email });
        const response = await fetch('/login/step1', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                encrypted_data: encryptedEmail
            })
        });
        
        const data = await response.json();
        if (response.ok) {
            currentChallenge = data.challenge;
            currentEmail = email;
            document.getElementById('login-email-display').textContent = email;
            document.getElementById('login-step1').style.display = 'none';
            document.getElementById('login-step2').style.display = 'block';
        } else {
            showError('login-email-error', data.error || '邮箱验证失败');
        }
    } catch (error) {
        console.error('登录步骤1失败:', error);
        showError('login-email-error', '服务器错误');
    }
}

// 完成登录
async function completeLogin() {
    const password = document.getElementById('login-password').value;
    clearErrors();
    
    if (!password) {
        showError('login-password-error', '请输入密码');
        return;
    }
    
    try {
        const passwordHash = CryptoJS.SHA256(password).toString();
        const response = CryptoJS.SHA256(passwordHash + currentChallenge).toString();
        
        const encryptedData = encryptData({
            email: currentEmail,
            challenge: currentChallenge,
            response: response
        });
        
        const loginResponse = await fetch('/login/step2', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                encrypted_data: encryptedData
            })
        });
        
        const data = await loginResponse.json();
        if (loginResponse.ok) {
            alert('登录成功！');
            // 清空表单
            document.getElementById('login-password').value = '';
            // 返回第一步
            backToStep1();
        } else {
            showError('login-password-error', data.error || '密码验证失败');
        }
    } catch (error) {
        console.error('登录失败:', error);
        showError('login-password-error', '服务器错误');
    }
}

// 注册
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
    console.log('当前公钥:', publicKey);

    try {
        const encryptedData = encryptData({
            email: email,
            password: password
        });
        
        const response = await fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                encrypted_data: encryptedData
            })
        });
        console.log('收到响应:', response);

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
            // 根据后端返回的错误类型显示对应的错误信息
            if (data.error.includes('邮箱')) {
                showError('register-email-error', data.error);
            } else if (data.error.includes('密码')) {
                showError('register-password-error', data.error);
            } else {
                showError('register-email-error', data.error);
            }
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