// Firebase imports
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.9.0/firebase-app.js";
import { getDatabase, ref, push, set, onValue, update, get } from "https://www.gstatic.com/firebasejs/12.9.0/firebase-database.js";

// Firebase Configuration
const firebaseConfig = {
    apiKey: "AIzaSyBelaY5N-UBHZ09vOAKYkuNUPOcmFvb2uk",
    authDomain: "offensive-ac4e4.firebaseapp.com",
    databaseURL: "https://offensive-ac4e4-default-rtdb.firebaseio.com",
    projectId: "offensive-ac4e4",
    storageBucket: "offensive-ac4e4.firebasestorage.app",
    messagingSenderId: "908110623148",
    appId: "1:908110623148:web:77c6100a3acaf4879a8a09"
};

// Админский ключ - ВАЖНО: Замени на свой уникальный ключ!
const ADMIN_SECRET_KEY = "ADMIN-2026-SECURE-KEY-CHANGE-ME";

// =============== LANGUAGE SYSTEM ===============

let currentLanguage = localStorage.getItem('forum_language') || 'en';

const translations = {
    en: {
        // Toasts
        'login_success': 'Login successful!',
        'login_failed': 'Login failed',
        'invalid_username': 'Invalid username format',
        'invalid_key': 'Invalid key format',
        'key_not_found': 'Key not found',
        'key_inactive': 'Key already used',
        'access_granted': 'Access granted!',
        'rate_limit': 'Too many attempts. Try again later',
        'thread_created': 'Thread created successfully!',
        'invalid_title': 'Title must be 5-200 characters',
        'invalid_body': 'Body must be 10-5000 characters',
        'xss_detected': 'Invalid input detected',
        'reply_added': 'Reply added!',
        'invalid_reply': 'Reply must be 5-2000 characters',
        'no_access': 'No access to private thread',
        'admin_only': 'Admin only function',
        'keys_generated': 'keys generated',
        'key_gen_error': 'Key generation error',
        'no_public_threads': 'No public threads',
        'no_private_threads': 'No private threads',
        'no_replies': 'No replies yet',
        'no_keys': 'No keys',
        'author': 'Author',
        'replies': 'Replies',
        'views': 'Views',
        'just_now': 'just now',
        'min_ago': 'min ago',
        'hour_ago': 'h ago',
        'active': 'Active',
        'used_by': 'Used by',
        'unknown': 'Unknown',
        'loading': 'Loading...',
        'admin_access_granted': 'Admin access granted!',
        'private_thread_admin_only': 'Only admins can create private threads',
        'public_thread_anyone': 'Anyone can create public threads'
    },
    ru: {
        // Toasts
        'login_success': 'Вход выполнен!',
        'login_failed': 'Ошибка входа',
        'invalid_username': 'Неверный формат имени',
        'invalid_key': 'Неверный формат ключа',
        'key_not_found': 'Ключ не найден',
        'key_inactive': 'Ключ уже использован',
        'access_granted': 'Доступ получен!',
        'rate_limit': 'Слишком много попыток. Попробуйте позже',
        'thread_created': 'Тема создана!',
        'invalid_title': 'Заголовок должен быть 5-200 символов',
        'invalid_body': 'Описание должно быть 10-5000 символов',
        'xss_detected': 'Обнаружен недопустимый ввод',
        'reply_added': 'Ответ добавлен!',
        'invalid_reply': 'Ответ должен быть 5-2000 символов',
        'no_access': 'Нет доступа к приватной теме',
        'admin_only': 'Только для админов',
        'keys_generated': 'ключей сгенерировано',
        'key_gen_error': 'Ошибка генерации ключей',
        'no_public_threads': 'Нет публичных тем',
        'no_private_threads': 'Нет приватных тем',
        'no_replies': 'Нет ответов',
        'no_keys': 'Нет ключей',
        'author': 'Автор',
        'replies': 'Ответов',
        'views': 'Просмотров',
        'just_now': 'только что',
        'min_ago': 'мин назад',
        'hour_ago': 'ч назад',
        'active': 'Активен',
        'used_by': 'Использован',
        'unknown': 'Неизвестно',
        'loading': 'Загрузка...',
        'admin_access_granted': 'Доступ админа получен!',
        'private_thread_admin_only': 'Только админы могут создавать приватные темы',
        'public_thread_anyone': 'Публичные темы могут создавать все'
    }
};

function t(key) {
    return translations[currentLanguage][key] || key;
}

function updateLanguage() {
    document.querySelectorAll('[data-lang-en]').forEach(el => {
        const enText = el.getAttribute('data-lang-en');
        const ruText = el.getAttribute('data-lang-ru');
        el.textContent = currentLanguage === 'en' ? enText : ruText;
    });
    
    // Update placeholders
    document.querySelectorAll('input[placeholder], textarea[placeholder]').forEach(el => {
        if (el.id === 'username') {
            el.placeholder = currentLanguage === 'en' ? 'Enter username...' : 'Введите имя...';
        } else if (el.id === 'threadTitle') {
            el.placeholder = currentLanguage === 'en' ? 'Enter title...' : 'Введите заголовок...';
        } else if (el.id === 'threadBody') {
            el.placeholder = currentLanguage === 'en' ? 'Describe the thread...' : 'Опишите тему...';
        } else if (el.id === 'replyText') {
            el.placeholder = currentLanguage === 'en' ? 'Your reply...' : 'Ваш ответ...';
        }
    });
}

window.toggleLanguage = function() {
    currentLanguage = currentLanguage === 'en' ? 'ru' : 'en';
    localStorage.setItem('forum_language', currentLanguage);
    document.getElementById('langBtn').textContent = currentLanguage === 'en' ? 'RU' : 'EN';
    updateLanguage();
    
    // Перерендерим контент
    if (currentUser) {
        renderPublicThreads();
        if (currentUser.hasAccess) {
            renderPrivateThreads();
        }
        if (currentUser.isAdmin) {
            renderKeys();
        }
    }
}

// Initialize language on load
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('langBtn').textContent = currentLanguage === 'en' ? 'RU' : 'EN';
    updateLanguage();
});

// =============== SIEM INTEGRATION ===============

const SIEM_API_URL = 'http://localhost:3001';

class SimpleSIEM {
    constructor() {
        this.events = [];
        this.maxEvents = 100;
    }

    async sendEvent(type, data, severity = 'medium') {
        const event = {
            type,
            data,
            severity,
            timestamp: Date.now(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };

        this.events.push(event);
        if (this.events.length > this.maxEvents) {
            this.events.shift();
        }

        try {
            localStorage.setItem('siem_events', JSON.stringify(this.events.slice(-50)));
        } catch (e) {
            console.warn('SIEM storage error:', e);
        }

        try {
            await fetch(`${SIEM_API_URL}/api/siem/event`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(event)
            });
        } catch (err) {
            // Сервер недоступен
        }
    }

    detectXSS(input) {
        const xssPatterns = [
            /<script[^>]*>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /<iframe/i,
            /eval\(/i
        ];

        for (const pattern of xssPatterns) {
            if (pattern.test(input)) {
                this.sendEvent('xss_attempt', {
                    payload: input.substring(0, 200),
                    pattern: pattern.toString()
                }, 'high');
                return true;
            }
        }
        return false;
    }

    reportFailedLogin(username, reason) {
        this.sendEvent('failed_login', { username, reason }, 'medium');
    }

    reportRateLimit(action, count) {
        this.sendEvent('rate_limit', { action, count }, 'medium');
    }

    reportSuspiciousActivity(action, details) {
        this.sendEvent('suspicious_activity', { action, details }, 'high');
    }

    reportSuccessfulLogin(username, method) {
        this.sendEvent('successful_login', { username, method }, 'low');
    }

    reportThreadCreated(threadId, isPrivate) {
        this.sendEvent('thread_created', { threadId, isPrivate }, 'low');
    }

    reportKeysGenerated(count, generatedBy) {
        this.sendEvent('keys_generated', { count, generatedBy }, 'medium');
    }
}

const siem = new SimpleSIEM();

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const db = getDatabase(app);

// Глобальные переменные
let currentUser = null;
let threadsData = {};
let repliesData = {};
let keysData = {};

// =============== ЗАЩИТА ОТ УЯЗВИМОСТЕЙ ===============

function escapeHtml(text) {
    if (typeof text !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

const validators = {
    username: (str) => {
        if (!str || typeof str !== 'string') return false;
        if (str.length < 3 || str.length > 50) return false;
        return /^[a-zA-Z0-9_\-]+$/.test(str);
    },
    
    accessKey: (str) => {
        if (!str || typeof str !== 'string') return false;
        return /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(str);
    },
    
    threadTitle: (str) => {
        if (!str || typeof str !== 'string') return false;
        if (str.length < 5 || str.length > 200) return false;
        if (/<script|javascript:|on\w+=/i.test(str)) return false;
        return true;
    },
    
    threadBody: (str) => {
        if (!str || typeof str !== 'string') return false;
        if (str.length < 10 || str.length > 5000) return false;
        if (/<script|javascript:|on\w+=/i.test(str)) return false;
        return true;
    },
    
    replyText: (str) => {
        if (!str || typeof str !== 'string') return false;
        if (str.length < 5 || str.length > 2000) return false;
        if (/<script|javascript:|on\w+=/i.test(str)) return false;
        return true;
    }
};

function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    
    let sanitized = input.replace(/<[^>]*>/g, '');
    
    sanitized = sanitized
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    
    return sanitized.trim();
}

const rateLimiter = {
    attempts: new Map(),
    
    check(action, maxAttempts = 5, windowMs = 60000) {
        const now = Date.now();
        const key = `${action}_${currentUser?.username || 'anon'}`;
        
        if (!this.attempts.has(key)) {
            this.attempts.set(key, []);
        }
        
        const attempts = this.attempts.get(key).filter(time => now - time < windowMs);
        
        if (attempts.length >= maxAttempts) {
            return false;
        }
        
        attempts.push(now);
        this.attempts.set(key, attempts);
        return true;
    },
    
    reset(action) {
        const key = `${action}_${currentUser?.username || 'anon'}`;
        this.attempts.delete(key);
    }
};

let sessionId = localStorage.getItem('session_id');
if (!sessionId) {
    sessionId = generateSecureId();
    localStorage.setItem('session_id', sessionId);
}

function generateSecureId() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// =============== UI ФУНКЦИИ ===============

const cursorGlow = document.querySelector('.cursor-glow');
document.addEventListener('mousemove', (e) => {
    cursorGlow.style.transform = `translate(${e.clientX - 300}px, ${e.clientY - 300}px)`;
});

setTimeout(() => {
    document.getElementById('loadingScreen').classList.add('hidden');
}, 800);

window.showToast = function(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

window.showLoginModal = function() {
    document.getElementById('loginModal').classList.add('active');
    document.getElementById('username').focus();
}

window.showCreateThreadModal = function(forcePrivate = false) {
    // КРИТИЧЕСКАЯ ЛОГИКА: Проверка прав на создание приватных тем
    if (forcePrivate && (!currentUser || !currentUser.isAdmin)) {
        showToast(t('private_thread_admin_only'), 'error');
        return;
    }
    
    document.getElementById('createThreadModal').classList.add('active');
    document.getElementById('isPrivate').checked = forcePrivate;
    
    // Если не админ - отключаем checkbox приватности
    if (currentUser && !currentUser.isAdmin) {
        document.getElementById('isPrivate').disabled = true;
        document.getElementById('isPrivate').checked = false;
    } else {
        document.getElementById('isPrivate').disabled = false;
    }
}

window.closeModal = function(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

window.showSection = function(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    
    document.getElementById(`${section}Section`).classList.add('active');
    
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        if ((section === 'public' && item.textContent.includes('Public') || item.textContent.includes('Публичные')) ||
            (section === 'private' && item.textContent.includes('Private') || item.textContent.includes('Приватные')) ||
            (section === 'admin' && item.textContent.includes('Admin') || item.textContent.includes('Админ'))) {
            item.classList.add('active');
        }
    });
}

// =============== AUTH FUNCTIONS ===============

window.login = async function(e) {
    e.preventDefault();
    
    if (!rateLimiter.check('login', 5, 60000)) {
        showToast(t('rate_limit'), 'error');
        siem.reportRateLimit('login', 5);
        return;
    }
    
    const username = document.getElementById('username').value.trim();
    const accessKey = document.getElementById('accessKey').value.trim().toUpperCase();
    
    document.getElementById('usernameError').textContent = '';
    document.getElementById('keyError').textContent = '';
    
    if (!validators.username(username)) {
        document.getElementById('usernameError').textContent = t('invalid_username');
        siem.reportFailedLogin(username, 'invalid_format');
        return;
    }
    
    if (siem.detectXSS(username)) {
        document.getElementById('usernameError').textContent = t('xss_detected');
        return;
    }
    
    if (accessKey && !validators.accessKey(accessKey)) {
        document.getElementById('keyError').textContent = t('invalid_key');
        siem.reportFailedLogin(username, 'invalid_key_format');
        return;
    }
    
    const isAdmin = accessKey === ADMIN_SECRET_KEY;
    
    if (isAdmin) {
        currentUser = {
            username: sanitizeInput(username),
            hasAccess: true,
            isAdmin: true,
            sessionId
        };
        
        localStorage.setItem('current_user', JSON.stringify(currentUser));
        
        siem.reportSuccessfulLogin(username, 'admin_key');
        
        showToast(t('admin_access_granted'), 'success');
        closeModal('loginModal');
        
        updateUI();
        loadAdminKeys();
        rateLimiter.reset('login');
        return;
    }
    
    if (accessKey) {
        const keysRef = ref(db, 'keys');
        const snapshot = await get(keysRef);
        const keys = snapshot.val() || {};
        
        let keyFound = false;
        let keyId = null;
        
        for (const [id, keyData] of Object.entries(keys)) {
            if (keyData.key === accessKey) {
                keyFound = true;
                keyId = id;
                
                if (!keyData.active) {
                    document.getElementById('keyError').textContent = t('key_inactive');
                    siem.reportFailedLogin(username, 'key_already_used');
                    return;
                }
                
                await update(ref(db, `keys/${id}`), {
                    active: false,
                    usedBy: username,
                    usedAt: Date.now()
                });
                
                break;
            }
        }
        
        if (!keyFound) {
            document.getElementById('keyError').textContent = t('key_not_found');
            siem.reportFailedLogin(username, 'key_not_found');
            return;
        }
        
        currentUser = {
            username: sanitizeInput(username),
            hasAccess: true,
            isAdmin: false,
            sessionId
        };
        
        siem.reportSuccessfulLogin(username, 'access_key');
        showToast(t('access_granted'), 'success');
    } else {
        currentUser = {
            username: sanitizeInput(username),
            hasAccess: false,
            isAdmin: false,
            sessionId
        };
        
        siem.reportSuccessfulLogin(username, 'public_only');
        showToast(t('login_success'), 'success');
    }
    
    localStorage.setItem('current_user', JSON.stringify(currentUser));
    
    closeModal('loginModal');
    updateUI();
    rateLimiter.reset('login');
}

function updateUI() {
    const headerButtons = document.getElementById('headerButtons');
    
    if (currentUser) {
        const langBtn = document.getElementById('langBtn');
        headerButtons.innerHTML = `
            ${langBtn.outerHTML}
            <span style="color: #4ade80; margin-right: 15px;">${escapeHtml(currentUser.username)}${currentUser.isAdmin ? ' 👑' : ''}</span>
            <button class="btn" onclick="logout()">${t('logout')}</button>
        `;
        
        // Re-attach language button handler
        document.getElementById('langBtn').onclick = toggleLanguage;
        
        document.getElementById('createThreadBtn').style.display = 'block';
        
        if (currentUser.hasAccess) {
            document.getElementById('privateNav').style.display = 'flex';
        }
        
        if (currentUser.isAdmin) {
            document.getElementById('adminNav').style.display = 'flex';
        }
    }
}

window.logout = function() {
    currentUser = null;
    localStorage.removeItem('current_user');
    
    location.reload();
}

// Auto-login from localStorage
const savedUser = localStorage.getItem('current_user');
if (savedUser) {
    currentUser = JSON.parse(savedUser);
    updateUI();
    if (currentUser.isAdmin) {
        loadAdminKeys();
    }
}

// =============== THREAD FUNCTIONS ===============

window.createThread = async function(e) {
    e.preventDefault();
    
    if (!currentUser) {
        showToast(t('login_failed'), 'error');
        return;
    }
    
    if (!rateLimiter.check('create_thread', 3, 60000)) {
        showToast(t('rate_limit'), 'error');
        siem.reportRateLimit('create_thread', 3);
        return;
    }
    
    const title = document.getElementById('threadTitle').value.trim();
    const body = document.getElementById('threadBody').value.trim();
    const isPrivate = document.getElementById('isPrivate').checked;
    
    // КРИТИЧЕСКАЯ ПРОВЕРКА: Приватные темы только для админов
    if (isPrivate && !currentUser.isAdmin) {
        showToast(t('private_thread_admin_only'), 'error');
        siem.reportSuspiciousActivity('unauthorized_private_thread', { 
            user: currentUser.username 
        });
        return;
    }
    
    document.getElementById('titleError').textContent = '';
    document.getElementById('bodyError').textContent = '';
    
    if (!validators.threadTitle(title)) {
        document.getElementById('titleError').textContent = t('invalid_title');
        return;
    }
    
    if (!validators.threadBody(body)) {
        document.getElementById('bodyError').textContent = t('invalid_body');
        return;
    }
    
    if (siem.detectXSS(title) || siem.detectXSS(body)) {
        showToast(t('xss_detected'), 'error');
        return;
    }
    
    try {
        const threadsRef = ref(db, 'threads');
        const newThreadRef = push(threadsRef);
        
        await set(newThreadRef, {
            title: sanitizeInput(title),
            body: sanitizeInput(body),
            author: currentUser.username,
            timestamp: Date.now(),
            isPrivate: isPrivate,
            views: 0,
            replies: 0
        });
        
        siem.reportThreadCreated(newThreadRef.key, isPrivate);
        
        showToast(t('thread_created'), 'success');
        closeModal('createThreadModal');
        
        document.getElementById('threadTitle').value = '';
        document.getElementById('threadBody').value = '';
        document.getElementById('isPrivate').checked = false;
        
        rateLimiter.reset('create_thread');
    } catch (error) {
        console.error('Error creating thread:', error);
        showToast('Error creating thread', 'error');
    }
}

function loadThreads() {
    const threadsRef = ref(db, 'threads');
    onValue(threadsRef, (snapshot) => {
        threadsData = {};
        const data = snapshot.val() || {};
        Object.entries(data).forEach(([id, item]) => {
            if (item && item.title) {
                threadsData[id] = item;
            }
        });
        renderPublicThreads();
        if (currentUser && currentUser.hasAccess) {
            renderPrivateThreads();
        }
        updateStats();
    });
}

window.viewThread = async function(threadId) {
    const thread = threadsData[threadId];
    
    if (!thread) return;
    
    // Проверка доступа к приватной теме
    if (thread.isPrivate && (!currentUser || !currentUser.hasAccess)) {
        showToast(t('no_access'), 'error');
        return;
    }
    
    await update(ref(db, `threads/${threadId}`), {
        views: (thread.views || 0) + 1
    });
    
    document.getElementById('threadView').classList.add('active');
    
    const threadContent = document.getElementById('threadContent');
    threadContent.innerHTML = `
        <div class="thread-full">
            <div class="thread-header-full">
                <h1 class="thread-title-full">
                    ${escapeHtml(thread.title)}
                    ${thread.isPrivate ? `<span class="thread-badge private">${currentLanguage === 'en' ? 'PRIVATE' : 'ПРИВАТНАЯ'}</span>` : ''}
                </h1>
                <div class="thread-meta">
                    <span>${t('author')}: ${escapeHtml(thread.author)}</span>
                    <span>•</span>
                    <span>${formatDate(thread.timestamp)}</span>
                    <span>•</span>
                    <span>${t('views')}: ${thread.views || 0}</span>
                </div>
            </div>
            <div class="thread-body-full">${escapeHtml(thread.body)}</div>
        </div>
        
        <div class="replies-section">
            <h3>${t('replies')} (${thread.replies || 0})</h3>
            <div id="repliesList"></div>
            
            ${currentUser && currentUser.hasAccess ? `
                <form onsubmit="addReply(event, '${threadId}')" class="reply-form">
                    <textarea id="replyText" placeholder="${currentLanguage === 'en' ? 'Your reply...' : 'Ваш ответ...'}" required minlength="5" maxlength="2000"></textarea>
                    <button type="submit" class="btn btn-primary">${currentLanguage === 'en' ? 'Add Reply' : 'Добавить ответ'}</button>
                </form>
            ` : `
                <div class="empty-state">${currentLanguage === 'en' ? 'Login with access key to reply' : 'Войдите с ключом для ответа'}</div>
            `}
        </div>
    `;
    
    loadReplies(threadId);
}

window.addReply = async function(e, threadId) {
    e.preventDefault();
    
    if (!currentUser || !currentUser.hasAccess) {
        showToast(t('no_access'), 'error');
        return;
    }
    
    if (!rateLimiter.check('add_reply', 5, 60000)) {
        showToast(t('rate_limit'), 'error');
        siem.reportRateLimit('add_reply', 5);
        return;
    }
    
    const replyText = document.getElementById('replyText').value.trim();
    
    if (!validators.replyText(replyText)) {
        showToast(t('invalid_reply'), 'error');
        return;
    }
    
    if (siem.detectXSS(replyText)) {
        showToast(t('xss_detected'), 'error');
        return;
    }
    
    try {
        const repliesRef = ref(db, `replies/${threadId}`);
        const newReplyRef = push(repliesRef);
        
        await set(newReplyRef, {
            author: currentUser.username,
            text: sanitizeInput(replyText),
            timestamp: Date.now()
        });
        
        const thread = threadsData[threadId];
        await update(ref(db, `threads/${threadId}`), {
            replies: (thread.replies || 0) + 1
        });
        
        showToast(t('reply_added'), 'success');
        document.getElementById('replyText').value = '';
        rateLimiter.reset('add_reply');
    } catch (error) {
        console.error('Error adding reply:', error);
        showToast('Error adding reply', 'error');
    }
}

function loadReplies(threadId) {
    const repliesRef = ref(db, `replies/${threadId}`);
    const repliesList = document.getElementById('repliesList');
    
    onValue(repliesRef, (snapshot) => {
        const replies = snapshot.val() || {};

        const repliesArray = Object.entries(replies).map(([id, data]) => ({ id, ...data }));

        if (repliesArray.length === 0) {
            repliesList.innerHTML = `<div class="empty-state">${t('no_replies')}</div>`;
            return;
        }

        repliesArray.sort((a, b) => a.timestamp - b.timestamp);

        repliesList.innerHTML = repliesArray.map((reply, index) => `
            <div class="reply-item" style="animation-delay: ${index * 0.1}s;">
                <div class="reply-header">
                    <span class="reply-author">${escapeHtml(reply.author)}</span>
                    <span class="reply-time">${formatDate(reply.timestamp)}</span>
                </div>
                <div class="reply-body">${escapeHtml(reply.text)}</div>
            </div>
        `).join('');
    });
}

window.backToList = function() {
    document.getElementById('threadView').classList.remove('active');
    if (currentUser && currentUser.hasAccess) {
        showSection('private');
    } else {
        showSection('public');
    }
}

function renderPublicThreads() {
    const container = document.getElementById('publicThreads');
    const threads = Object.entries(threadsData)
        .filter(([_, t]) => !t.isPrivate)
        .map(([id, data]) => ({ id, ...data }));

    if (threads.length === 0) {
        container.innerHTML = `<div class="empty-state">${t('no_public_threads')}</div>`;
        return;
    }

    threads.sort((a, b) => b.timestamp - a.timestamp);

    container.innerHTML = threads.map((thread, index) => `
        <div class="thread-item" onclick="viewThread('${escapeHtml(thread.id)}')" style="animation-delay: ${index * 0.05}s;">
            <div class="thread-header">
                <div class="thread-title">${escapeHtml(thread.title)}</div>
            </div>
            <div class="thread-meta">
                <span>${t('author')}: ${escapeHtml(thread.author)}</span>
                <span>•</span>
                <span>${formatDate(thread.timestamp)}</span>
                <span>•</span>
                <span>${t('replies')}: ${thread.replies || 0}</span>
                <span>•</span>
                <span>${t('views')}: ${thread.views || 0}</span>
            </div>
        </div>
    `).join('');
}

function renderPrivateThreads() {
    const container = document.getElementById('privateThreads');
    const threads = Object.entries(threadsData)
        .filter(([_, t]) => t.isPrivate)
        .map(([id, data]) => ({ id, ...data }));

    if (threads.length === 0) {
        container.innerHTML = `<div class="empty-state">${t('no_private_threads')}</div>`;
        return;
    }

    threads.sort((a, b) => b.timestamp - a.timestamp);

    container.innerHTML = threads.map((thread, index) => `
        <div class="thread-item" onclick="viewThread('${escapeHtml(thread.id)}')" style="animation-delay: ${index * 0.05}s;">
            <div class="thread-header">
                <div class="thread-title">
                    ${escapeHtml(thread.title)}
                    <span class="thread-badge private">${currentLanguage === 'en' ? 'PRIVATE' : 'ПРИВАТНАЯ'}</span>
                </div>
            </div>
            <div class="thread-meta">
                <span>${t('author')}: ${escapeHtml(thread.author)}</span>
                <span>•</span>
                <span>${formatDate(thread.timestamp)}</span>
                <span>•</span>
                <span>${t('replies')}: ${thread.replies || 0}</span>
                <span>•</span>
                <span>${t('views')}: ${thread.views || 0}</span>
            </div>
        </div>
    `).join('');
}

// =============== ADMIN FUNCTIONS ===============

window.generateKeys = async function() {
    if (!currentUser || !currentUser.isAdmin) {
        showToast(t('admin_only'), 'error');
        siem.reportSuspiciousActivity('unauthorized_key_gen', { user: currentUser?.username });
        return;
    }

    const count = parseInt(document.getElementById('keyCount').value);
    
    if (count < 1 || count > 50) {
        showToast(currentLanguage === 'en' ? 'Count: 1 to 50' : 'Количество: от 1 до 50', 'error');
        return;
    }

    try {
        const keysRef = ref(db, 'keys');

        for (let i = 0; i < count; i++) {
            const key = generateAccessKey();
            const newKeyRef = push(keysRef);
            await set(newKeyRef, {
                key,
                active: true,
                createdAt: Date.now(),
                createdBy: currentUser.username,
                usedBy: null,
                usedAt: null
            });
        }

        siem.reportKeysGenerated(count, currentUser.username);

        showToast(`${count} ${t('keys_generated')}`, 'success');
    } catch (error) {
        console.error('Error generating keys:', error);
        showToast(t('key_gen_error'), 'error');
    }
}

function generateAccessKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const parts = [];
    
    for (let i = 0; i < 4; i++) {
        let part = '';
        for (let j = 0; j < 4; j++) {
            const randomIndex = Math.floor(Math.random() * chars.length);
            part += chars[randomIndex];
        }
        parts.push(part);
    }
    
    return parts.join('-');
}

function loadAdminKeys() {
    const keysRef = ref(db, 'keys');
    onValue(keysRef, (snapshot) => {
        keysData = {};
        const data = snapshot.val() || {};
        Object.entries(data).forEach(([id, item]) => {
            if (item && item.key) {
                keysData[id] = item;
            }
        });
        renderKeys();
        updateKeyStats();
    });
}

function renderKeys() {
    const container = document.getElementById('keyList');
    const keys = Object.values(keysData);

    if (keys.length === 0) {
        container.innerHTML = `<div class="empty-state">${t('no_keys')}</div>`;
        return;
    }

    keys.sort((a, b) => b.createdAt - a.createdAt);

    container.innerHTML = keys.map((key, index) => `
        <div class="key-item" style="animation-delay: ${index * 0.03}s;">
            <div>
                <div class="key-code">${escapeHtml(key.key)}</div>
                <div class="key-status ${key.active ? 'active' : ''}">
                    ${key.active ? t('active') : `${t('used_by')}: ${escapeHtml(key.usedBy || t('unknown'))}`}
                </div>
            </div>
            <span>${formatDate(key.createdAt)}</span>
        </div>
    `).join('');
}

// =============== UTILITY FUNCTIONS ===============

function formatDate(timestamp) {
    const date = new Date(timestamp);
    const now = Date.now();
    const diff = now - timestamp;
    
    if (diff < 60000) return t('just_now');
    if (diff < 3600000) return `${Math.floor(diff / 60000)} ${t('min_ago')}`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} ${t('hour_ago')}`;
    
    return date.toLocaleDateString(currentLanguage === 'en' ? 'en-US' : 'ru-RU');
}

function updateStats() {
    const total = Object.keys(threadsData).length;
    document.getElementById('totalThreads').textContent = total;
}

function updateKeyStats() {
    const keys = Object.values(keysData);
    document.getElementById('totalKeys').textContent = keys.length;
    document.getElementById('activeKeys').textContent = keys.filter(k => k.active).length;
    document.getElementById('usedKeys').textContent = keys.filter(k => !k.active).length;
}

document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
        }
    });
});

loadThreads();

window.addEventListener('beforeunload', () => {
    if (!currentUser?.isAdmin) {
        keysData = {};
    }
});

let devtoolsOpen = false;
const checkDevTools = () => {
    const threshold = 160;
    if (window.outerWidth - window.innerWidth > threshold || 
        window.outerHeight - window.innerHeight > threshold) {
        if (!devtoolsOpen) {
            devtoolsOpen = true;
            console.log('⚠️ DevTools detected');
        }
    } else {
        devtoolsOpen = false;
    }
};

setInterval(checkDevTools, 1000);
