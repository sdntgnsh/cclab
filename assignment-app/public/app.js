document.addEventListener('DOMContentLoaded', () => {

    // --- FORM SWITCHING LOGIC ---
    const showRegisterBtn = document.getElementById('show-register');
    const showLoginBtn = document.getElementById('show-login');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    if (showRegisterBtn && showLoginBtn) {
        showRegisterBtn.addEventListener('click', (e) => {
            e.preventDefault();
            loginForm.classList.remove('active');
            setTimeout(() => {
                loginForm.classList.add('hidden');
                registerForm.classList.remove('hidden');
                setTimeout(() => registerForm.classList.add('active'), 50);
            }, 300); // Wait for transition
        });

        showLoginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            registerForm.classList.remove('active');
            setTimeout(() => {
                registerForm.classList.add('hidden');
                loginForm.classList.remove('hidden');
                setTimeout(() => loginForm.classList.add('active'), 50);
            }, 300);
        });
    }

    // --- AUTHENTICATION FLOWS ---
    
    // Helper to manage UI state during requests
    const setFormState = (btnId, msgId, isLoading, errorMsg = '', successMsg = '') => {
        const btn = document.getElementById(btnId);
        const msg = document.getElementById(msgId);
        const btnText = btn.querySelector('span');
        const spinner = btn.querySelector('.spinner');

        if (isLoading) {
            btn.disabled = true;
            btn.style.opacity = '0.7';
            btnText.classList.add('hidden');
            spinner.classList.remove('hidden');
            msg.textContent = '';
        } else {
            btn.disabled = false;
            btn.style.opacity = '1';
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
            
            if (errorMsg) {
                msg.textContent = errorMsg;
                msg.className = 'form-messages msg-error';
            } else if (successMsg) {
                msg.textContent = successMsg;
                msg.className = 'form-messages msg-success';
            }
        }
    };

    // Register Handler
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('register-username').value;
            const password = document.getElementById('register-password').value;

            setFormState('register-btn', 'register-message', true);

            try {
                const res = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await res.json();

                if (res.ok) {
                    setFormState('register-btn', 'register-message', false, '', 'Account created! Redirecting...');
                    setTimeout(() => window.location.href = '/dashboard.html', 1000);
                } else {
                    setFormState('register-btn', 'register-message', false, data.error || 'Registration failed');
                }
            } catch (err) {
                setFormState('register-btn', 'register-message', false, 'Network error occurred');
            }
        });
    }

    // Login Handler
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;

            setFormState('login-btn', 'login-message', true);

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await res.json();

                if (res.ok) {
                    setFormState('login-btn', 'login-message', false, '', 'Login successful! Redirecting...');
                    setTimeout(() => window.location.href = '/dashboard.html', 500);
                } else {
                    setFormState('login-btn', 'login-message', false, data.error || 'Login failed');
                }
            } catch (err) {
                setFormState('login-btn', 'login-message', false, 'Network error occurred');
            }
        });
    }

    // Logout Handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                await fetch('/api/logout', { method: 'POST' });
            } finally {
                // Ignore errors and force redirect locally
                document.cookie = 'user=; Max-Age=0; path=/;';
                window.location.href = '/index.html';
            }
        });
    }

    // Retry fetching users
    const retryBtn = document.getElementById('retry-btn');
    if (retryBtn) {
        retryBtn.addEventListener('click', window.fetchUsers);
    }
});

// --- DASHBOARD LOGIC ---
window.fetchUsers = async () => {
    const tableElement = document.getElementById('users-table');
    const loadingState = document.getElementById('users-loading');
    const errorState = document.getElementById('users-error');
    const errorText = document.getElementById('error-text');
    const tbody = document.getElementById('users-tbody');

    if (!tableElement) return; // Only run on dashboard page

    // Reset UI
    loadingState.classList.remove('hidden');
    errorState.classList.add('hidden');
    tableElement.classList.add('hidden');
    tbody.innerHTML = '';

    try {
        const res = await fetch('/api/users');
        if (!res.ok) {
            if (res.status === 401) {
                window.location.href = '/index.html'; // Auth failed
                return;
            }
            throw new Error('Failed to fetch users');
        }

        const users = await res.json();
        
        loadingState.classList.add('hidden');
        
        if (users.length === 0) {
            errorState.classList.remove('hidden');
            errorText.textContent = 'No users found in the database.';
            return;
        }

        users.forEach(user => {
            const letter = user.username.charAt(0).toUpperCase();
            const date = new Date(user.createdAt).toLocaleDateString('en-US', {
                year: 'numeric', month: 'short', day: 'numeric'
            });

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>
                    <div class="user-avatar">${letter}</div>
                </td>
                <td style="font-weight: 500;">@${user.username}</td>
                <td style="color: var(--text-muted);">${date}</td>
                <td><span class="status-badge">Active</span></td>
            `;
            tbody.appendChild(tr);
        });

        tableElement.classList.remove('hidden');

    } catch (err) {
        loadingState.classList.add('hidden');
        errorState.classList.remove('hidden');
        errorText.textContent = 'Could not load users. Check server connection.';
    }
};
