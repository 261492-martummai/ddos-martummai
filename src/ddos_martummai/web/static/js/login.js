    // ── Theme toggle (mirrors index.html logic) ────────────
    let currentTheme = localStorage.getItem('nm-theme') || 'dark';

    function applyTheme(t) {
      document.documentElement.classList.toggle('light', t === 'light');
      document.querySelector('#theme-btn .icon').textContent  = t === 'dark' ? '🌙' : '☀️';
      document.querySelector('#theme-btn .label').textContent = t === 'dark' ? 'DARK' : 'LIGHT';
      localStorage.setItem('nm-theme', t);
    }

    document.getElementById('theme-btn').addEventListener('click', () => {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      applyTheme(currentTheme);
    });

    applyTheme(currentTheme);   // restore on load

    // ── Auth logic ────────────────────────────────────────
    const errorBox  = document.getElementById('error-msg');
    const errorText = document.getElementById('error-text');
    const loginBtn  = document.getElementById('login-btn');
    const usernameEl = document.getElementById('username');
    const passwordEl = document.getElementById('password');

    function showError(msg) {
      errorText.textContent = msg;
      errorBox.classList.add('visible');
    }

    function clearError() {
      errorBox.classList.remove('visible');
    }

    // Clear error as soon as user starts typing again
    usernameEl.addEventListener('input', clearError);
    passwordEl.addEventListener('input', clearError);

    // Allow Enter key on either field to submit
    [usernameEl, passwordEl].forEach(el => {
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') doLogin();
      });
    });

    async function doLogin() {
      const username = usernameEl.value.trim();
      const password = passwordEl.value;

      if (!username) { showError('USERNAME REQUIRED'); usernameEl.focus(); return; }
      if (!password) { showError('PASSWORD REQUIRED'); passwordEl.focus(); return; }

      loginBtn.classList.add('loading');
      clearError();

      try {
        const res = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
          credentials: 'include',   // send/receive session cookie
        });

        if (res.ok) {
          // Successful auth → redirect to monitor
          window.location.replace('/monitor');
        } else {
          const body = await res.json().catch(() => ({}));
          showError(body.detail || 'INVALID CREDENTIALS');
          passwordEl.value = '';
          passwordEl.focus();
        }
      } catch {
        showError('SERVER UNREACHABLE');
      } finally {
        loginBtn.classList.remove('loading');
      }
    }

    loginBtn.addEventListener('click', doLogin);

    // Auto-focus username on load
    usernameEl.focus();